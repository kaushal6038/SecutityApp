# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from django.shortcuts import render,redirect
from redtree_app.models import *
from django.conf import settings
from django.db.models import Count, Q
from django.shortcuts import render
from redtree_app.forms import *
import requests
import time
import hashlib, random
from lxml import etree
from django.views.generic import View
from django.utils.decorators import method_decorator
from .models import ApiList
from .forms import (
    ApiForm,
    MasscanFileUploadForm,
    AddKbArticleForm,
)
from django.http import HttpResponse, HttpResponseBadRequest, HttpResponseRedirect, JsonResponse, QueryDict
import datetime
from django.contrib import messages
import logging
import re
from threading import Thread
from django.db import connection
from django.conf import settings
import os
from django.core.files import File
from django.core.files.temp import NamedTemporaryFile
from django.contrib.auth.decorators import login_required
from redtree_app.constants import BANNER_PATTERN
from datetime import datetime
from django.contrib import messages
from redtree_app.ip_validator import *
from private.serializers import *
from utils.log_user_activity import *
from raven.contrib.django.raven_compat.models import client as sentry_client
from nessus.serializers import *
from rest_framework import serializers
import json
from utils.nessus_upload_helper import (
    process_nessus,
    process_nessus_data,
    reprocess_nessus,
)

logging.basicConfig(level=logging.DEBUG, format='%(relativeCreated)6d %(threadName)s %(message)s')
# log = logging.getLogger(__name__)

logger = logging.getLogger('nessus')
logger.setLevel(logging.DEBUG)
fh = logging.FileHandler('nessus.log')
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
fh.setFormatter(formatter)
fh.setLevel(logging.DEBUG)
logger.addHandler(fh)


def postpone(function):
    def decorator(*args, **kwargs):
        t = Thread(target = function, args=args, kwargs=kwargs)
        t.daemon = True
        t.start()
    return decorator


def get_request_ip(request):
    try:
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
    except:
        return request


def get_file_code(fname):
    hash_md5 = hashlib.md5()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    f.close()
    file_code = hash_md5.hexdigest()
    logger.info('File Code {}'.format(file_code))
    return file_code


@login_required
def reportupload(request):
    log_user_activity(request)
    if request.method == "POST":
        form = NessusFileUploadForm(request.POST, request.FILES)
        if form.is_valid():
            file_obj = form.save()
            logger.info('File recieved.Saving....')
            try:
                file_path = file_obj.file.path
                logger.info('Generating file code...')
                code = get_file_code(file_path)
                logger.info('file code generated.')
                file_obj.file_code = code
                file_obj.save()
                logger.info('File saved.Processing the file')
            except Exception as error:
                file_obj.delete()
                return HttpResponseBadRequest("Unable to process the request {}".\
                    format(error))
            nessus_file_obj = NessusFile.objects.filter(id=file_obj.id)
            logger.info('Processing file....')
            process_nessus(nessus_file_obj, request)
            return HttpResponse("Scan file saved.")
        if len(form.non_field_errors().data) > 1:
            validation_data = form.non_field_errors().data
            nessus_data_list = []
            for val_data in validation_data:
                nessus_data_list.append(str(val_data))
            nessus_data_list.pop(0)
            nessus_data = {'nessus_host': nessus_data_list}
            return JsonResponse(nessus_data,safe=False)    
        elif len(form.non_field_errors().data) == 1:
            validation_data = form.non_field_errors().data[0]
            return HttpResponseBadRequest(validation_data)
    else:
        api_obj = ApiList.objects.first()
        appliances_obj = Appliances.objects.first()
        data = {'plugin_list': ''}
        if api_obj:
            url = "{}/kb-plugins/".format(api_obj.kb_base_url)
        headers = {
            'Content-Type': 'application/json',
            'Accept':'application/json',
            'Authorization': 'Token {}'.format(api_obj.kb_auth_token)
        }
        try:
            article_response = requests.post(url, json=data, headers=headers)
        except:
            article_response = None
        error_message = None
        if not (article_response and article_response.status_code == 200)\
                and not appliances_obj:
            error_message = "Issues detection will not work, "\
                "Either KB is down or configuration is not setup properly. Also"\
                " Screenshot will not be captured for application because "\
                "appliacne is not setup."
        elif appliances_obj and not\
                (article_response and article_response.status_code == 200):
            error_message = "Issues detection will not work, Either KB is "\
                "down or configuration is not setup properly."
        elif (article_response and article_response.status_code == 200)\
                and not appliances_obj:
            error_message = "Screenshot will not be captured for application"\
                " because appliacne is not setup."

        if error_message:
            messages.error(request, error_message)
        form = NessusFileUploadForm()
    files = NessusFile.objects.all().order_by('-id')
    for file in files:
        file.file_name = os.path.basename(file.file.name)
    context = {
        'form': form,
        'files': files
    }
    return render(
        request,
        'redtree_app/fileupload.html',
        context
    )


@login_required
def masscan_upload(request):
    log_user_activity(request)
    if request.method == "POST":
        form = MasscanFileUploadForm(request.POST, request.FILES)
        if form.is_valid():
            host_not_found_list = list()
            host_discovery_not_found_list = list()
            file = request.FILES['file']
            xml_content = file.read()
            root = etree.fromstring(xml_content)
            new_port = 0
            excluded_port = 0
            masscan_response_list = []
            vul_history = []
            if root.attrib['scanner'] != 'masscan':
                return HttpResponseBadRequest("Only masscan files are supported.")

            elif root.attrib['scanner'] == 'masscan':

                for host in root.iter("host"):
                    for address in host.iter("address"):
                        for ports in host.iter("ports"):
                            for port in host.iter("port"):
                                for state in host.iter("state"):
                                    host_type = get_host_type(address.attrib['addr'])
                                    user_host = check_host_exists(
                                        address.attrib['addr'], host_type
                                    )
                                    vul_obj = Vulnerability.objects.filter(
                                        virtue_id=8,
                                        plugin_id='11219',
                                        title='Open TCP Port',
                                        port=port.attrib['portid'],
                                        description='An open port was discovered',
                                        risk='Note',
                                        host_ip=address.attrib['addr'],
                                        remediation='N/A'
                                    )
                                    if user_host:
                                        if not vul_obj.exists():
                                            network_type = user_host.network.network_type
                                            if not Host.objects.filter(
                                                    user_host=user_host,
                                                    host=address.attrib['addr']
                                                ).exists():
                                                host_obj = Host.objects.create(
                                                    user_host=user_host,
                                                    host=address.attrib['addr']
                                                )
                                            else:
                                                host_obj = Host.objects.filter(
                                                    user_host=user_host,
                                                    host=address.attrib['addr']
                                                ).first()
                                            vul_obj = Vulnerability.objects.create(
                                                virtue_id=8,plugin_id='11219',
                                                port=port.attrib['portid'],
                                                risk='Note',title='Open TCP Port',
                                                description='An open port was discovered',
                                                remediation='N/A', post_status=True,
                                                host_ip=address.attrib['addr'],
                                                network_type=network_type,
                                                host=host_obj
                                            )
                                            vul_history.append(vul_obj.title)
                                            masscan_response_dict = {
                                                'host': address.attrib['addr'],
                                                'port': port.attrib['portid'],
                                                'status': 'INSERTED'
                                            }
                                            masscan_response_list.append(
                                                masscan_response_dict
                                            )
                                            new_port = new_port + 1
                                            try:
                                                nessus_obj = NessusData.objects.get(
                                                    plugin_id=11219,
                                                    host=address.attrib['addr'],
                                                    port=port.attrib['portid'],
                                                    name='Open TCP Port',
                                                    virtue_id=8
                                                )
                                            except NessusData.MultipleObjectsReturned:
                                                nessus_obj = NessusData.objects.filter(
                                                    plugin_id=11219,
                                                    host=address.attrib['addr'],
                                                    port=port.attrib['portid'],
                                                    name='Open TCP Port',
                                                    virtue_id=8
                                                ).first()
                                            except NessusData.DoesNotExist:
                                                nessus_obj = None
                                            if nessus_obj:
                                                nessus_obj.date_confirmed = datetime.date.today()
                                                nessus_obj.save()
                                        else:
                                            masscan_response_dict = {
                                                'host': address.attrib['addr'],
                                                'port': port.attrib['portid'],
                                                'status': 'EXISTED'
                                            }
                                            masscan_response_list.append(
                                                masscan_response_dict
                                            )
                                            excluded_port = excluded_port + 1
                                    else:
                                        host_not_found_list.append(
                                            address.attrib['addr']
                                        )
                                        host_discovery_not_found_dict ={
                                            'host': address.attrib['addr'],
                                            'port': port.attrib['portid'],
                                            'state': state.attrib['state'],
                                            'date': datetime.today().date(),
                                            'protocol': port.attrib['protocol']
                                        }
                                        host_discovery_not_found_list.append(
                                            host_discovery_not_found_dict
                                        )
                if host_not_found_list:
                    host_not_found_list = "These hosts not found:  [" +\
                        ",\n ".join(host_not_found_list) + "]"
                masscan_data = {
                    'masscan_response_list': masscan_response_list,
                    'new_port': new_port,
                    'excluded_port': excluded_port,
                    'host_not_found_list': host_not_found_list,
                    'discovery_host': host_discovery_not_found_list
                }
                vul_history = set(vul_history)
                if vul_history:
                    vul_history_data = "create_vulnerability: " 
                    for vul_data in vul_history:
                        vul_history_data = vul_history_data + str(vul_data) + ", "
                    RedtreeEventHistory.objects.create(
                        event_type  =   'create_vulnerability',
                        time_stamp  =   datetime.now().strftime('%s'),
                        username    =   request.user.username,
                        ip          =   get_request_ip(request),
                        data        =   vul_history_data
                    )
            return JsonResponse(masscan_data,safe=False)    
        return HttpResponseBadRequest(form.non_field_errors().data[0])
    else:
        form = MasscanFileUploadForm()
    return render(request, 'redtree_app/fileupload.html', {'form': form})    



def get_application_data(nessus_obj):
    application_ip_data = list()
    for nessusObj in nessus_obj:
        if re.search("SSL : yes", (nessusObj.plugin_output)):
            if not (nessusObj.port in (80,443)):
                application_url = "https://" + str(nessusObj.host) +\
                    ":" + str(nessusObj.port)
            else:
                application_url = "https://" + str(nessusObj.host)
        elif re.search("SSL : no", (nessusObj.plugin_output)):
            if not (nessusObj.port in (80,443)):
                application_url = "http://" + str(nessusObj.host) +\
                    ":" + str(nessusObj.port)
            else:
                application_url = "http://" + str(nessusObj.host)
        else:
            application_url = None
        if application_url:
            if nessusObj.user_host:
                data = {
                    "application_url": application_url,
                    "nessus_obj": nessusObj
                }
                application_ip_data.append(data)
    return application_ip_data


def reprocess_nessusdata(request):
    reprocess_nessus(request=request, nessus_import=False)
    time.sleep(2)
    return redirect('/nessus')


def get_risk_factor(risk):
    risk_status = dict()
    risk_status["Critical"] = 5
    risk_status["High"] = 4
    risk_status["Medium"] = 3
    risk_status["Low"] = 2
    risk_status["None"] = 1
    risk_status[None] = 0

    return risk_status[risk]


@login_required
def nessusdata(request):
    log_user_activity(request)
    if request.method == "POST":
        vul_history = list()
        vul_count = list()
        add_kb_article_form = AddKbArticleForm(request.POST)
        plugin_id = request.POST.get('Plugin_Id_Value')
        nessus_plugin_array = request.POST.get('nessus_plugin_array')
        nessus_plugin_list = list()
        if nessus_plugin_array:
            nessus_plugin_list = nessus_plugin_array.split(',')
        if add_kb_article_form.is_valid():
            article_type = add_kb_article_form.cleaned_data.get('article_type')
            title = add_kb_article_form.cleaned_data.get('title')
            description = add_kb_article_form.cleaned_data.get('description')
            remediation = add_kb_article_form.cleaned_data.get('remediation')
            triage = add_kb_article_form.cleaned_data.get('triage')
            risk = add_kb_article_form.cleaned_data.get('risk')
            slug = add_kb_article_form.cleaned_data.get('slug')
            data = {
                'article_type': article_type,
                'title': title,
                'description': description,
                'remediation': remediation,
                'triage': triage,
                'risk': risk,
                'slug': slug,
                'nessus_plugin_list': nessus_plugin_list
            }
            api_obj = ApiList.objects.first()
            if api_obj:
                url = "{}/api/add-kb-article/".format(
                    api_obj.kb_base_url
                )
            else:
                url = None
            headers = {
                'Content-Type': 'application/json',
                'Accept':'application/json',
                'Authorization': 'Token {}'.format(
                    api_obj.kb_auth_token
                )
            }
            try:
                article_response = requests.post(
                    url,
                    json=data,
                    headers=headers
                )
            except:
                article_response = None
            if article_response and article_response.status_code == 200:
                response_data = article_response.json()
                virtue_id = response_data.get('data').get('virtue_id')
                NessusData.objects.filter(
                    plugin_id__in=nessus_plugin_list
                ).update(virtue_id=virtue_id)

    raw_issues = NessusData.objects.values(
        'plugin_id', 'risk', 'name', 'virtue_id'
    ).annotate(instances=Count('name'))
    nessus_issues = NessusDataSerializer(raw_issues, many=True)
    ordered_sections = sorted(nessus_issues.data, key=lambda x: x['risk_factor'], reverse=True)
    networks = Networks.objects.all()
    api_obj = ApiList.objects.first()
    data = {'plugin_list': ''}
    if api_obj:
        url = "{}/kb-plugins/".format(api_obj.kb_base_url)
    headers = {'Content-Type': 'application/json', 'Accept':'application/json', 'Authorization': 'Token {}'.format(api_obj.kb_auth_token)}
    try:
        article_response = requests.post(url, json=data, headers=headers)
    except:
        article_response = None
    if not (article_response and article_response.status_code == 200):
        messages.error(request, "Issues detection will not work, Either KB is down or configuration is not setup properly.")
        scanning_status = False
        scan_text = "Issues detection will not work, Either KB is down or configuration is not setup properly."
    else:
        scanning_status = True
        scan_text = ''
    add_kb_article_form = AddKbArticleForm()
    context = {
        'scanning_status': scanning_status,
        'ordered_sections': ordered_sections,
        'networks': networks,
        'scan_text': scan_text,
        'form': add_kb_article_form
    }
    return render(request, 'nessus/nessusdata.html', context)


@login_required
def nessus_issue_detail(request,plugin_id,issue_id):
    log_user_activity(request)
    try:
        nesuss_obj = NessusData.objects.get(id=int(issue_id), plugin_id=int(plugin_id))
    except NessusData.MultipleObjectsReturned:
        nesuss_obj = NessusData.objects.filter(id=int(issue_id), plugin_id=int(plugin_id)).first()
    except NessusData.DoesNotExist:
        nesuss_obj = None
    return render(request, 'nessus/nessus-issue-detail.html', {'issue_detail': nesuss_obj})


@login_required
def affected_hosts(request, plugin_id):
    log_user_activity(request)
    affectedhost_obj = NessusData.objects.filter(plugin_id=plugin_id)
    banner_exist = False
    serializer_class = NessusDetailSerializer
    nessus_detail = serializer_class(affectedhost_obj , many=True)
    for data in nessus_detail.data:
        if data['banner']:
            banner_exist = True
    context = {
        'nessus_host': None,
        'affectedHosts': nessus_detail.data,
        'banner_exist': banner_exist,
        'affectedhost_obj': affectedhost_obj.first()
    }
    return render(
        request,
        'nessus/affected-hosts.html',
        context
    )


class NessusFileSerializer(serializers.ModelSerializer):
    filename = serializers.SerializerMethodField()
    class Meta:
        model = NessusFile
        fields = [
            'id',
            'file',
            'file_code',
            'low_risk_count',
            'medium_risk_count',
            'high_risk_count',
            'critical_risk_count',
            'low_new_issue',
            'medium_new_issue',
            'high_new_issue',
            'critical_new_issue',
            'uploaded_at',
            'xml_process_status',
            'applications_process_status',
            'vulnerabilities_process_status',
            'is_completed',
            'error_message',
            'filename',
            'is_accepted',
            'hosts_list'
        ]

    def get_filename(self, obj):
        filename = str(os.path.basename(obj.file.name))
        if not filename:
            filename = obj.file_code
        return filename

@login_required
def nessus_files(request):
    log_user_activity(request)
    files = NessusFile.objects.all().order_by('-id')
    for file in files:
        file.file_name = os.path.basename(file.file.name)
    data = NessusFileSerializer(files, many=True).data
    return JsonResponse(data, safe=False)


@login_required
def search_title(request):
    if request.is_ajax():
        title = request.POST.get('title')
        data = {
                'title': title,     
            }
        api_obj = ApiList.objects.first()
        url = "{}/api/search/".format(
            api_obj.kb_base_url
        )
    
        headers = {
            'Content-Type': 'application/json',
            'Accept':'application/json',
            'Authorization': 'Token {}'.format(
                api_obj.kb_auth_token
            )
        }
        try:
            article_response = requests.post(
                url,
                json=data,
                headers=headers
            )
        except:
            article_response = None
        if article_response and article_response.status_code == 200:
            response_data = article_response.json()

            response_data = response_data.get('data')
        elif response.status_code == 403:
            response_data = {
                "status": False,
                "status_code": 403,
                "message": "Unable to authenticate the processed request.",
                "data": []
            }
        else:
            response_data = {
                "status": False,
                "status_code": 500,
                "message": "Some error occured with the record.",
                "data": []
            }
        return JsonResponse(response_data, safe=False)


@login_required
def plugin_map(request):
    if request.is_ajax():
        virtue_id = request.POST.get('virtue_id')
        plugin_id = request.POST.get('plugin_id')
        nessus_obj = NessusData.objects.filter(plugin_id=plugin_id)
        api_obj = ApiList.objects.first()
        if api_obj:
            if nessus_obj:
                req_data = {
                    "virtue_id": virtue_id,
                    "plugin_id": plugin_id,
                    "title": nessus_obj.first().name
                }
                url = "{}/api/kb/map/".format(
                    api_obj.kb_base_url
                )
                headers = {
                    'Content-Type': 'application/json',
                    'Accept':'application/json',
                    'Authorization': 'Token {}'.format(
                        api_obj.kb_auth_token
                    )
                }
                try:
                    article_response = requests.post(
                        url,
                        json=req_data,
                        headers=headers
                    )
                except:
                    article_response = None
                if article_response and article_response.status_code == 201:
                    NessusData.objects.filter(
                            plugin_id=plugin_id
                        ).update(virtue_id=virtue_id)
                    response_data = article_response.json()
                else:
                    response_data = {
                        "status": False,
                        "status_code": 500,
                        "message": "Some error occured with the record.",
                        "data": []
                    }
            else:
                response_data = {
                    'status': False,
                    'code': 404,
                    'error': "Nessus record doesn't exists.",
                    'message': "Unable to Map Nessus record."
                }
        return JsonResponse(response_data, safe=False)


@login_required
def nessusfile_history(request, file_code=None):
    log_user_activity(request)
    message = ''
    try:
        file_obj = NessusFile.objects.filter(file_code=file_code).first()
        file_content = NessusData.objects.filter(
            linked_file=file_obj
        ).values('plugin_id', 'risk', 'name', 'host', 'port', 'first_identified')
        for file_contents in file_content:
            file_contents['risk_factor'] = get_risk_factor(file_contents['risk'])
        file_data = sorted(file_content, key=lambda x: x['risk_factor'], reverse=True)
    except:
        file_obj = ""
        file_data = ""
        message = 'No Record Found for "{}"'.format(file_code)
    context = {
        'file_detail': file_obj,
        'file_content': file_data,
        'message': message
    }
    return render(request, 'nessus/nessus-file-detail.html', context)


@login_required
def delete_nessus_file(request, id):
    log_user_activity(request)
    if request.method == "DELETE":
        data = QueryDict(request.body)
        pk = data.get('pk')
        try:
            file_obj = NessusFile.objects.get(pk=pk)
        except:
            file_obj = None
        if file_obj:
            file_obj.delete()
        response_data = {
            'ok': True,
            'status': 200,
            'message': 'File deleted successfully.'
        }
        return JsonResponse(response_data, safe=False)
    response_data = {
            'ok': False,
            'status': 400,
            'message': 'Method Not allowded.'
    }
    return JsonResponse(response_data, safe=False)


@login_required
def file_logs(request, file_id):
    log_user_activity(request)
    log_obj = NessusFileLog.objects.filter(linked_file=int(file_id))
    return render(request, 'nessus/nessus-file-logs.html', {'logs': log_obj})


@method_decorator(login_required, name='dispatch')
class NetworkNessusVulnerabilitiesDetailView(View):
    template_name = 'nessus/nessusnetworkdata.html'
    context = dict()

    def get_nessus_objects(self):
        network_id = self.kwargs.get('network_id')
        user_hosts = UserHosts.objects.filter(network__id=network_id)
        return NessusData.objects.filter(user_host__in=user_hosts)

    def get(self, request, *args, **kwargs):
        log_user_activity(request)
        nessus_objs = self.get_nessus_objects()
        vulnerabilities_obj = nessus_objs.values(
            'plugin_id', 'risk', 'name', 'virtue_id'
        ).annotate(instances=Count('name'))
        for vulnerability in vulnerabilities_obj:
            vulnerability['risk_factor'] = get_risk_factor(vulnerability['risk'])
        ordered_sections = sorted(
            vulnerabilities_obj,
            key=lambda x: x['risk_factor'],
            reverse=True
        )
        networks = Networks.objects.all()
        api_obj = ApiList.objects.first()
        data = {'plugin_list': ''}
        if api_obj:
            url = "{}/kb-plugins/".format(api_obj.kb_base_url)
        headers = {
            'Content-Type': 'application/json',
            'Accept':'application/json',
            'Authorization': 'Token {}'.format(api_obj.kb_auth_token)
        }
        try:
            article_response = requests.post(url, json=data, headers=headers)
        except:
            article_response = None
        if not (article_response and article_response.status_code == 200):
            messages.error(
                request,
                "Issues detection will not work, "\
                "Either KB is down or configuration is not setup properly."
            )
            scanning_status = False
            scan_text = "Issues detection will not work, "\
                "Either KB is down or configuration is not setup properly."
        else:
            scanning_status = True
            scan_text = ''
        self.context['scanning_status'] = scanning_status
        self.context['scan_text'] = scan_text
        self.context['ordered_sections'] = ordered_sections
        self.context['networks'] = networks
        self.context['network_id'] = kwargs.get('network_id')
        return render(
            request,
            self.template_name,
            self.context
        )


def host_plugin_issues(request, plugin_id, host_id):
    try:
        host_obj = Host.objects.get(id=host_id)
    except:
        host_obj = None
    if host_obj:
        nessus_data = NessusData.objects.filter(
            plugin_id=plugin_id,
            host_link=host_obj
        )
        banner_exist = False
        serializer_class = NessusDetailSerializer
        nessus_detail = serializer_class(nessus_data , many=True)
        for data in nessus_detail.data:
            if data.get('banner'):
                banner_exist = True
        context = {
            'nessus_host': host_obj,
            'affectedHosts': nessus_detail.data,
            'banner_exist': banner_exist,
            'affectedhost_obj': nessus_data.first()
        }
    else:
        context = {
            'nessus_host': None,
            'affectedHosts': None,
            'banner_exist': None,
            'affectedhost_obj': None
        }
    return render(
        request,
        'nessus/affected-hosts.html',
        context
    )
