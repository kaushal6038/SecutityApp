# -*- coding: utf-8 -*-
from __future__ import unicode_literals
#---Base Import---#
import random
import shutil
import re
import json
import pdfkit
import logging
import hashlib
import os
import ast
import requests
from django.http import (
    HttpResponse,
    Http404,
    JsonResponse,
    HttpResponseRedirect,
    QueryDict,
)
from django.utils.translation import gettext_lazy as _
from django.shortcuts import render, redirect
from .forms import *
from private.serializers import *
from .models import *
from nessus.models import (
    ApiList
)
from playground.models import (
    ApplicationScanData
)
from nessus.forms import *
from django.conf import settings
from datetime import date, datetime, timedelta
from time import gmtime, strftime
from django.forms import modelformset_factory
from django.core.paginator import Paginator
from django.core.files import File
from ip_validator import *
from django.contrib import messages
from markdown_helper import *
from utils.AwsDescriptor import AwsDescriptor
from utils.RestApiScanDescriptor import RestApiScanDescriptor
from utils.MasscanRestApiDescriptor import MasscanRestApiDescriptor
from utils.MediaUploader import MediaUploader
from utils.process_nessus_file import process_file
from utils.calculate_time_ago import calculate_time_ago
from django.db.models.functions import Cast
from django.db.models import FloatField, IntegerField
from utils.helpers import (
    get_sorted_user_host_vulnerabilities,
    get_sorted_host_vulnerabilities,
    get_risk_factor,
    get_sorted_cipher,
    get_sorted_vulnerabilities,
    application_vulnerability_count,
    unprocessed_burp_count
)
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_http_methods
from nessus.views import postpone
from django.views.generic import View
from django.utils.decorators import method_decorator
from collections import Counter
from django.template.loader import get_template
# from tasks import *
from django.db.models import Count, Q
from django.utils import timezone
from redtree.celery import app
from celery.task.control import inspect
from templatetags.markdown_tags import *
from PyPDF2 import PdfFileWriter, PdfFileReader
from playground.models import *
from django.db import connection
from private.serializers import (
    ApplicationDetailSerializer,
    BurpDetailSerializer,
    GetRiskHistoricalDataSerializer
)
from utils.helpers import (
    find_markdown_images, update_cipher_helper
)
from utils.views import (
    get_subdomain_ip_scope,
    get_domain_host,
    get_strength_count,
    get_ciphers_strength,
)
from django.core import serializers
from celery.task.control import revoke
from utils.log_user_activity import *
from django.views.decorators.cache import cache_control
from django.core.paginator import (
    Paginator,
    EmptyPage,
    PageNotAnInteger
)
from django.template.loader import render_to_string
log = logging.getLogger(__name__)


@login_required
def index(request):
    return redirect('/home')


def get_request_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


@login_required
@cache_control(must_revalidate=True, max_age=200)
def home(request):
    log_user_activity(request)
    client_conf_obj = ClientConfiguration.objects.first()
    total_hosts = UserHosts.objects.aggregate(Sum('count'))['count__sum']
    host_obj = UserHosts.objects.all()
    message = ''
    if not host_obj:
        if client_conf_obj:
            message = "No targets have been uploaded by {}".\
                format(client_conf_obj.client_name)
        else:
            message = "No targets have been uploaded"
    else:
        message = "{} IPs in scope".format(total_hosts)
    External_host_obj = host_obj.filter(network__network_type="External")
    Internal_host_obj = host_obj.filter(network__network_type="Internal")
    application_data = Applications.objects.all()
    cloud_asset_data = CloudAssetsData.objects.all()
    subdomains_data = EnumeratedSubdomains.objects.all().\
        order_by('subdomain').distinct('subdomain')
    domains_data = Domains.objects.all()
    network_obj = Networks.objects.all().order_by('id')
    nessus_obj = NessusData.objects.all().\
        filter(virtue_id__isnull=True
    )
    nessus_unprocessed = NessusData.objects.\
        filter(virtue_id__isnull=True).values('name', 'virtue_id').\
        annotate(instances=Count('name'))
    burp_obj = ApplicationScanData.objects.\
        filter(virtue_id__isnull=True).values('name', 'virtue_id').\
        annotate(instances=Count('name'))
    testing_obj = TestVulnerabilities.objects.all()
    application_message = "{} Applications in scope".format(application_data.count())
    assets_message = "{} Cloud Assets in scope.".format(cloud_asset_data.count())
    nessus_message = "{} Unprocessed Nessus".format(nessus_unprocessed.count())
    burp_message = "{} Unprocessed Burp".format(burp_obj.count())
    test_queue_message = "{} Queued for manual review".format(testing_obj.count())
    pl_users_objs = PurpleleafUserEventHistory.objects.values_list(
        'username',
        flat=True
    )
    pl_users_list = [str(item) for item in pl_users_objs]
    pl_users = set(pl_users_list)
    if 'None' in pl_users:
        pl_users.remove('None')
    pl_user_event_id_list = list()
    for user in pl_users:
        pl_user_obj = PurpleleafUserEventHistory.objects.filter(
            username=user
        ).latest('created')
        pl_user_event_id_list.append(pl_user_obj.id)
    pl_user_event = PurpleleafUserEventHistory.objects.filter(
        id__in=pl_user_event_id_list
    )

    context = {
        'ips_message': message,
        'External_host_obj': External_host_obj,
        'Internal_host_obj': Internal_host_obj,
        'total_host': total_hosts,
        'application_data': application_data,
        'application_message': application_message,
        'assets_message': assets_message,
        'cloud_asset_data': cloud_asset_data,
        'total_assets': cloud_asset_data.count(),
        'total_applications': application_data.count(),
        'networks': network_obj,
        'total_networks': network_obj.count(),
        'domain_data': domains_data,
        'total_domains': domains_data.count(),
        'subdomains_data' : subdomains_data,
        'nessus_message' : nessus_message,
        'burp_message' : burp_message,
        'nessus_obj' : nessus_obj,
        'total_nessus' : nessus_obj.count(),
        'test_queue_message' : test_queue_message,
        'testing_obj' : testing_obj,
        'total_test' : testing_obj.count(),
        'pl_user_event': pl_user_event
    }
    return render(request, 'redtree_app/home.html', context)


@method_decorator(login_required, name='dispatch')
class VulnerabilitiesDetailView(View):
    template_name = 'redtree_app/vulnerabilities.html'
    context = dict()
    serializer_class = NetworkDetailSerializer

    def get_object(self):
        external_virtueIds = Vulnerability.objects.filter(
            host__user_host__network__network_type="External"
            ).values_list('virtue_id', flat=True)
        internal_virtueIds = Vulnerability.objects.filter(
            host__user_host__network__network_type="Internal"
            ).values_list('virtue_id', flat=True)
        external_vul_obj = get_sorted_vulnerabilities(
            virtue_ids=external_virtueIds,
            network_type="External"
        )
        internal_vul_obj = get_sorted_vulnerabilities(
            virtue_ids=internal_virtueIds,
            network_type="Internal"
        )
        vul_obj = {
            'external_vulnerabilities': external_vul_obj,
            'internal_vulnerabilities': internal_vul_obj
        }
        network_obj = Networks.objects.all().order_by('-id')
        return vul_obj, network_obj

    def get(self, request, *args, **kwargs):
        log_user_activity(request)
        vulnerabilities, networks = self.get_object()
        internal_net_serializer = self.serializer_class(
            networks.filter(network_type="Internal"), 
            many=True
        )
        external_net_serializer = self.serializer_class(
            networks.filter(network_type="External"),
            many=True
        )
        self.context['external_vulnerabilities'] = vulnerabilities.get(
            'external_vulnerabilities'
        )
        self.context['internal_vulnerabilities'] = vulnerabilities.get(
            'internal_vulnerabilities'
        )
        self.context['external_network'] = external_net_serializer.data
        self.context['internal_network'] = internal_net_serializer.data
        return render(
            request,
            self.template_name,
            self.context
        )
 

@method_decorator(login_required, name='dispatch')
class VulnerabilityCreateView(View):
    template_name = 'redtree_app/create-vulnerability.html'
    context = dict()

    def get(self, request, *args, **kwargs):
        log_user_activity(request)
        form = VulnerabilityForm()
        self.context['form'] = form
        return render(
            request,
            self.template_name,
            self.context
        )

    def post(self, request, *args, **kwargs):
        client_conf_obj = ClientConfiguration.objects.first()
        vul_type = request.POST.get("vulnerability_type")
        form = VulnerabilityForm(request.POST)
        if form.is_valid() and vul_type:
            host_array = form.cleaned_data.get('host')
            kb_virtue_id = request.POST.get('virtue_id')
            base_path = str(settings.BASE_DIR)
            evidence_images = find_markdown_images(form.cleaned_data['evidence'])
            remediation_images = find_markdown_images(form.cleaned_data['remediation'])
            description_images = find_markdown_images(form.cleaned_data['description'])
            all_images = evidence_images + remediation_images + description_images
            if all_images:
                for image in all_images:
                    image_path = base_path + str(image)
                    image_file = File(open(image_path, 'rb'))
                    if client_conf_obj and client_conf_obj.storage_type=="S3":
                        image_key = ''.join(['screenshots/',
                            os.path.basename(image_file.name)]
                        )
                        if not S3Uploads.objects.filter(key=image_key).exists():
                            media_uploader = MediaUploader(client_conf_obj,
                                image_key, image_file
                            )
                            result = media_uploader.upload()
                            if result == "success":
                                S3Uploads.objects.create(
                                    key=image_key,
                                    filename=os.path.basename(image_file.name)
                                )
            
            if not kb_virtue_id:
                if (vul_type == "network") and not Vulnerability.objects.all().exists():
                    virtue_id = 50000
                else:
                    last_vul = Vulnerability.objects.filter(virtue_id__gte=50000).last()
                    if last_vul:
                        last_virtue_id = last_vul.virtue_id
                    else:
                        last_virtue_id = 50000
                    virtue_id = last_virtue_id + 1
            else:
                virtue_id = kb_virtue_id
            
            virtue_id = virtue_id
            title = form.cleaned_data['title']
            risk = form.cleaned_data['risk']
            port = form.cleaned_data['port']

            raw_description = form.cleaned_data['description']
            raw_remediation = form.cleaned_data['remediation']
            raw_evidence = form.cleaned_data['evidence']

            description = change_media_path(raw_description)
            remediation = change_media_path(raw_remediation)
            evidence = change_media_path(raw_evidence)
            if host_array:
                host_list = host_array.split(',')
                if vul_type == "network":
                    for host in host_list:
                        host = host.strip()
                        host_type = get_host_type(host)
                        user_host = check_host_exists(host, host_type)
                        if user_host:
                            if not Host.objects.filter(
                                    user_host=user_host, host=host
                                ).exists():
                                host_obj = Host.objects.create(
                                    user_host=user_host, host=host
                                )
                            else:
                                host_obj = Host.objects.filter(
                                    user_host=user_host, host=host
                                ).first()
                            if not Vulnerability.objects.filter(
                                virtue_id=int(virtue_id),
                                port=port, host_ip=host
                            ).exists():
                                network_type = user_host.network.network_type
                                vul_obj = Vulnerability.objects.create(
                                    virtue_id=int(virtue_id), title=str(title),
                                    description=description.encode("utf-8"),
                                    risk=str(risk), port=str(port),
                                    evidence=evidence.encode("utf-8"),
                                    remediation=remediation.encode("utf-8"),
                                    host_ip=str(host), post_status=True,
                                    network_type=network_type, host=host_obj
                                )
            return redirect('/vulnerabilities')
        self.context['form'] = form
        return render(
            request,
            self.template_name,
            self.context
        )


@method_decorator(login_required, name='dispatch')
class VulnerabilitiesUpdateView(View):

    def get(self, request, *args, **kwargs):
        virtue_Ids = list(Vulnerability.objects.values_list(
            'virtue_id', flat=True
        ).distinct())
        if virtue_Ids:
            data = {
                'virtue_id_list': virtue_Ids
            }
            api_obj = ApiList.objects.first()
            if api_obj:
                url = "{}/api/articles-detail".format(api_obj.kb_base_url)
            else:
                url = None
            headers = {
                'Content-Type': 'application/json',
                'Accept':'application/json',
                'Authorization': 'Token {}'.format(api_obj.kb_auth_token)
            }
            try:
                response = requests.post(url, json=data, headers=headers)
            except:
                response = None
            if response and response.status_code == 200:
                try:
                    response_data = response.json()
                except:
                    response_data = None
                if response_data and response_data.get('code') == 200:
                    article_list = response_data.get('data').get('article_list')
                    for data in article_list:
                        if data.get('id'):
                            vul_objs = Vulnerability.objects.filter(
                                virtue_id=data.get('id')
                            )
                            if vul_objs.first():
                                kb_date = datetime.strptime(
                                    data.get('modified'),"%Y-%m-%d"
                                ).date()
                                vul_date = vul_objs.first().modified_date.date()
                                if kb_date and vul_date:
                                    modified_difference = kb_date > vul_date
                                    if modified_difference:
                                        vul_objs.update(
                                            title=data.get('title'),
                                            description=data.get('description'),
                                            remediation=data.get('remediation'),
                                            risk=data.get('risk'),
                                            modified_date=kb_date
                                        )
                    messages.success(
                        request,
                        "Vulnerabilities updated successfully."
                    )
                else:
                    messages.error(
                        request,
                        "Unable to update vulnerabilities, Bad response from KB."
                    )
            else:
                messages.error(
                    request,
                    "Unable to update vulnerabilities, Either KB is down or "\
                    "configuration is not setup properly."
                )
        else:
            messages.success(
                request,
                "No Vulnerabilities to be updated."
            )
        return redirect('/vulnerabilities')


@login_required
def create_application_vulnerability(request):
    log_user_activity(request)
    if request.method == "POST":
        form = ApplicationVulnerabilityForm(request.POST)
        if form.is_valid():
            messages.success(request, "Application Vulenrability created successfully.")
            form.save()
            return HttpResponseRedirect('/applications/')
    return HttpResponseRedirect('/vulnerabilities')


@method_decorator(login_required, name='dispatch')
class VulnerabilityDetailView(View):
    template_name = 'redtree_app/vulnerability-detail.html'
    context = dict()
    
    def get(self, request, *args, **kwargs):
        log_user_activity(request)
        virtue_id = int(kwargs.get('virtue_id'))
        request_url = request.path_info
        network_type = None
        if "/external/" in request_url:
            network_type = "External"
        elif "/internal/" in request_url:
            network_type = "Internal"
        affected_hosts = Vulnerability.objects.filter(
            virtue_id=virtue_id,
            host__user_host__network__network_type=network_type
        )
        vulnerability_evidence_objs = affected_hosts.values_list(
            'evidence', flat=True
        )
        evidence_list = [evidence for evidence in vulnerability_evidence_objs if evidence]
        evidence_count = len(evidence_list)
        vulnerability = affected_hosts.first()
        conf_obj = ClientConfiguration.objects.first()
        if conf_obj and affected_hosts:
            for vulnerability in affected_hosts:
                if vulnerability.evidence:
                    markdown_evidence = get_markdown_with_images(
                        vulnerability.evidence
                    )
                    vulnerability.evidence = markdownify(markdown_evidence)
        if conf_obj and vulnerability:
            if vulnerability.remediation:
                markdown_remediation = get_markdown_with_images(
                    vulnerability.remediation
                )
                vulnerability.remediation = markdownify(markdown_remediation)
            if vulnerability.description:
                markdown_description = get_markdown_with_images(
                    vulnerability.description
                )
                vulnerability.description = markdownify(markdown_description)
        banner_count = 0
        for banner in affected_hosts:
            if banner.banner:
                banner_count = banner_count + 1
        if banner_count > 0:
            banner_exist = True
        else:
            banner_exist = False
        page = request.GET.get('page', 1)
        paginator = Paginator(affected_hosts.order_by('-id'), 1000)
        try:
            affected_hosts = paginator.page(page)
        except PageNotAnInteger:
            affected_hosts = paginator.page(1)
        except EmptyPage:
            affected_hosts = paginator.page(paginator.num_pages)
        self.context['vulnerability'] = vulnerability
        self.context['evidence_count'] = evidence_count
        self.context['affected_hosts'] = affected_hosts
        self.context['banner'] = banner_exist
        return render(
            request,
            self.template_name,
            self.context
        )


def get_evidence_with_s3_images(markdown_text):
    regex = r"[^(\s]+\.(?:jpeg|jpg|png|gif)(?=\))"
    markdown_images = re.findall(regex, markdown_text)
    for image in markdown_images:
        image_key = ''.join(['screenshots/', os.path.basename(image)])
        client_conf_obj = ClientConfiguration.objects.first()
        media_uploader = MediaUploader(client_conf_obj, image_key)
        s3_image_link = media_uploader.get_link()
        markdown_text = re.sub(image, s3_image_link, markdown_text)
    return markdown_text


@method_decorator(login_required, name='dispatch')
class VulnerabilityHostDetailView(View):
    template_name = 'redtree_app/vulnerability-host-detail.html'
    context = dict()

    def get_vulnerability_obj(self):
        vul_id = self.kwargs.get('id')
        try:
            vul_obj = Vulnerability.objects.get(id=vul_id)
        except:
            vul_obj = None
        return vul_obj

    def get(self, request, *args, **kwargs):
        log_user_activity(request)
        vul_obj = self.get_vulnerability_obj()
        form = RetestNoteForm()
        client_conf_obj = ClientConfiguration.objects.first()
        if vul_obj and client_conf_obj:
            if vul_obj.evidence:
                vul_obj.evidence = get_markdown_with_images(vul_obj.evidence)
            if vul_obj.remediation:
                vul_obj.remediation = get_markdown_with_images(vul_obj.remediation)
            if vul_obj.description:
                vul_obj.description = get_markdown_with_images(vul_obj.description)
        self.context['vulnerability'] = vul_obj
        self.context['form'] = form
        return render(
            request,
            self.template_name,
            self.context
        )

    def post(self, request, *args, **kwargs):
        log_user_activity(request)
        vul_id = kwargs.get('id')
        redirect_url = "/vulnerabilities/{}".format(vul_id)
        vul_obj = self.get_vulnerability_obj()
        form = RetestNoteForm(request.POST)
        if form.is_valid() and vul_obj:
            try:
                retest_obj = vul_obj.retest
            except RetestVulnerabilities.DoesNotExist:
                retest_obj = RetestVulnerabilities.objects.create(
                    vulnerability=vul_obj
                    )
            retestnote_obj = form.save()
            retestnote_obj.vul_id = vul_id
            retestnote_obj.vulnerability = vul_obj
            if 'leave' in request.POST:
                status = 'Leave_Open'
            elif 'close' in request.POST:
                status = 'Closed'
            retestnote_obj.status = status
            retest_obj.status = status
            retest_obj.save()
            retestnote_obj.save()
        return redirect(redirect_url)


@method_decorator(login_required, name='dispatch')
class VulnerabilityUpdateView(View):
    template_name = 'redtree_app/vulnerability-edit.html'
    context = dict()

    def get_vulnerability_obj(self):
        vul_id = self.kwargs.get('id')
        try:
            vul_obj = Vulnerability.objects.get(id=vul_id)
        except:
            vul_obj = None
        if vul_obj:
            vulnerability_data = {
                "port": vul_obj.port,
                "risk": vul_obj.risk,
                "title": vul_obj.title,
                "description": vul_obj.description,
                "remediation": vul_obj.remediation,
                "evidence": vul_obj.evidence,
                "banner": vul_obj.banner,
            }
        else:
            vulnerability_data = None
        return vul_obj,vulnerability_data

    def get(self, request, *args, **kwargs):
        log_user_activity(request)
        vulnerability_obj, vulnerability_data = self.get_vulnerability_obj()
        client_conf_obj = ClientConfiguration.objects.first()
        network_type = None
        virtue_id = None
        if vulnerability_obj and client_conf_obj:
            network_type = vulnerability_obj.host.user_host.network.network_type.lower()
            virtue_id = vulnerability_obj.virtue_id
            if vulnerability_obj.evidence:
                vulnerability_obj.evidence = get_markdown_with_images(
                    vulnerability_obj.evidence
                )
            if vulnerability_obj.remediation:
                vulnerability_obj.remediation = get_markdown_with_images(
                    vulnerability_obj.remediation
                )
            if vulnerability_obj.description:
                vulnerability_obj.description = get_markdown_with_images(
                    vulnerability_obj.description
                )

        form = VulnerabilityEditForm(initial=vulnerability_data)
        self.context['form'] = form
        self.context['network'] = network_type
        self.context['virtue_id'] = virtue_id 
        return render(
            request,
            self.template_name,
            self.context
        )

    def post(self, request, *args, **kwargs):
        client_conf_obj = ClientConfiguration.objects.first()
        vulnerability_obj, vulnerability_data = self.get_vulnerability_obj()
        if vulnerability_obj:
            network_type = vulnerability_obj.host.user_host.network.network_type.lower()
            virtue_id = vulnerability_obj.virtue_id
        else:
            network_type = None
            virtue_id = None
        form = VulnerabilityEditForm(request.POST, initial=vulnerability_data)
        if form.is_valid() and form.has_changed():
            vulnerability_obj.port = form.cleaned_data.get('port')
            vulnerability_obj.title = form.cleaned_data.get('title')
            vulnerability_obj.description = change_media_path(
                form.cleaned_data.get('description')
            )
            vulnerability_obj.remediation = change_media_path(
                form.cleaned_data.get('remediation')
            )
            vulnerability_obj.evidence = change_media_path(
                form.cleaned_data.get('evidence')
            )
            vulnerability_obj.risk = form.cleaned_data.get('risk')
            vulnerability_obj.save()
            if vulnerability_obj.evidence:
                evidence_images = find_markdown_images(vulnerability_obj.evidence)
            else:
                evidence_images = []
            if vulnerability_obj.remediation:
                remediation_images = find_markdown_images(vulnerability_obj.remediation)
            else:
                remediation_images = []
            if vulnerability_obj.description:
                description_images = find_markdown_images(vulnerability_obj.description)
            else:
                description_images = []

            all_images = evidence_images + remediation_images + description_images
            base_path = str(settings.BASE_DIR)
            for image in all_images:
                if not S3Uploads.objects.filter(key=image).exists():
                    actual_file_path = ''.join(['/media/', image])
                    image_path = base_path + str(actual_file_path)
                    image_file = File(open(image_path, 'rb'))
                    if client_conf_obj and client_conf_obj.storage_type=="S3":
                        image_key = ''.join(['screenshots/', os.path.basename(
                            image_file.name)]
                        )
                        media_uploader = MediaUploader(
                            client_conf_obj, image_key, image_file
                        )
                        result = media_uploader.upload()
                        if result == "success" and not S3Uploads.objects.filter(
                                key=image_key
                            ).exists():
                            S3Uploads.objects.create(
                                key=image_key,
                                filename=os.path.basename(image_file.name)
                            )
            redirect_url = "/vulnerabilities/{}/{}/".format(network_type, virtue_id)
            return redirect(redirect_url)
        elif form.is_valid() and not form.has_changed():
            redirect_url = "/vulnerabilities/{}/{}/".format(network_type, virtue_id)
            return redirect(redirect_url)
        self.context['form'] = form
        self.context['network'] = network_type
        self.context['virtue_id'] = virtue_id
        return render(
            request,
            self.template_name,
            self.context
        )


@method_decorator(login_required, name='dispatch')
class VulnerabilityDeleteView(View):

    def get_vulnerability_obj(self):
        vul_id = self.kwargs.get('id')
        try:
            vul_obj = Vulnerability.objects.get(id=vul_id)
        except:
            vul_obj = None
        return vul_obj

    def get(self, request, *args, **kwargs):
        log_user_activity(request)
        vulnerability_obj = self.get_vulnerability_obj()
        virtue_id = None
        network_type = None
        if vulnerability_obj:
            network_type = vulnerability_obj.host.user_host.network.network_type.lower()
            virtue_id = vulnerability_obj.virtue_id
            vulnerability_obj.delete()
            messages.success(request, "Vulnerability deleted successfully")
        else:
            messages.error(request, "vulnerability doesn't exists")
        if Vulnerability.objects.filter(virtue_id=virtue_id).exists():
            # redirect_url = request.META.get('HTTP_REFERER')
            redirect_url = "/vulnerabilities/{}/{}/".format(network_type, virtue_id)
        else:
            redirect_url = "/vulnerabilities/"
        return redirect(redirect_url)


@method_decorator(login_required, name='dispatch')
class VulnerabilitiesDeleteView(View):
    
    def get_vulnerability_objs(self):
        virtue_id = self.kwargs.get('virtue_id')
        return Vulnerability.objects.filter(virtue_id=virtue_id)

    def get(self, request, *args, **kwargs):
        log_user_activity(request)
        vul_obj = self.get_vulnerability_objs()
        if vul_obj:
            vul_obj.delete()
            response_text = {
                'CODE': 200,
                'status': True
            }
            return JsonResponse(response_text, safe=False)
        response_text = {
            'CODE': 400,
            'status': False
        }
        return JsonResponse(response_text, safe=False)


def get_page_body(boxes):
    for box in boxes:
        if box.element_tag == 'body':
            return box
        return get_page_body(box.all_children())



@login_required
def report(request):
    log_user_activity(request)
    return render(request, 'redtree_app/report.html')



def get_affected_hosts(**kwargs):
    affected_hosts = Vulnerability.objects.filter(
        virtue_id=kwargs.get('virtue_id'),
        risk=kwargs.get('risk'),
        host__user_host__network__network_type=kwargs.get('network_type')
    )
    return affected_hosts


def get_report_data(*args, **kwargs):
    request = kwargs.get('request')
    network_type = kwargs.get('network_type')
    totalhighvulnerabilities = None
    totalmediumvulnerabilities = None
    totallowvulnerabilities = None
    totalcriticalvulnerabilities = None
    vulnerabilities_obj = Vulnerability.objects.filter(
        host__user_host__network__network_type=network_type
    ).exclude(risk="Note")
    vulnerabilities_obj = vulnerabilities_obj.\
        values('virtue_id', 'risk', 'title').annotate(
        instances=Count('title'))
    for data in vulnerabilities_obj:
        data['risk_factor'] = get_risk_factor(data['risk'])

    all_vulnerabilities = sorted(vulnerabilities_obj,
        key=lambda x: x['risk_factor'], reverse=True
    )
    criticalVulnerabilities = vulnerabilities_obj.filter(risk="Critical").\
        values('title', 'virtue_id',
            'risk', 'description',
            'remediation', 'evidence',
            'banner'
        ).annotate(title_count=Count('title'))
    critical_vulnerabilities = sorted(criticalVulnerabilities,
        key=lambda x: x['title'], reverse=True
    )
    highVulnerabilities = vulnerabilities_obj.filter(risk="High").\
        values('title', 'virtue_id',
            'risk', 'description',
            'remediation', 'evidence',
            'banner'
        ).annotate(itle_count=Count('title'))

    high_vulnerabilities = sorted(highVulnerabilities,
        key=lambda x: x['title'], reverse=True
    )
    mediumVulnerabilities = vulnerabilities_obj.filter(risk="Medium").\
        values('title', 'virtue_id',
            'risk', 'description',
            'remediation', 'evidence',
            'banner'
        ).annotate(title_count=Count('title'))
    medium_vulnerabilities = sorted(mediumVulnerabilities,
        key=lambda x: x['title'], reverse=True
    )
    lowVulnerabilities = vulnerabilities_obj.filter(risk="Low").\
        values('title', 'virtue_id',
            'risk', 'description',
            'remediation', 'evidence',
            'banner'
        ).annotate(title_count=Count('title'))
    low_vulnerabilities = sorted(lowVulnerabilities,
        key=lambda x: x['title'], reverse=True
    )

    for vulnerability in critical_vulnerabilities:
        kwargs = {'virtue_id': vulnerability['virtue_id'], 'title': vulnerability['title'],
                  'risk': vulnerability['risk'], 'network_type': network_type}
        vulnerability['affected_hosts'] = get_affected_hosts(**kwargs)
        if vulnerability['description']:
            vulnerability['description'] = get_markdown_with_images(vulnerability['description'])
        if vulnerability['remediation']:
            vulnerability['remediation'] = get_markdown_with_images(vulnerability['remediation'])
        if vulnerability['evidence']:
            vulnerability['evidence'] = get_markdown_with_images(vulnerability['evidence'])

    for vulnerability in high_vulnerabilities:
        kwargs = {'virtue_id': vulnerability['virtue_id'], 'title': vulnerability['title'],
                  'risk': vulnerability['risk'], 'network_type': network_type}
        vulnerability['affected_hosts'] = get_affected_hosts(**kwargs)
        if vulnerability['description']:
            vulnerability['description'] = get_markdown_with_images(vulnerability['description'])
        if vulnerability['remediation']:
            vulnerability['remediation'] = get_markdown_with_images(vulnerability['remediation'])
        if vulnerability['evidence']:
            vulnerability['evidence'] = get_markdown_with_images(vulnerability['evidence'])

    for vulnerability in medium_vulnerabilities:
        kwargs = {'virtue_id': vulnerability['virtue_id'], 'title': vulnerability['title'],
                  'risk': vulnerability['risk'], 'network_type': network_type}
        vulnerability['affected_hosts'] = get_affected_hosts(**kwargs)
        if  vulnerability['description']:
            vulnerability['description'] = get_markdown_with_images(vulnerability['description'])
        if vulnerability['remediation']:
            vulnerability['remediation'] = get_markdown_with_images(vulnerability['remediation'])
        if vulnerability['evidence']:
            vulnerability['evidence'] = get_markdown_with_images(vulnerability['evidence'])

    for vulnerability in low_vulnerabilities:
        kwargs = {'virtue_id': vulnerability['virtue_id'], 'title': vulnerability['title'],
                  'risk': vulnerability['risk'], 'network_type': network_type}
        vulnerability['affected_hosts'] = get_affected_hosts(**kwargs)
        if vulnerability['description']:
            vulnerability['description'] = get_markdown_with_images(vulnerability['description'])
        if vulnerability['remediation']:
            vulnerability['remediation'] = get_markdown_with_images(vulnerability['remediation'])
        if vulnerability['evidence']:
            vulnerability['evidence'] = get_markdown_with_images(vulnerability['evidence'])

    if critical_vulnerabilities:
        totalcriticalvulnerabilities = len(critical_vulnerabilities)
    if high_vulnerabilities:
        totalhighvulnerabilities = len(high_vulnerabilities)
    if medium_vulnerabilities:
        totalmediumvulnerabilities = len(medium_vulnerabilities)
    if low_vulnerabilities:
        totallowvulnerabilities = len(low_vulnerabilities)
    allhosts = UserHosts.objects.all()
    all_network_hosts = UserHosts.objects.filter(
        network__network_type=network_type
    )
    client_obj = ClientConfiguration.objects.first()
    if client_obj:
        clientName = client_obj.client_name
        clientLegalName = client_obj.client_legal_name
    else:
        clientName = None
        clientLegalName = None
    client_info = {
        'name': clientLegalName,
        'client_name': clientName,
        'testing_date': date.today().strftime("%B %d, %Y")

    }
    document_info = {
        'tester_name': 'Elliott Frantz',
        'office': '244 5th Avenue Suite F290 New York, NY 10001',
        'contact_number': '347-826-3330',
        'email': 'Elliott.Frantz@virtuesecurity.com'
    }

    report_data = {
        'allvulnerabilities': all_vulnerabilities,
        'criticalvulnerabilities': critical_vulnerabilities,
        'highvulnerabilities': high_vulnerabilities,
        'mediumvulnerabilities': medium_vulnerabilities,
        'lowvulnerabilities': low_vulnerabilities,
        'totalcriticalvulnerabilities': totalcriticalvulnerabilities,
        'totalhighvulnerabilities': totalhighvulnerabilities,
        'totalmediumvulnerabilities': totalmediumvulnerabilities,
        'totallowvulnerabilities': totallowvulnerabilities,
        'client_info': client_info,
        'document_info': document_info,
        'allhosts': allhosts,
        'all_network_hosts': all_network_hosts
    }
    return report_data


@login_required
def report_details(request):
    external_report_data = get_report_data(request=request, network_type="External")
    internal_report_data = get_report_data(request=request, network_type="Internal")
    report_data = {
        'external_report_data': external_report_data,
        'internal_report_data': internal_report_data
    }
    return render(request, 'redtree_app/report-design.html', report_data)


@method_decorator(login_required, name='dispatch')
class report_pdf(View):
        
    def get(self, request):
        log_user_activity(request)
        from redtree_app.tasks import create_report
        response, message = create_report(request=request)
        if response:
            return response
        else:
            messages.error(request, message)
            return redirect("/report/")


@method_decorator(login_required, name='dispatch')
class RetestVulnerabilitiesView(View):
    template_name = 'redtree_app/retest-vulnerabilities.html'
    context = dict()

    def get(self, request, *args, **kwargs):
        log_user_activity(request)
        form = RetestNoteForm()
        Notifications.objects.filter(seen=False).update(seen=True)
        retest_vul = RetestVulnerabilities.objects.filter(status='Requested')
        self.context['issues'] = retest_vul
        self.context['form'] = form
        return render(
            request,
            self.template_name,
            self.context
        )


@login_required
def notifications(request):
    notification_list = []
    retest_notifications = Notifications.objects.filter(seen=False).count()
    app_notifications = AppNotification.objects.filter(seen=False)[:100]
    for notification in app_notifications:
        notification_list.append({'type':notification.issue_type, 
            'message': notification.notification_message,
            'created_at': get_notification_time(notification.created)})
    context = {
        'retest': retest_notifications,
        'app_notifications': notification_list
    }
    return JsonResponse(context, safe=False)


@login_required
def scanningstatus(request):
    try:
        scanningstatus = Configuration.objects.first().scanning_status
    except Configuration.DoesNotExist:
        scanningstatus = 'no data'
    except:
        scanningstatus = 'no data'
    return JsonResponse(scanningstatus, safe=False)


@login_required
def setting(request):
    log_user_activity(request)
    api_obj = ApiList.objects.first()
    client_conf_obj = ClientConfiguration.objects.first()
    client_aws_assets = ClientAwsAssets.objects.first()
    if client_conf_obj:
        manual_hours_purchased = client_conf_obj.manual_hours_purchased
        manual_hours_remaining = client_conf_obj.manual_hours_remaining
    else:
        manual_hours_purchased = None
        manual_hours_remaining = None
    if client_conf_obj:
        data = {'timezone': client_conf_obj.time_zone}
    else:
        data = {'timezone': None}
    timezoneform = TimezoneForm(data, auto_id=False)
    regions = AwsRegion.objects.all()
    if client_conf_obj:
        application_status = client_conf_obj.application_status
        analytics_status = client_conf_obj.analytics_status
        scan_frequency = client_conf_obj.scan_frequency
        hostname = client_conf_obj.hostname
    else:
        application_status = None
        analytics_status = None
        scan_frequency = None
        hostname = None
    user_obj = PurpleleafUsers.objects.all()
    appliances_obj = Appliances.objects.all()
    notification_obj = NotificationEmails.objects.all()
    conf_obj = Configuration.objects.first()
    app_conf_form = AppConfigurationForm(instance=conf_obj)
    NotificationListFormset = modelformset_factory(NotificationEmails,
                                                   form=NotificationEmailListForm, extra=1)
    AppliancesFormset = modelformset_factory(Appliances, form=AppliancesForm, extra=1)
    appliances_forms = AppliancesFormset(queryset=appliances_obj)

    form = ApiForm(instance=api_obj)
    client_conf_form = ClientConfigurationForm(instance=client_conf_obj)
    scan_frequency_form = MicroServiceScanFrequencyForm(instance=client_conf_obj)
    notification_emails_forms = NotificationListFormset(queryset=notification_obj)
    media_form = MediaUploadTypeForm(instance=client_conf_obj)
    aws_settings_form = AwsSettingsForm(instance=client_aws_assets)
    client_conf = ClientConfiguration.objects.first()
    appliances_form = AppliancesForm()
    if request.method == "POST":
        form_type = request.POST.get('form-type')
        if form_type == "emaillist":
            notification_emails_forms = NotificationListFormset(
                request.POST, queryset=notification_obj
            )
            for email_form in notification_emails_forms:
                if email_form.is_valid() and email_form.has_changed():
                    if email_form.cleaned_data.get('email') is None:
                        continue
                    else:
                        email_form.save()
                        if 'email' in email_form.changed_data:
                            RedtreeEventHistory.objects.create(
                                event_type='change_setting',
                                time_stamp=datetime.now().strftime('%s'),
                                username=request.user.username,
                                ip=get_request_ip(request),
                                data='email: '+ email_form.cleaned_data.get('email')
                                )
        elif form_type == "clientconf":
            client_conf_form = ClientConfigurationForm(request.POST, instance=client_conf_obj)
            if client_conf_form.is_valid() and client_conf_form.has_changed():
                changed_data = {}
                for key in client_conf_form.changed_data:
                    changed_data[key] = str(client_conf_form.cleaned_data.get(key))
                if client_conf_form.cleaned_data.get('manual_hours_purchased') and manual_hours_purchased:
                    hours_purchased = int(client_conf_form.cleaned_data.get('manual_hours_purchased')) - int(manual_hours_purchased)
                    if hours_purchased != 0 and manual_hours_remaining:
                        hours_remaining = int(manual_hours_remaining) + int(hours_purchased)
                        if hours_remaining > 0:
                            manual_hours_remaining = hours_remaining
                        else:
                            manual_hours_remaining = 0
                        changed_data["manual_hours_remaining"] = manual_hours_remaining
                elif client_conf_form.cleaned_data.get('manual_hours_purchased') and not manual_hours_purchased:
                    hours_purchased = client_conf_form.cleaned_data.\
                        get('manual_hours_purchased')
                    changed_data["manual_hours_remaining"] = hours_purchased
                    manual_hours_remaining = hours_purchased
                elif client_conf_form.cleaned_data.get('manual_hours_purchased') is None:
                    hours_purchased = None
                    changed_data["manual_hours_remaining"] = None
                    manual_hours_remaining = None
                post_url = "{}/private/update-configuration".format(hostname)
                headers = {'data-auth-key': client_conf_obj.\
                    authentication_token, 'Content-Type': 'application/json', 'Accept':'application/json'}
                
                try:
                    response = requests.post(post_url, headers=headers, json=changed_data)
                except Exception as error:
                    response = None
                    messages.add_message(request, messages.WARNING, 'Unable to update Configuration')
                    RedtreeEventHistory.objects.create(
                                    event_type  =   'error',
                                    time_stamp  =   datetime.now().strftime('%s'),
                                    username    =   request.user.username,
                                    ip          =   get_request_ip(request),
                                    data        =   'Unable to update configuration due to ' + str(error)
                                    )
                if response and response.status_code == 200:
                    if (hours_purchased and hours_purchased != 0) or\
                        client_conf_form.cleaned_data.get('manual_hours_purchased') is None:
                        client_conf_object = client_conf_form.save(commit=False)
                        client_conf_object.manual_hours_remaining = manual_hours_remaining
                        client_conf_object.save()
                    else:
                        client_conf_form.save()
                    for key in client_conf_form.changed_data:
                        data = str(client_conf_form.cleaned_data.get(key))
                        if key == "application_status" or key == "analytics_status":
                            if key == "application_status" and data != str(application_status):
                                RedtreeEventHistory.objects.create(
                                    event_type  =   'change_setting',
                                    time_stamp  =   datetime.now().strftime('%s'),
                                    username    =   request.user.username,
                                    ip          =   get_request_ip(request),
                                    data        =   '{}: '.format(key) + data
                                    )

                            if key == "analytics_status" and data != str(analytics_status):
                                RedtreeEventHistory.objects.create(
                                    event_type  =   'change_setting',
                                    time_stamp  =   datetime.now().strftime('%s'),
                                    username    =   request.user.username,
                                    ip          =   get_request_ip(request),
                                    data        =   '{}: '.format(key) + data
                                    )
                        else:
                            RedtreeEventHistory.objects.create(
                                event_type  =   'change_setting',
                                time_stamp  =   datetime.now().strftime('%s'),
                                username    =   request.user.username,
                                ip          =   get_request_ip(request),
                                data        =   '{}: '.format(key) + data
                                )
                    messages.add_message(request, messages.SUCCESS,
                        'Configuration updated successfully'
                    )

        elif form_type == "apiform":
            form = ApiForm(request.POST, instance=api_obj)
            if form.is_valid():
                form.save()
                for key in form.changed_data:
                    data = str(form.cleaned_data.get(key))
                    RedtreeEventHistory.objects.create(
                        event_type  =   'change_setting',
                        time_stamp  =   datetime.now().strftime('%s'),
                        username    =   request.user.username,
                        ip          =   get_request_ip(request),
                        data        =   '{}: '.format(key) + data
                        )
                messages.add_message(request, messages.SUCCESS, 'Configuration updated successfully')

        elif form_type == "app_conf_form":
            app_conf_form = AppConfigurationForm(request.POST, instance=conf_obj)
            if app_conf_form.is_valid() and app_conf_form.has_changed():
                app_conf_form.save()
                if 'purpleleaf_auth_key' in app_conf_form.changed_data:
                    if app_conf_form.cleaned_data.get('purpleleaf_auth_key'):
                        data = app_conf_form.cleaned_data.get('purpleleaf_auth_key')
                    else:
                        data = 'None'
                    RedtreeEventHistory.objects.create(
                                event_type  =   'change_setting',
                                time_stamp  =   datetime.now().strftime('%s'),
                                username    =   request.user.username,
                                ip          =   get_request_ip(request),
                                data        =   'purpleleaf_auth_key: ' + data
                                )
        elif form_type == 'image_upload':
            media_form = MediaUploadTypeForm(request.POST, instance=client_conf_obj)
            if media_form.is_valid() and media_form.has_changed():
                changed_data = {}
                for key in media_form.changed_data:
                    changed_data[key] = str(media_form.cleaned_data.get(key))
                
                post_url = "{}/private/update-configuration".format(hostname)
                headers = {'data-auth-key': client_conf_obj.authentication_token, 'Content-Type': 'application/json', 'Accept':'application/json'}
                
                try:
                    response = requests.post(post_url, headers=headers, json=changed_data)
                except Exception as error:
                    response = None
                    messages.add_message(request, messages.WARNING, 'Unable to update Configuration')
                    RedtreeEventHistory.objects.create(
                                    event_type  =   'error',
                                    time_stamp  =   datetime.now().strftime('%s'),
                                    username    =   request.user.username,
                                    ip          =   get_request_ip(request),
                                    data        =   'Unable to update configuration due to ' + str(error)
                                    )
                if response and response.status_code == 200:
                    media_form.save()
                    for key in media_form.changed_data:
                        data = str(media_form.cleaned_data.get(key))
                        RedtreeEventHistory.objects.create(
                            event_type  =   'change_setting',
                            time_stamp  =   datetime.now().strftime('%s'),
                            username    =   request.user.username,
                            ip          =   get_request_ip(request),
                            data        =   '{}: '.format(key) + data
                            )
                    messages.add_message(request, messages.SUCCESS,
                        'Configuration updated successfully'
                    )

        elif form_type == 'aws_form':
            aws_settings_form = AwsSettingsForm(
                request.POST,
                instance=client_aws_assets
                )
            if aws_settings_form.is_valid() and aws_settings_form.has_changed():
                changed_data = {}
                for key in aws_settings_form.changed_data:
                    changed_data[key.split('client_')[1]] = str(aws_settings_form.cleaned_data.get(key))
                post_url = "{}/private/update-configuration".format(hostname)
                headers = {'data-auth-key': client_conf_obj.authentication_token, 'Content-Type': 'application/json', 'Accept':'application/json'}
                
                try:
                    response = requests.post(post_url, headers=headers, json=changed_data)
                except Exception as error:
                    response = None
                    messages.add_message(request, messages.WARNING, 'Unable to update Configuration')
                    RedtreeEventHistory.objects.create(
                                    event_type  =   'error',
                                    time_stamp  =   datetime.now().strftime('%s'),
                                    username    =   request.user.username,
                                    ip          =   get_request_ip(request),
                                    data        =   'Unable to update configuration due to ' + str(error)
                                    )
                if response and response.status_code == 200:
                    aws_settings_form.save()
                    for key in aws_settings_form.changed_data:
                        data = str(aws_settings_form.cleaned_data.get(key))
                        RedtreeEventHistory.objects.create(
                            event_type  =   'change_setting',
                            time_stamp  =   datetime.now().strftime('%s'),
                            username    =   request.user.username,
                            ip          =   get_request_ip(request),
                            data        =   '{}: '.format(key) + data
                            )
                    messages.add_message(request, messages.SUCCESS, 'Configuration updated successfully')
               
              
        elif form_type == "aws_regions":
            region_list = request.POST.getlist('regions')
            AwsRegion.objects.filter(id__in=region_list).update(status=True)
            AwsRegion.objects.exclude(id__in=region_list).update(status=False)
            messages.add_message(request, messages.SUCCESS, 'Aws Regions updated successfully')

        elif form_type == "timezone":
            if client_conf_obj:
                timezoneform = TimezoneForm(request.POST)
                if timezoneform.is_valid() and timezoneform.has_changed():
                    client_conf_obj.time_zone = timezoneform.cleaned_data.get('timezone')
                    client_conf_obj.save()
                    for key in timezoneform.changed_data:
                        data = str(timezoneform.cleaned_data.get(key))
                        RedtreeEventHistory.objects.create(
                            event_type  =   'change_setting',
                            time_stamp  =   datetime.now().strftime('%s'),
                            username    =   request.user.username,
                            ip          =   get_request_ip(request),
                            data        =   '{}: '.format(key) + data
                            )
                    messages.add_message(request, messages.SUCCESS, 'Configuration updated successfully')

        elif form_type == "appliances":
            appliances_forms = AppliancesFormset(request.POST, queryset=appliances_obj)
            for appliance_form in appliances_forms:
                if appliance_form.is_valid() and appliance_form.has_changed():
                    if appliance_form.cleaned_data.get('appliance_ip') and appliance_form.cleaned_data.get('network_type') is None:
                        continue
                    else:
                        try:
                            appliance_form.save()
                            messages.success(request, "Request processed successfully")
                        except:
                            messages.error(request, "Unable to update appliance")
        elif form_type == "scan_freq_form":
            scan_frequency_form = MicroServiceScanFrequencyForm(request.POST, instance=client_conf_obj)
            if scan_frequency_form.is_valid() and scan_frequency_form.has_changed():
                scan_frequency = int(scan_frequency_form.cleaned_data.get('scan_frequency'))
                scan_frequency_obj = scan_frequency_form.save()
                date = datetime.now() + timedelta(days=scan_frequency)
                day = date.day
                scan_frequency_obj.next_scan = day
                scan_frequency_obj.next_scan_date = date
                scan_frequency_obj.last_scan=timezone.now()
                scan_frequency_obj.save()
                for key in scan_frequency_form.changed_data:
                    data = str(scan_frequency_form.cleaned_data.get(key))
                    if key == "scan_frequency":
                        if key == "scan_frequency" and int(data) != int(scan_frequency):
                            RedtreeEventHistory.objects.create(
                                event_type  =   'change_setting',
                                time_stamp  =   datetime.now().strftime('%s'),
                                username    =   request.user.username,
                                ip          =   get_request_ip(request),
                                data        =   '{}: '.format(key) + data
                                )
                    else:
                        RedtreeEventHistory.objects.create(
                            event_type  =   'change_setting',
                            time_stamp  =   datetime.now().strftime('%s'),
                            username    =   request.user.username,
                            ip          =   get_request_ip(request),
                            data        =   '{}: '.format(key) + data
                            )
                messages.add_message(request, messages.SUCCESS, 'Configuration updated successfully')


        return redirect('/settings')
    else:
        context = {
            'form': form,
            'client_conf_form': client_conf_form,
            'notification_emails_forms': notification_emails_forms,
            'app_conf_form': app_conf_form,
            'user_obj': user_obj,
            'url': os.environ.get('PURPLELEAF_URL'),
            'media_upload_form': media_form,
            'aws_settings_form': aws_settings_form,
            'regions':regions,
            'timezoneform': timezoneform,
            'appliances_form': appliances_forms,
            'appliances_obj': appliances_obj,
            'scan_frequency_form':scan_frequency_form
        }
        return render(request, 'nessus/setting.html', context)


@require_http_methods(["POST"])
@login_required
def add_user(request):
    if request.is_ajax():
        log_user_activity(request)
        name = request.POST.get('name')
        email = request.POST.get('email')
        if not PurpleleafUsers.objects.filter(user_email=email).exists():
            conf_obj = ClientConfiguration.objects.first()
            if conf_obj:
                post_url = "{}/private/user".format(conf_obj.hostname)
                data = {
                    'name': name,
                    'email': email
                }
                headers = {
                    'data-auth-key': conf_obj.authentication_token
                }
                try:
                    response = requests.post(
                        post_url,
                        data=data,
                        headers=headers
                    )
                except Exception as e:
                    error_message = "Either some network issue or purpleleaf is down!"
                    responseData = {
                        'status': False,
                        'message': error_message
                    }
                    return JsonResponse(responseData, safe=False)
                if response and response.status_code == 201:
                    response_data = response.json().get('user')
                    pl_user_obj = PurpleleafUsers.objects.create(
                        user_name=response_data.get('name'),
                        user_email=response_data.get('email'),
                        purpleleaf_id=response_data.get('id'),
                        activation_key=response_data.get('activation_key')
                    )
                    RedtreeEventHistory.objects.create(
                        event_type='Add PL User Success',
                        time_stamp=datetime.now().strftime('%s'),
                        username=request.user.username,
                        ip=get_request_ip(request),
                        data=response_data.get('email')
                    )
                    responseData = {
                        'status': True,
                        'message': "User added Successfully!"
                    }
                    return JsonResponse(responseData, safe=False)
                elif response.status_code == 403:
                    responseData = {
                        'status': False,
                        'message': "Invalid AUTH key"
                    }
                    return JsonResponse(responseData, safe=False)
                else:
                    try:
                        response = response.json()
                    except:
                        response = None
                    if response and response.get('errors'):
                        error_message = response.get('errors')
                    elif response and not response.get('errors'):
                        error_message = response
                    else:
                        error_message = "Either some network issue or purpleleaf is down!"
                    responseData = {
                        'status': False,
                        'message': error_message
                    }
                    return JsonResponse(responseData, safe=False)
        else:
            responseData = {
                'status': False,
                'message': "User with given email already exists"
            }
            return JsonResponse(responseData, safe=False)


@require_http_methods(["POST"])
@login_required
def edit_user(request):
    if request.is_ajax():
        log_user_activity(request)
        user_id = request.POST.get('user_id')
        name = request.POST.get('name')
        email = request.POST.get('email')
        conf_obj = ClientConfiguration.objects.first()
        try:
            user_obj = PurpleleafUsers.objects.get(id=user_id)
        except:
            error_message = "User doesn't exists!"
            responseData = {
                'status': False,
                'message': error_message
            }
            return JsonResponse(responseData, safe=False)
        user_name = user_obj.user_name
        user_email = user_obj.user_email
        pl_id = user_obj.purpleleaf_id
        if pl_id:
            post_url = "{}/private/user/{}".format(
                conf_obj.hostname,
                pl_id
            )
        else:
            post_url = "{}/private/user".format(
                conf_obj.hostname
            )
        if conf_obj and (user_name != name or user_email != email):
            data = {
                'name': name,
                'email': email,
                'check_email': user_email
            }
            headers = {
                'data-auth-key': conf_obj.authentication_token
            }
            try:
                response = requests.patch(post_url, data=data, headers=headers)
            except:
                error_message = "Either some network issue or purpleleaf is down!"
                responseData = {
                    'status': False,
                    'message': error_message
                }
                return JsonResponse(responseData, safe=False)
            if response and response.status_code == 200:
                user_obj.user_name = name
                user_obj.user_email = email
                user_obj.save()
                if user_name != name:
                    RedtreeEventHistory.objects.create(
                            event_type='change_setting',
                            time_stamp=datetime.now().strftime('%s'),
                            username=request.user.username,
                            ip=get_request_ip(request),
                            data='user_name: '+ name
                        )
                if user_email != email:
                    RedtreeEventHistory.objects.create(
                            event_type='change_setting',
                            time_stamp=datetime.now().strftime('%s'),
                            username=request.user.username,
                            ip=get_request_ip(request),
                            data='user_email: '+ email
                        )
                responseData = {
                    'status': True,
                    'message': "User updated successfully!"
                }
                return JsonResponse(responseData, safe=False)
            elif response.status_code == 403:
                responseData = {
                    'status': False,
                    'message': "Invalid AUTH key"
                }
                return JsonResponse(responseData, safe=False)
            else:
                try:
                    response = response.json()
                except:
                    response = None
                if response and response.get('errors'):
                    error_message = response.get('errors')
                elif response and not response.get('errors'):
                    error_message = response
                else:
                    error_message = "Either some network issue or purpleleaf is down!"
                responseData = {
                    'status': False,
                    'message': error_message
                }
                return JsonResponse(responseData, safe=False)
        responseData = {
            'status': True,
            'message': "User updated successfully!"
        }
        return JsonResponse(responseData, safe=False)


@login_required
def user_delete(request, id):
    log_user_activity(request)
    conf_obj = ClientConfiguration.objects.first()
    try:
        user_obj = PurpleleafUsers.objects.get(id=id)
    except:
        messages.error(request, "User doesn't exists!")
        return redirect('/settings')
    user_email = user_obj.user_email
    pl_id = user_obj.purpleleaf_id
    if pl_id:
        post_url = "{}/private/user/{}".format(
            conf_obj.hostname,
            pl_id
        )
    else:
        post_url = "{}/private/user".format(
            conf_obj.hostname
        )
    data = {
        'check_email': user_email
    }
    headers = {
        'data-auth-key': conf_obj.authentication_token
    }
    try:
        response = requests.delete(
            post_url,
            data=data,
            headers=headers
        )
    except:
        error_message = "Either some network issue or purpleleaf is down!"
        messages.error(request, error_message)
        return redirect('/settings')
    if response and response.status_code == 200:
        RedtreeEventHistory.objects.create(
            event_type='Delete PL User Success',
            time_stamp=datetime.now().strftime('%s'),
            username=request.user.username,
            ip=get_request_ip(request),
            data=user_email
        )
        user_obj.delete()
        messages.success(request, "User deleted successfully!")
        return redirect('/settings')
    elif response.status_code == 403:
        messages.error(request, "Invalid AUTH key!")
        return redirect('/settings')
    else:
        try:
            response = response.json()
        except:
            response = None
        if response and response.get('message'):
            error_message = response.get('message')
        elif response and response.get('errors'):
            error_message = response.get('errors')
        elif response and not response.get('errors'):
            error_message = response
        else:
            error_message = "Either some network issue or purpleleaf is down!"
        messages.error(request, error_message)
        return redirect('/settings')


@login_required
def delete_notification_email(request, email_id):
    try:
        email_obj = NotificationEmails.objects.get(id=email_id)
    except NotificationEmails.DoesNotExist:
        email_obj = None
    if email_obj:
        email_obj.delete()
        messages.success(request, "Notification email deleted successfully.")
    else:
        messages.error(request, "No such notification email")
    return redirect('/settings')


@require_http_methods(["POST"])
@login_required
def ipinfodata(request):
    if request.method == "POST":
        hosts = UserHosts.objects
        hostid = request.POST.get('hostid', None)
        try:
            hostObj = hosts.get(pk=hostid)
        except:
            hostObj = None
        if hostid:
            ips = list()
            hostType = hostObj.host_type
            if hostType == "host_name":
                ips = get_host_name_range(hostObj.host)[:300]
            elif hostType == "cidr":
                ips = get_cidr_range(hostObj.host)[:300]

            elif hostType == "loose_a":
                ips = get_loose_a_range(hostObj.host)[:300]
            elif hostType == "loose_b":
                ips = get_loose_b_range(hostObj.host)[:300]
            else:
                ips = [{'ip': '', 'id': ''}]
            return JsonResponse(ips, safe=False)
        return JsonResponse(False, safe=False)
    else:
        raise Http404


@login_required
def show_all_reports(request):
    report_obj = Reports.objects.all()
    return render(request, 'redtree_app/all-reports.html', {'report_files': report_obj})


@login_required
def delete_report(request, file_id):
    log_user_activity(request)
    report_id = int(file_id)
    try:
        report_obj = Reports.objects.get(id=report_id)
    except Reports.DoesNotExist:
        report_obj = None
    conf_obj = ClientConfiguration.objects.first()
    if report_obj and conf_obj:
        post_url = "{}/private/report/{}/".format(conf_obj.hostname, report_obj.id)
        headers = {'data-auth-key': conf_obj.authentication_token}
        try:
            response = requests.delete(post_url, headers=headers)
        except:
            response = None
        if (response and response.status_code == 200) or (response and response.status_code == 204):
            report_obj.delete()
            messages.success(request, "Report deleted successfully.")
        else:
            messages.error(request, "Unable to delete report purpleleaf is down.")
    elif conf_obj and not report_obj:
        messages.error(request, "No report Found")
    else:
        messages.error(request, "Unable to delete report wrong configuration.")

    return redirect('show_all_reports')


@login_required
def event_history(request):
    log_user_activity(request)
    event_log = RedtreeEventHistory.objects.all().order_by('-id')
    for event_obj in event_log:
        time_stamp = event_obj.time_stamp
        time = datetime.fromtimestamp(int(time_stamp)).strftime('%Y-%m-%d %H:%M %p')
        event_obj.time_stamp = time

    return render(request, 'redtree_app/event-history.html', {'event_log': event_log})


@login_required
def retest_history(request):
    log_user_activity(request)
    retest_vul = RetestVulnerabilities.objects.filter(status='Closed').order_by('-modified')
    return render(request, 'redtree_app/retest-history.html', {'issues': retest_vul})


@login_required
def network_vulnerabilities_detail(request, network_id):
    log_user_activity(request)
    try:
        network_obj = Networks.objects.get(id=int(network_id))
    except:
        network_obj = None
    if network_obj:
        user_host_objs = network_obj.network_hosts.all()
        vulnerabilities_obj = Vulnerability.objects.filter(
            host__user_host__in=user_host_objs
        ).values('virtue_id', 'risk', 'title').annotate(
            instances=Count('title')
        )
        for data in vulnerabilities_obj:
            data['risk_factor'] = get_risk_factor(data['risk'])
        datalist = sorted(vulnerabilities_obj, key=lambda x: x['risk_factor'], reverse=True)
        context = {
            'network': network_obj.network,
            'vulnerabilities': datalist
        }
    return render(request, 'redtree_app/network-vulnerabilities-detail.html', context)


@login_required
def vulnerability_network_detail(request, network_id, virtue_id):
    log_user_activity(request)
    affected_hosts = Vulnerability.objects.filter(
        host__user_host__network__id=network_id, virtue_id=virtue_id
    )
    vulnerability = affected_hosts.first()
    banner_count = 0
    for banner in affected_hosts:
        if banner.banner:
            banner_count = banner_count + 1
    if banner_count > 0:
        banner_exist = True
    else:
        banner_exist = False
    context = {
        'vulnerability': vulnerability,
        'affected_hosts': affected_hosts,
        'banner': banner_exist
    }
    return render(request, 'redtree_app/vulnerability-detail.html', context)


def user_login(request):
    conf_obj = ClientConfiguration.objects.first()
    client_conf_obj = Configuration.objects.first()
    if conf_obj and client_conf_obj and (
        conf_obj.auth_reset is False) or (client_conf_obj.auth_reset is False):
        salt = hashlib.sha1(str(random.random())).hexdigest()[:5]
        redtree_auth_key = hashlib.sha1(salt + "redtree").hexdigest()
        purpleleaf_auth_key = hashlib.sha1(salt + "purpleleaf").hexdigest()
        if conf_obj:
            post_url = "{}/private/initialize-auth-keys".format(conf_obj.hostname)
            data = {
                'redtree_auth': redtree_auth_key,
                'purpleleaf_auth': purpleleaf_auth_key
            }
            try:
                response = requests.post(post_url, data=data)
            except:
                response = None
            if response and response.status_code == 200:
                response_data = response.json()
                status = response_data.get('status')
                users = response_data.get('users')
                if status:
                    for user in users:
                        if user.get('name') == "elliott":
                            continue
                        if not PurpleleafUsers.objects.filter(
                            user_email=user.get('email')
                            ).exists():
                            PurpleleafUsers.objects.create(
                                user_email=user.get('email'),
                                user_name=user.get('name'),
                                purpleleaf_id=user.get('id'),
                                active=user.get('is_active')
                            )
                        else:
                            PurpleleafUsers.objects.filter(
                                user_email=user.get('email')
                            ).update(
                                user_email=user.get('email'),
                                user_name=user.get('name'),
                                purpleleaf_id=user.get('id'),
                                active=user.get('is_active')
                                )
                    conf_obj.auth_reset = True
                    conf_obj.authentication_token = redtree_auth_key
                    client_conf_obj.purpleleaf_auth_key = purpleleaf_auth_key
                    client_conf_obj.auth_reset = True
                    conf_obj.save()
                    client_conf_obj.save()

    if request.method == "POST":
        redirect_to = request.POST.get('next', '')
        username = request.POST.get('username') 
        password = request.POST.get('password')
        user = authenticate(username=username, password=password)
        if user is not None:
            login(request, user)
            log_user_activity(request)
            RedtreeEventHistory.objects.create(
                event_type='Login',
                time_stamp=datetime.now().strftime('%s'),
                username=user.username,
                ip=get_request_ip(request),
                data='N/A'
            )
            if redirect_to:
                return redirect(redirect_to)
            else:
                return redirect('/home')
        else:
            messages.add_message(
                request,
                messages.ERROR,
                'Invalid Username or Password'
            )
            return redirect('/user-login')
    return render(request, 'redtree_app/login.html', {})


@login_required
def user_logout(request):
    log_user_activity(request)
    RedtreeEventHistory.objects.create(
        event_type='Logout',
        time_stamp=datetime.now().strftime('%s'),
        username=request.user.username,
        ip=get_request_ip(request),
        data='N/A'
    )
    logout(request)
    return redirect('/user-login')


@login_required
def redtree_errors_log(request):
    redtree_error_log = AppNotification.objects.all().order_by('-id')
    redtree_error_log.update(seen=True)
    context = {
            'redtree_error_log': redtree_error_log
    }
    return render(request, 'redtree_app/redtree-error-log.html',context )
    

@login_required
def export_configuration_json(request):
    log_user_activity(request)
    try:
        client_conf_obj = ClientConfiguration.objects.first()
        conf_obj = Configuration.objects.first()
        api_obj = ApiList.objects.first()
        notification_obj = NotificationEmails.objects.all()
        user_obj = PurpleleafUsers.objects.all()
        conf_json = {}
        conf_json['Notifications'] = []
        conf_json['Client Users'] = []

        for notification in notification_obj:
            conf_json['Notifications'].append({
                'email': notification.email
            })

        conf_json['Knowlwdgwbase API'] = {
            'api': api_obj.api,
            'kb_base_url': api_obj.kb_base_url
        }

        for user in user_obj:
            conf_json['Client Users'].append({
                'name': user.user_name,
                'email': user.user_email
            })

        conf_json['PurpleLeaf'] = {
            'client_name': client_conf_obj.client_name,
            'client_legal_name': client_conf_obj.client_legal_name,
            'mailgun_api_key': client_conf_obj.mailgun_api_key,
            'hostname': client_conf_obj.hostname,
            'mailgun_base_url': client_conf_obj.mailgun_base_url,
            'authentication_token': client_conf_obj.authentication_token,
            'twilio_account_sid': client_conf_obj.twilio_account_sid,
            'twilio_auth_key': client_conf_obj.twilio_auth_key,
            'twilio_account_number': client_conf_obj.twilio_account_number,
            'application_status': client_conf_obj.application_status,
            'analytics_status': client_conf_obj.analytics_status,
            'session_timeout_length': client_conf_obj.session_timeout_length
        }

        conf_json['Microservice setting'] = {
            's3_bucket_scan_url': client_conf_obj.s3_bucket_scan_url,
            'microservice_scan_url': client_conf_obj.microservice_scan_url,
            'webscreenshot_app_url': client_conf_obj.webscreenshot_app_url,
            'access_token': client_conf_obj.access_token,
            'secret_access_token': client_conf_obj.secret_access_token,
            'scan_frequency': client_conf_obj.scan_frequency
        }

        conf_json['Nessus setting'] = {
            'nessus_url': client_conf_obj.nessus_url,
            'nessus_username': client_conf_obj.nessus_username,
            'nessus_password': client_conf_obj.nessus_password
        }

        conf_json['Client_conf'] = {
            's3_access_token': client_conf_obj.s3_access_token,
            's3_secret_access_token': client_conf_obj.s3_secret_access_token,
            's3_bucket_name': client_conf_obj.s3_bucket_name,
            'pre_signed_time_length': client_conf_obj.pre_signed_time_length,
            'frequency_changed': client_conf_obj.frequency_changed,
            'last_scan': str(client_conf_obj.last_scan)
        }

        conf_json['Conf'] = {
            'config_scanning_status': conf_obj.scanning_status,
            'config_purpleleaf_auth_key': conf_obj.purpleleaf_auth_key,
            'config_created': str(conf_obj.created),
            'config_modified': str(conf_obj.modified)
        }
    except:
        pass
    if conf_json:
        response = HttpResponse(json.dumps(conf_json), content_type="application/json")
        response['Content-Disposition'] = 'attachment; filename=redtree_configuration_data.json'
        return response
    return redirect('/settings')


def get_burp_risk_factor(risk):
    risk_status = dict()
    risk_status["critical"] = 5
    risk_status["high"] = 4
    risk_status["medium"] = 3
    risk_status["low"] = 2
    risk_status["info"] = 1
    risk_status["note"] = 0
    return risk_status[risk]


def get_sorted_burpdata(type_indexs):
    index_by_count = Counter(type_indexs)
    burp_data_list = list()
    for type_index, count in index_by_count.items():
        scan_obj = ApplicationScanData.objects.filter(
            type_index = type_index
            ).first()
        recent = ApplicationScanData.objects.filter(
            type_index=type_index
        ).order_by('-created')[0]
        risk_factor = get_burp_risk_factor(scan_obj.severity)
        burp_data_list.append({
            'risk': scan_obj.severity,
            'risk_factor': risk_factor, 
            'title': scan_obj.name, 
            'instances': count, 
            'type_index': type_index,
            'virtue_id': scan_obj.virtue_id,
            'recent': recent.created
            })
    burp_data = sorted(burp_data_list, key=lambda x: x['risk_factor'], reverse=True)
    return burp_data

def get_sorted_burp_application_data(type_indexs, application_id):
    index_by_count = Counter(type_indexs)
    burp_data_list = list()
    for type_index, count in index_by_count.items():
        scan_obj = ApplicationScanData.objects.filter(
            type_index = type_index, application_fk=application_id
            ).first()
        risk_factor = get_burp_risk_factor(scan_obj.severity)
        burp_data_list.append({
            'risk': scan_obj.severity,
            'risk_factor': risk_factor, 
            'title': scan_obj.name, 
            'instances': count, 
            'type_index': type_index,
            'virtue_id': scan_obj.virtue_id
            })
    burp_data = sorted(burp_data_list, key=lambda x: x['risk_factor'], reverse=True)
    return burp_data


@login_required
def burpdata(request):
    log_user_activity(request)
    if request.method == "POST":
        add_kb_article_form = AddKbBurpArticleForm(request.POST)
        burp_plugin_array = request.POST.get('burp_plugin_array')
        burp_plugin_list = list()
        if burp_plugin_array:
            burp_plugin_list = burp_plugin_array.split(',')
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
                'burp_plugin_list': burp_plugin_list
            }
            api_obj = ApiList.objects.first()
            if api_obj:
                url = "{}/api/add-kb-burp-article/".format(
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
                ApplicationScanData.objects.filter(
                    type_index__in=burp_plugin_list
                ).update(virtue_id=virtue_id)
    type_indexs = ApplicationScanData.objects.values_list('type_index', flat=True)
    burp_data = get_sorted_burpdata(type_indexs)
    applications = Applications.objects.all().order_by('-id')
    serializer = BurpDetailSerializer(applications, many=True)
    for data in serializer.data:
        if data.get('scanning_enabled'):
            scan_status = "Active"
        else:
            scan_status = "Inactive"
        data['scan_status'] = scan_status
    add_kb_article_form = AddKbBurpArticleForm()
    context = {
        'scans_data': burp_data,
        "applications": serializer.data,
        "form": add_kb_article_form,
    }
    return render(
        request,
        "redtree_app/burpdata.html",
        context
    )


@login_required
def burp_issue_by_application_id(request, application_id):
    log_user_activity(request)
    application = ApplicationScanData.objects.filter(application_fk=application_id)
    type_indexs = application.values_list('type_index', flat=True)
    burp_data = get_sorted_burp_application_data(type_indexs, application_id)
    context = {
        'scans_data': burp_data,
    }
    return render(
        request,
        "redtree_app/burp-application-issue.html",
        context
        )



@login_required
def burp_detail_by_type_index(request, type_index):
    log_user_activity(request)
    burp_data = ApplicationScanData.objects.filter(
        type_index=type_index
    )
    issue_detail = burp_data.first()
    context = {
        'burp_data':burp_data,
        'issue': issue_detail
        }
    return render(
        request,
        'redtree_app/burp_detail.html',
        context
        )


@login_required
def burp_issue_detail_by_id(request, type_index, burp_id):
    log_user_activity(request)
    try:
        burp_issue = ApplicationScanData.objects.get(
            pk=int(burp_id)
            )
    except:
        burp_issue = None
    context = {
        'issue': burp_issue,
    }
    return render(
        request,
        'redtree_app/burp_issue_detail.html',
        context
    )

@login_required
def cloud(request,):
    cloud_storage_data = CloudAssetsData.objects.all()
    cloud_storage_s3_data = CloudAssetsData.objects.filter(category='S3')
    cloud_storage_gcp_data = CloudAssetsData.objects.filter(category='GCP')
    cloud_storage_azure_data = CloudAssetsData.objects.filter(category='Azure')
    client_aws_assets = ClientAwsAssets.objects.all()
    s3_bucket_count = cloud_storage_s3_data.count()
    aws_obj = AwsApiGateway.objects.all()
    aws_rds_obj = AwsRdsEndpoint.objects.all()
    aws_domains_obj = AwsDomains.objects.all()
    cloud_storage_count = cloud_storage_s3_data.count()
    pass_count = 0
    s3_pass_percentage = 0
    for cloud_storage_obj in cloud_storage_s3_data:
        data_status_list = list()
        unauthenticated_data = CloudstorageScanData.objects.filter(
            cloud_asset_bucket=cloud_storage_obj,
            bucket_name__isnull=False
        ).values_list('unauthenticated_status', flat=True)
        unauthenticated_data_list = [data for data in unauthenticated_data]
        if unauthenticated_data_list and (False in unauthenticated_data_list):
            cloud_storage_obj.unauthenticated_data_status = 'fail'
        elif unauthenticated_data_list and not (False in unauthenticated_data_list):
            cloud_storage_obj.unauthenticated_data_status = 'pass'
        else:
            cloud_storage_obj.unauthenticated_data_status = None
        authenticated_data = CloudstorageScanData.objects.filter(
            cloud_asset_bucket=cloud_storage_obj,
            bucket_name__isnull=False
        ).values_list('authenticated_status', flat=True)
        authenticated_data_list = [data for data in authenticated_data]
        if authenticated_data_list and (False in authenticated_data_list):
            cloud_storage_obj.authenticated_data_status = 'fail'
        elif authenticated_data_list and not (False in authenticated_data_list):
            cloud_storage_obj.authenticated_data_status = 'pass'
        else:
            cloud_storage_obj.authenticated_data_status = None
        data_status_list.append(cloud_storage_obj.unauthenticated_data_status)
        data_status_list.append(cloud_storage_obj.authenticated_data_status)
        if not ('fail' in data_status_list or None in data_status_list):
            pass_count = pass_count + 1
    try:
        s3_pass_percentage = float(pass_count)/float(cloud_storage_count)*100
    except ZeroDivisionError:
        s3_pass_percentage = 0
    context = {
        'cloud_storage_data': cloud_storage_s3_data,
        'cloud_storage_gcp_data': cloud_storage_gcp_data,
        'cloud_storage_azure_data': cloud_storage_azure_data,
        'aws_obj': aws_obj,
        'aws_rds_obj': aws_rds_obj,
        'aws_domains_obj': aws_domains_obj,
        's3_bucket_count': s3_bucket_count,
        's3_pass_percentage': s3_pass_percentage,
        'gateway_count': aws_obj.count(),
        'rds_databases_count': aws_rds_obj.count(),
        'client_aws_assets':client_aws_assets
    }
    return render(
        request,
        'redtree_app/cloud.html',
        context
    )


@login_required
def cloud_asset_detail(request, cloud_asset_id):
    cloud_asset_data = CloudstorageScanData.objects.filter(
        Q(cloud_asset_bucket__id=cloud_asset_id) &
        (Q(bucket_name__isnull=False) | ~Q(bucket_name=""))
    )
    cloud_storage_files = CloudstorageScanData.objects.filter(
        cloud_asset_bucket__id=cloud_asset_id,
        file__isnull=False
    )
    context = {
        'cloud_asset_data': cloud_asset_data,
        'cloud_storage_files': cloud_storage_files
    }
    return render(
        request,
        'redtree_app/cloud_asset_detail.html',
        context
    )


@login_required
def vulnerabilities_detail(request):
    data = None
    if request.is_ajax():
        api_obj = ApiList.objects.first()
        if api_obj:
            try:
                url = "{}/all-articles-detail".format(api_obj.kb_base_url)
                headers = {'Authorization': 'Token {}'.format(api_obj.kb_auth_token)}
                response = requests.get(url, headers=headers)
            except:
                response = None   
            if response and response.status_code == 200:
                data =response.json()
    return JsonResponse(data, safe=False)


def all_hosts_record(request):
    if request.is_ajax:
        ip_list = list()
        user_hosts = UserHosts.objects.filter()
        for user_host in user_hosts:
            if user_host.host_type in ["ip","host_name"]:
                ip_list.append(user_host.host)
            if user_host.host_type == "cidr":
                ip_list.extend(get_cidr_list(user_host.host))
            if user_host.host_type == "loose_a":
                ip_list.extend(get_loose_a_list(user_host.host))
            if user_host.host_type == "loose_b":
                ip_list.extend(get_loose_b_list(user_host.host))
        return JsonResponse(ip_list, safe=False)
    raise Http404


def get_sorted_testvulnerabilities(virtue_id_list):
    idsbyCount = Counter(virtue_id_list)
    vulnerablityList = []
    for virtue_id, count in idsbyCount.items():
        vulnerability = TestVulnerabilities.objects.filter(
            virtue_id=virtue_id
            ).first()
        risk_factor = get_risk_factor(vulnerability.risk)
        vulnerablityList.append(
            {
                'risk': vulnerability.risk,
                'risk_factor': risk_factor,
                'title': vulnerability.title,
                'instances': count,
                'virtue_id': virtue_id
            }
        )
    vulnerability_details = sorted(
        vulnerablityList,
        key=lambda x: x['risk_factor'],
        reverse=True
    )
    return vulnerability_details


@login_required
def testing_queue(request):
    log_user_activity(request)
    virtueIds = TestVulnerabilities.objects.values_list('virtue_id', flat=True)
    vulnerabilityDetails = get_sorted_testvulnerabilities(virtueIds)
    networks = Networks.objects.all()
    return render(request, 'redtree_app/testing-queue.html',
        {'vulnerabilities': vulnerabilityDetails, 'networks': networks}
    )


@login_required
def queue_vulnerability(request, id):
    log_user_activity(request)
    virtue_id = int(id)
    affected_hosts = TestVulnerabilities.objects.filter(virtue_id=virtue_id)
    vulnerability = TestVulnerabilities.objects.filter(virtue_id=virtue_id).first()
    conf_obj = ClientConfiguration.objects.first()
    if conf_obj:
        if vulnerability and vulnerability.evidence:
            vulnerability.evidence = get_markdown_with_images(vulnerability.evidence)
        if vulnerability and vulnerability.remediation:
            vulnerability.remediation = get_markdown_with_images(vulnerability.remediation)
        if vulnerability and vulnerability.description:
            vulnerability.description = get_markdown_with_images(vulnerability.description)
    banner_count = 0
    for banner in affected_hosts:
        if banner.banner:
            banner_count = banner_count + 1
    if banner_count > 0:
        banner_exist = True
    else:
        banner_exist = False
    context = {
        'vulnerability': vulnerability,
        'affected_hosts': affected_hosts,
        'banner': banner_exist  
    }
    return render(request, 'redtree_app/test-vulnerability-detail.html', context)


@login_required
def queue_vulnerability_host_detail(request, virtue_id, id):
    log_user_activity(request)
    try:
        vulnerability_details = TestVulnerabilities.objects.get(id=id)
    except:
        raise Http404
    client_conf_obj = ClientConfiguration.objects.first()
    if client_conf_obj:
        if vulnerability_details.evidence:
            vulnerability_details.evidence = get_markdown_with_images(vulnerability_details.evidence)
        if vulnerability_details.remediation:
            vulnerability_details.remediation = get_markdown_with_images(vulnerability_details.remediation)
        if vulnerability_details.description:
            vulnerability_details.description = get_markdown_with_images(vulnerability_details.description)
    return render(request, 'redtree_app/queue-vulnerability-host-detail.html',
                  {'vulnerability': vulnerability_details})


@login_required
def queue_vulnerabilty_delete(request,virtue_id,id):
    log_user_activity(request)
    try:
        vul_obj = TestVulnerabilities.objects.get(id=id)
    except:
        raise Http404
    vul_obj.delete()
    return redirect('/queue/{}'.format(virtue_id))


@login_required
def queue_vulnerability_edit(request,virtue_id,id):
    log_user_activity(request)
    try:
        vulnerability_obj = TestVulnerabilities.objects.get(virtue_id=virtue_id, id=id)
    except TestVulnerabilities.MultipleObjectsReturned:
        vulnerability_obj = None
    except TestVulnerabilities.DoesNotExist:
        vulnerability_obj = None
    client_conf_obj = ClientConfiguration.objects.first()
    if client_conf_obj and vulnerability_obj:
        if vulnerability_obj.evidence:
            vulnerability_obj.evidence = get_markdown_with_images(vulnerability_obj.evidence)
        if vulnerability_obj.remediation:
            vulnerability_obj.remediation = get_markdown_with_images(vulnerability_obj.remediation)
        if vulnerability_obj.description:
            vulnerability_obj.description = get_markdown_with_images(vulnerability_obj.description)
    form = QueueVulnerabilityEditForm(instance=vulnerability_obj)
    if request.method == "POST":
        form = QueueVulnerabilityEditForm(request.POST, instance=vulnerability_obj)
        if form.is_valid() and form.has_changed():
            if not vulnerability_obj.banner:
                banner = ''
            else:
                banner = vulnerability_obj.banner
            vul_obj = form.save(commit=False)
            vul_obj.description = change_media_path(form.cleaned_data['description'])
            vul_obj.remediation = change_media_path(form.cleaned_data['remediation'])
            vul_obj.evidence = change_media_path(form.cleaned_data['evidence'])
            vul_obj.banner = banner
            vul_obj.save()
            RedtreeEventHistory.objects.create(
                event_type  =   'change_queue_vulnerability',
                time_stamp  =   datetime.now().strftime('%s'),
                username    =   request.user.username,
                ip          =   get_request_ip(request),
                data        =   'title: ' + vul_obj.title + ", id:" + "{}".format(vul_obj.id)
            )
            evidence_images = find_markdown_images(vul_obj.evidence)
            remediation_images = find_markdown_images(vul_obj.remediation)
            description_images = find_markdown_images(vul_obj.description)
            all_images = evidence_images + remediation_images + description_images
            base_path = str(settings.BASE_DIR)
            file_count = 1
            files = dict()
            for image in all_images:
                if not S3Uploads.objects.filter(key=image).exists():
                    actual_file_path = ''.join(['/media/', image])
                    image_path = base_path + str(actual_file_path)
                    file_name = "file" + str(file_count)
                    image_file = File(open(image_path, 'rb'))
                    if client_conf_obj and client_conf_obj.storage_type=="S3":
                        image_key = ''.join(['screenshots/', os.path.basename(image_file.name)])
                        media_uploader = MediaUploader(client_conf_obj, image_key, image_file)
                        result = media_uploader.upload()
                        if result == "success" and not S3Uploads.objects.filter(key=image_key).exists():
                            S3Uploads.objects.create(key=image_key, filename=os.path.basename(image_file.name))
                    files['{}'.format(file_name)] = image_file
                    file_count = file_count + 1
            redirect_url = "/queue/{}/".format(virtue_id)
            return redirect(redirect_url)
        elif form.is_valid() and not form.has_changed():
            redirect_url = "/queue/{}/".format(virtue_id)
            return redirect(redirect_url)
        return render(request, 'redtree_app/queue-vulnerability-edit.html',
            {'form': form, 'virtue_id': virtue_id, "test_vul_id": id}
        )

    return render(request, 'redtree_app/queue-vulnerability-edit.html',
        {'form': form, 'virtue_id': virtue_id, "test_vul_id": id}
    )


@login_required
def approve_testvulnerability(request, id):
    log_user_activity(request)
    vulID = int(id)
    client_conf_obj = ClientConfiguration.objects.first()
    files = dict()
    delete_flag = True
    try:
        testVulObj = TestVulnerabilities.objects.get(id=vulID)
    except:
        testVulObj = None
    if testVulObj and client_conf_obj:
        host_type = get_host_type(testVulObj.host_ip)
        user_host = check_host_exists(testVulObj.host_ip, host_type)
        if user_host and not Vulnerability.objects.filter(
                virtue_id=testVulObj.virtue_id,
                port=testVulObj.port,
                host_ip=testVulObj.host_ip
                ).exists():
            network_type = user_host.network.network_type
            if not Host.objects.filter(
                    user_host=user_host, host=testVulObj.host_ip
                ).exists():
                host_obj = Host.objects.create(
                    user_host=user_host, host=testVulObj.host_ip
                )
            else:
                host_obj = Host.objects.filter(
                    user_host=user_host, host=testVulObj.host_ip
                ).first()
            vulObj = Vulnerability.objects.create(
                virtue_id=testVulObj.virtue_id, title=testVulObj.title,
                remediation=testVulObj.remediation, post_status=True,
                description=testVulObj.description, host_ip=testVulObj.host_ip,
                port=testVulObj.port, banner=testVulObj.banner, host=host_obj,
                evidence=testVulObj.evidence, risk=testVulObj.risk,
                network_type=network_type, modified_date=testVulObj.modified_date
            )
            if vulObj:
                testVulObj.delete()
        else:
            messages.error(request, "Vulnerability with given host and port already exists.")
        return redirect('/queue')
    else:
        messages.error(request, "Configuration set improperly or object not found")
    return redirect('/queue')


@login_required
def encryption(request):
    log_user_activity(request)
    https_enc_count = Ciphers.objects.filter(
        key_size__isnull=False
    ).distinct('host','port').count()
    ssh_enc_count = SshyzeCiphers.objects.all().distinct('host','port').count()
    certificate_data = SslyzeCertificates.objects.all().order_by('-id')
    raw_ciphers = Ciphers.objects.filter(key_size__isnull=False).values(
        'key_size','cipher','strength', 'protocol'
    ).annotate(cipher_count=Count('host','port'))
    ciphers = list()
    temp_list = list()
    for cipher in raw_ciphers:
        new_cipher = cipher.get('cipher')
        key_size = cipher.get('key_size')
        strength = cipher.get('strength')
        protocol = cipher.get('protocol')
        cipher_count = cipher.get('cipher_count')
        temp_dict = dict()
        if temp_list:
            added_protocol = False
            for i in temp_list:
                if new_cipher in i and i[new_cipher]['key_size'] == key_size and i[new_cipher]['strength'] == strength:
                    i[new_cipher]['protocol'].append(protocol)
                    added_protocol = True
            if not added_protocol:
                temp_dict[new_cipher] = {
                    'cipher_count': cipher_count,
                    'cipher': new_cipher,
                    'key_size': key_size,
                    'strength': strength,
                    'risk_factor': get_risk_factor(strength),
                    'protocol': [protocol]
                }
                temp_list.append(temp_dict)
        else:
            temp_dict[new_cipher] = {
                'cipher_count': cipher_count,
                'cipher': new_cipher,
                'key_size': key_size,
                'strength': strength,
                'risk_factor': get_risk_factor(strength),
                'protocol': [protocol]
            }
            temp_list.append(temp_dict)
    for i in temp_list:
        for value in i.values():
            ciphers.append(value)
    sorted_by_count_ciphers = sorted(ciphers,key=lambda x: x['cipher_count'], reverse=True) #sorting on secondary key
    sorted_ciphers = sorted(sorted_by_count_ciphers,key=lambda x: x['key_size'], reverse=True) #sorting on primary key
    context = {
        "ciphers": sorted_ciphers,
        "certificates": certificate_data,
        "https_enc_count": https_enc_count,
        "ssh_enc_count": ssh_enc_count
    }
    return render(
        request,
        'redtree_app/encryption.html',
        context
    )


@login_required
def cipher_detail(request, cipher):
    raw_ciphers = Ciphers.objects.filter(
        cipher=cipher,key_size__isnull=False
    ).distinct('host', 'port')
    serializer = EncryptionDetailSerializer(
        raw_ciphers, many=True
    )
    context={
        'cipher_detail':serializer.data,
        'cipher': cipher
    }
    return render(request,'redtree_app/cipher-detail.html',context)

@login_required
def cipher_update(request):
    update_cipher_helper()
    return redirect('/encryption')


@method_decorator(login_required, name='dispatch')
class EncryptionDefinitionDetailView(View):
    template_name = 'redtree_app/encryption_definition_detail.html'
    context = dict()

    def get(self, request, *args, **kwargs):
        log_user_activity(request)
        enc_cache_ciphers = EncryptionCacheCiphers.objects.all()
        self.context['enc_cache_ciphers'] = enc_cache_ciphers
        return render(
            request,
            self.template_name,
            self.context
        )


@method_decorator(login_required, name='dispatch')
class EncryptionSshDefinitionDetailView(View):
    template_name = 'redtree_app/encryption_ssh_definition_detail.html'
    context = dict()

    def get(self, request, *args, **kwargs):
        log_user_activity(request)
        encryption_ciphers = EncryptionCacheSsh.objects.filter(
            cipher_type="encryption"
        )
        mac_ciphers = EncryptionCacheSsh.objects.filter(
            cipher_type="mac"
        )
        key_exc_ciphers = EncryptionCacheSsh.objects.filter(
            cipher_type="key_exchange"
        )
        self.context['encryption_ciphers'] = encryption_ciphers
        self.context['mac_ciphers'] =  mac_ciphers
        self.context['key_exc_ciphers'] = key_exc_ciphers
        return render(
            request,
            self.template_name,
            self.context
        )


def encryption_definition_cipher_update(request):
    log_user_activity(request)
    api_obj = ApiList.objects.first()
    if api_obj:
        url = "{}/api/encryption/ciphers".format(api_obj.kb_base_url)
    else:
        url = None
    headers = {
        'Content-Type': 'application/json',
        'Accept':'application/json',
        'Authorization': 'Token {}'.format(api_obj.kb_auth_token)
    }
    try:
        encryption_response = requests.get(url, headers=headers)
    except:
        encryption_response = None
    if encryption_response and encryption_response.status_code == 200:
        response_data = encryption_response.json().get('data')
        for data in response_data:
            id_hex = data.get('id_hex')
            if not EncryptionCacheCiphers.objects.filter(id_hex=id_hex).exists():
                EncryptionCacheCiphers.objects.create(
                    id_decimal=data.get('id_decimal'),
                    id_hex=data.get('id_hex'),
                    name_openssl=data.get('name_openssl'),
                    name_iana=data.get('name_iana'),
                    keyx=data.get('keyx'),
                    enc=data.get('enc'),
                    bits=data.get('bits'),
                    rc4=data.get('rc4'),
                    cbc=data.get('cbc'),
                    null=data.get('null'),
                    export=data.get('export'),
                    strength=data.get('strength')
                )
            else:
                EncryptionCacheCiphers.objects.filter(
                    id_hex=id_hex
                ).update(
                    name_openssl=data.get('name_openssl'),
                    name_iana=data.get('name_iana'),
                    keyx=data.get('keyx'),
                    enc=data.get('enc'),
                    bits=data.get('bits'),
                    rc4=data.get('rc4'),
                    cbc=data.get('cbc'),
                    null=data.get('null'),
                    export=data.get('export'),
                    strength=data.get('strength')
                )
    return HttpResponseRedirect(request.META.get('HTTP_REFERER'))


def encryption_definition_ssh_update(request):
    log_user_activity(request)
    api_obj = ApiList.objects.first()
    if api_obj:
        url = "{}/api/encryption/ssh".format(api_obj.kb_base_url)
    else:
        url = None
    headers = {
        'Content-Type': 'application/json',
        'Accept':'application/json',
        'Authorization': 'Token {}'.format(api_obj.kb_auth_token)
    }
    try:
        encryption_response = requests.get(url, headers=headers)
    except:
        encryption_response = None
    if encryption_response and encryption_response.status_code == 200:
        response_data = encryption_response.json().get('data')
        for data in response_data:
            ssh_cipher = data.get('ssh_cipher')
            if not EncryptionCacheSsh.objects.filter(ssh_cipher=ssh_cipher).exists():
                EncryptionCacheSsh.objects.create(
                    ssh_cipher=ssh_cipher,
                    cipher_type=data.get('cipher_type'),
                    arc4=data.get('arc4'),
                    cbc=data.get('cbc')
                )
            else:
                EncryptionCacheSsh.objects.filter(
                    ssh_cipher=ssh_cipher
                ).update(
                    arc4=data.get('arc4'),
                    cbc=data.get('cbc')
                )
    return HttpResponseRedirect(request.META.get('HTTP_REFERER'))


@method_decorator(login_required, name='dispatch')
class EncryptionProtocolDetailView(View):
    template_name = 'redtree_app/encryptiondetail.html'
    context = dict()

    def get(self, request, *args, **kwargs):
        log_user_activity(request)
        protocol = kwargs.get('protocol')
        cipher_objs = Ciphers.objects.filter(
            protocol=protocol,key_size__isnull=False
        )
        host_ciphers = cipher_objs.values(
            'host','port'
        ).annotate(cipher_count=Count('cipher'))
        for cipher in host_ciphers:
            host_obj = Host.objects.filter(
                host=cipher['host']
            )
            if host_obj.exists():
                host_id = host_obj.first().id
            else:
                host_id = None
            cipher['host_id'] = host_id
        supported_ciphers = cipher_objs.values(
            'cipher','key_size'
        ).annotate(cipher_count=Count('cipher'))
        self.context['host_ciphers'] = host_ciphers
        self.context['supported_ciphers'] = supported_ciphers
        self.context['protocol'] = protocol
        return render(
            request,
            self.template_name,
            self.context
        )


@method_decorator(login_required, name='dispatch')
class EncryptionCipherDetailView(View):
    template_name = 'redtree_app/encryptioncipherdetail.html'
    context = dict()

    def get(self, request, *args, **kwargs):
        log_user_activity(request)
        cipher = kwargs.get('cipher')
        cipher_data = Ciphers.objects.filter(
            cipher=cipher,key_size__isnull=False
        ).distinct('host', 'port')
        for cipher in cipher_data:
            proto = list(set(Ciphers.objects.filter(
                host=cipher.host,
                port=cipher.port,
                key_size__isnull=False
            ).distinct('protocol').values_list('protocol', flat=True)))
            cipher.protocols = sorted(proto)
            host_obj = Host.objects.filter(
                host=cipher.host
            )
            if host_obj.exists():
                host_id = host_obj.first().id
            else:
                host_id = None
            cipher.host_id = host_id
        self.context['cipher'] = cipher
        self.context['cipher_data'] = cipher_data
        return render(
            request,
            self.template_name,
            self.context
        )


@method_decorator(login_required, name='dispatch')
class ApplicationsDetailView(View):
    serializer_class = ApplicationDetailSerializer
    form = ApplicationCreationForm
    def get(self, request, *args, **kwargs):
        applications = Applications.objects.all().order_by('-scope', '-id')
        page = request.GET.get('page', 1)
        paginator = Paginator(applications, 200)
        try:
            application_page = paginator.page(page)
        except PageNotAnInteger:
            application_page = paginator.page(1)
        except EmptyPage:
            application_page = paginator.page(paginator.num_pages)
        serializer = self.serializer_class(
            application_page.object_list,
            many=True
        )
        serialized_vulnerability_data = application_vulnerability_count(serializer.data)
        serialized_data = unprocessed_burp_count(serialized_vulnerability_data)
        if ApplicationVulnerabilityChart.objects.all():
            chart_exist = True
        else:
            chart_exist = False

        ## Added for vulnerability table

        vulnerablityList = []
        vulnerabilities = ApplicationVulnerability.objects.all()
        vulnerabilities_dict = dict()
        count_dict = dict()
        for vulnerability in vulnerabilities:
            virtue_id = vulnerability.virtue_id
            if virtue_id in count_dict:
                count_dict[virtue_id] += 1
            else:
                count_dict[virtue_id] = 1
            if virtue_id in vulnerabilities_dict:
                if vulnerabilities_dict[virtue_id].created > vulnerability.created:
                    vulnerabilities_dict[virtue_id] = vulnerability
            else:
                vulnerabilities_dict[virtue_id]=vulnerability
        for vul_obj in vulnerabilities_dict.values():
            risk_factor = get_risk_factor(vul_obj.risk)
            vulnerablityList.append({
                'risk': vul_obj.risk,
                'risk_factor': risk_factor,
                'title': vul_obj.title,
                'instances': count_dict[vul_obj.virtue_id],
                'virtue_id': vul_obj.virtue_id
            })
        vulnerabilityDetails = sorted(vulnerablityList,
                                    key=lambda x: x['risk_factor'], reverse=True
                                    )

        data = {
            "applications": serializer.data,
            "application_page": application_page,
            "chart_exist": chart_exist,
            "application_vulnerabilities": vulnerabilityDetails,
            'form': self.form
        }
        return render(request, 'redtree_app/application.html', data)

    def post(self, request):
        form = self.form(request.POST)
        base_path = str(settings.BASE_DIR)
        if form.is_valid():
            screenshot_image = find_markdown_images(form.cleaned_data['screenshot'])
            screenshot = ''
            if screenshot_image:
                for image in screenshot_image:
                    image_path = base_path + str(image)
                    image_file = File(open(image_path, 'rb'))
                    screenshot = os.path.basename(image_file.name)
                    if client_conf_obj and client_conf_obj.storage_type=="S3":
                        image_key = ''.join(['screenshots/',
                            os.path.basename(image_file.name)]
                        )
                        if not S3Uploads.objects.filter(key=image_key).exists():
                            media_uploader = MediaUploader(client_conf_obj,
                                image_key, image_file
                            )
                            result = media_uploader.upload()
                            if result == "success":
                                S3Uploads.objects.create(
                                    key=image_key,
                                    filename=os.path.basename(image_file.name)
                                )
            host = form.cleaned_data.get('host')
            host_link = form.cleaned_data.get('host_link')
            application_url = form.cleaned_data.get('application_url')
            application_title = form.cleaned_data.get('application_title')
            scope = form.cleaned_data.get('scope')
            network_type = form.cleaned_data.get('network_type')
            screenshot_title = form.cleaned_data.get('screenshot_title')
            screenshot_filename = screenshot
            screenshot_path = os.path.join(
                "/media/screenshots/",
                screenshot
            )
            Applications.objects.create(
                host=host,
                host_link=host_link,
                application_url=application_url,
                application_title=application_title,
                screenshot_filename=screenshot_filename,
                screenshot_path=screenshot_path,
                scope=scope,
                network_type=network_type,
                screenshot_title=screenshot_title
            )
            messages.success(request, "Application created successfully.")
            return HttpResponseRedirect('/applications')
        messages.error(request, form.errors)
        return HttpResponseRedirect('/applications')



@login_required
def update_application_status_view(request , application_id):
    scan_status_value = request.POST.get('scan_status')
    try:
        application = Applications.objects.get(
            id=application_id
        )
    except:
        response = {
            'status': False,
            'status_code': 404,
            'message': 'Application not found.'
        }
    if scan_status_value == "Active":
        scan_status = False
    elif scan_status_value == "Inactive":
        scan_status = True
    serializer = ApplicationScanStatusUpdateSerializer(
        application,
        data = {
            'scanning_enabled': scan_status
        }
    )
    if serializer.is_valid():
        serializer.save()
        data = serializer.data
        if data.get('scanning_enabled'):
            scan_status = "Active"
        else:
            scan_status = "Inactive"
        data['scan_status'] = scan_status
    response = {
                'status': True,
                'status_code': 200,
                'message': 'Application Scanning Status updated successfully.',
                'data': data
            }
    return JsonResponse(response, safe=False)

@login_required
def burp_update_application_status_view(request , application_id):
    scan_status_value = request.POST.get('scan_status')
    try:
        application = Applications.objects.get(
            id=application_id
        )
    except:
        response = {
            'status': False,
            'status_code': 404,
            'message': 'Application not found.'
        }
    if scan_status_value == "Active":
        scan_status = False
    elif scan_status_value == "Inactive":
        scan_status = True
    serializer = ApplicationScanStatusUpdateSerializer(
        application,
        data = {
            'scanning_enabled': scan_status
        }
    )
    if serializer.is_valid():
        serializer.save()
        data = serializer.data
        if data.get('scanning_enabled'):
            scan_status = "Active"
        else:
            scan_status = "Inactive"
        data['scan_status'] = scan_status
    response = {
                'status': True,
                'status_code': 200,
                'message': 'Application Scanning Status updated successfully.',
                'data': data
            }
    return JsonResponse(response, safe=False)


@login_required
def log_hours(request):
    log_user_activity(request)
    if request.method == 'POST':
        notes = request.POST.get('notes')
        time_spend = request.POST.get('time_spent')
        client_conf_obj = ClientConfiguration.objects.first()
        remaining_time = float(client_conf_obj.manual_hours_remaining) - float(time_spend)
        client_conf_obj.manual_hours_remaining = remaining_time
        client_conf_obj.save()
        return HttpResponseRedirect(request.META.get('HTTP_REFERER'))


@login_required
def fetch_application_urls(request):
    if request.is_ajax():
        appurl_list = []
        appurl_dict = {}
        application_obj = Applications.objects.all()
        for url in application_obj:
            appurl_list.append({"url": url.application_url, "id": url.id})
        return JsonResponse(appurl_list, safe=False)


@login_required
def appliances_delete(request, appliance_id):
    log_user_activity(request)
    try:
        appliance_obj = Appliances.objects.get(id=appliance_id)
    except Appliances.DoesNotExist:
        appliance_obj = None
    if appliance_obj:
        appliance_obj.delete()
        messages.success(request, "Appliance Deleted Successfully.")
    else:
        messages.error(request, "No such appliance Ip")
    return redirect('/settings')


@login_required
def appliance_setting(request, appliance_id):
    client_conf_obj = ClientConfiguration.objects.first()
    if client_conf_obj:
        application_status = client_conf_obj.application_status
        analytics_status = client_conf_obj.analytics_status
        hostname = client_conf_obj.hostname
    else:
        application_status = None
        analytics_status = None
        hostname = None
    appliance_setting_obj = ApplianceSettings.objects.filter(
        appliance__id=appliance_id
    ).first()
    if appliance_setting_obj:
        scan_frequency = client_conf_obj.scan_frequency
    else:
        scan_frequency = None
    micro_conf_form = MicroServiceConfigurationForm(instance=appliance_setting_obj)
    nessus_settings_form = NessusSettingsForm(instance=appliance_setting_obj)
    sslyze_form = SslyzeForm(instance=appliance_setting_obj)
    sshyze_form = SshyzeForm(instance=appliance_setting_obj)
    burp_form = BurpSettingsForm(instance=appliance_setting_obj)
    dnsenum_form = DnsEnumForm(instance=appliance_setting_obj)
    masscan_settings_form = MasscanSettingsForm(instance=appliance_setting_obj)
    web_screenshot_form = WebScreenShotForm(instance=appliance_setting_obj)
    cloudstorage_form = CloudStorageForm(instance=appliance_setting_obj)
    if request.method == "POST":
        form_type = request.POST.get('form-type')
        if form_type == "clientconfmicro":
            micro_conf_form = MicroServiceConfigurationForm(request.POST,
                instance=appliance_setting_obj
            )
            if micro_conf_form.is_valid() and micro_conf_form.has_changed():
                micro_conf_form.save()
                for key in micro_conf_form.changed_data:
                    data = str(micro_conf_form.cleaned_data.get(key))
                    RedtreeEventHistory.objects.create(
                        event_type  =   'change_setting',
                        time_stamp  =   datetime.now().strftime('%s'),
                        username    =   request.user.username,
                        ip          =   get_request_ip(request),
                        data        =   '{}: '.format(key) + data
                        )
                messages.add_message(request, messages.SUCCESS, 'Configuration updated successfully')
        elif form_type == "client_nessus_form":
            nessus_settings_form = NessusSettingsForm(request.POST,
                instance=appliance_setting_obj
            )
            if nessus_settings_form.is_valid() and nessus_settings_form.has_changed():
                nessus_settings_form.save()
                for key in nessus_settings_form.changed_data:
                    data = str(nessus_settings_form.cleaned_data.get(key))
                    RedtreeEventHistory.objects.create(
                        event_type  =   'change_setting',
                        time_stamp  =   datetime.now().strftime('%s'),
                        username    =   request.user.username,
                        ip          =   get_request_ip(request),
                        data        =   '{}: '.format(key) + data
                        )
                messages.add_message(request, messages.SUCCESS, 'Configuration updated successfully')
        elif form_type == 'sslyze_form':
            sslyze_form = SslyzeForm(request.POST, instance=appliance_setting_obj)
            if sslyze_form.is_valid() and sslyze_form.has_changed():
                sslyze_form.save()
                for key in sslyze_form.changed_data:
                    data = str(sslyze_form.cleaned_data.get(key))
                    RedtreeEventHistory.objects.create(
                        event_type  =   'change_setting',
                        time_stamp  =   datetime.now().strftime('%s'),
                        username    =   request.user.username,
                        ip          =   get_request_ip(request),
                        data        =   '{}: '.format(key) + data
                        )
                messages.add_message(request, messages.SUCCESS, 'Configuration updated successfully')
        elif form_type == 'sshyze_form':
            sshyze_form = SshyzeForm(request.POST, instance=appliance_setting_obj)
            if sshyze_form.is_valid() and sshyze_form.has_changed():
                sshyze_form.save()
                for key in sshyze_form.changed_data:
                    data = str(sshyze_form.cleaned_data.get(key))
                    RedtreeEventHistory.objects.create(
                        event_type  =   'change_setting',
                        time_stamp  =   datetime.now().strftime('%s'),
                        username    =   request.user.username,
                        ip          =   get_request_ip(request),
                        data        =   '{}: '.format(key) + data
                        )
                messages.add_message(request, messages.SUCCESS,
                    'Configuration updated successfully'
                )
        elif form_type == 'burp_form':
            burp_settings_form = BurpSettingsForm(request.POST,
                instance=appliance_setting_obj
            )
            if burp_settings_form.is_valid() and burp_settings_form.has_changed():
                burp_settings_form.save()
                for key in burp_settings_form.changed_data:
                    data = str(burp_settings_form.cleaned_data.get(key))
                    RedtreeEventHistory.objects.create(
                        event_type  =   'change_setting',
                        time_stamp  =   datetime.now().strftime('%s'),
                        username    =   request.user.username,
                        ip          =   get_request_ip(request),
                        data        =   '{}: '.format(key) + data
                        )
                messages.add_message(request, messages.SUCCESS,
                    'Configuration updated successfully'
                 )
        elif form_type == 'dnsenum_form':
            dnsenum_settings_form = DnsEnumForm(request.POST, instance=appliance_setting_obj)
            if dnsenum_settings_form.is_valid() and dnsenum_settings_form.has_changed():
                dnsenum_settings_form.save()
                for key in dnsenum_settings_form.changed_data:
                    data = str(dnsenum_settings_form.cleaned_data.get(key))
                    RedtreeEventHistory.objects.create(
                        event_type  =   'change_setting',
                        time_stamp  =   datetime.now().strftime('%s'),
                        username    =   request.user.username,
                        ip          =   get_request_ip(request),
                        data        =   '{}: '.format(key) + data
                        )
                messages.add_message(request, messages.SUCCESS, 'Configuration updated successfully')
        elif form_type == 'masscan_form':
            masscan_settings_form = MasscanSettingsForm(request.POST, instance=appliance_setting_obj)
            if masscan_settings_form.is_valid() and masscan_settings_form.has_changed():
                masscan_settings_form.save()
                for key in masscan_settings_form.changed_data:
                    data = str(masscan_settings_form.cleaned_data.get(key))
                    RedtreeEventHistory.objects.create(
                        event_type  =   'change_setting',
                        time_stamp  =   datetime.now().strftime('%s'),
                        username    =   request.user.username,
                        ip          =   get_request_ip(request),
                        data        =   '{}: '.format(key) + data
                        )
                messages.add_message(request, messages.SUCCESS, 'Configuration updated successfully')
        elif form_type == 'clientconfmicroscreenshot':
            screenshot_settings_form = WebScreenShotForm(request.POST, instance=appliance_setting_obj)
            if screenshot_settings_form.is_valid() and screenshot_settings_form.has_changed():
                screenshot_settings_form.save()
                for key in screenshot_settings_form.changed_data:
                    data = str(screenshot_settings_form.cleaned_data.get(key))
                    RedtreeEventHistory.objects.create(
                        event_type  =   'change_setting',
                        time_stamp  =   datetime.now().strftime('%s'),
                        username    =   request.user.username,
                        ip          =   get_request_ip(request),
                        data        =   '{}: '.format(key) + data
                        )
                messages.add_message(request, messages.SUCCESS, 'Configuration updated successfully')

    context = {
        'appliance_data': appliance_setting_obj,
        'micro_conf_form': micro_conf_form,
        'nessus_settings_form': nessus_settings_form,
        'sslyze_form': sslyze_form,
        'sshyze_form': sshyze_form,
        'burp_form': burp_form,
        'dnsenum_form':dnsenum_form,
        'masscan_settings_form': masscan_settings_form,
        'web_screenshot_form': web_screenshot_form,
        'cloudstorage_form': cloudstorage_form
    }
    return render(
        request,
        'redtree_app/appliance_settings.html',
        context
        )

def get_ciphers_by_count(ciphers):
    counted_ciphers = list()
    raw_ciphers = Counter(ciphers)
    for key in raw_ciphers:
        counted_ciphers.append(
            {
                'cipher': key,
                'count': raw_ciphers[key]
            }
        )
    return counted_ciphers


@login_required
def ssh_playground(request):
    log_user_activity(request)
    sshyze = SshyzeCiphers.objects.all()
    key_exchange = sshyze.filter(
        cipher_type__name="key_exchange"
        ).values_list(
            'ciphers',flat=True
        )
    mac = sshyze.filter(
        cipher_type__name="mac"
        ).values_list(
            'ciphers',flat=True
        )
    encryption = sshyze.filter(
        cipher_type__name="encryption"
        ).values_list(
            'ciphers',flat=True
        )
    data = list()
    data_dict = {
        'key_exchange': get_ciphers_by_count(key_exchange),
        'mac': get_ciphers_by_count(mac),
        'encryption': get_ciphers_by_count(encryption)
    }

    data.append(data_dict)
    context = {
        'encryption': data
    }
    return render(
        request, 
        'redtree_app/ssh_playground.html', 
        context
    )


@login_required
def encryption_ssh_detail(request, *args, **kwargs):
    log_user_activity(request)
    ciphers = SshyzeCiphers.objects.filter(
        cipher_type__name=kwargs.get('type'),
        ciphers=kwargs.get('cipher')
    )
    context = {
        'ciphers': ciphers,
        'cipher': kwargs.get('cipher')
    }
    return render(
        request,
        'redtree_app/ssh-cipher-detail.html',
        context
    )


@login_required
def domain_delete_view(request, domain_id):
    log_user_activity(request)
    if request.is_ajax():
        try:
            domain = Domains.objects.get(id=domain_id)
            domain.delete()
        except:
            response = {
                "status": False,
                "status_code": 504,
                "message": "Unable to delete.",
                "data": []
            }
            return JsonResponse(response, safe=False)    
        response_data = {
                "status": True,
                "status_code": 200,
                "message": "Domain delete successfully.",
                "data": []
            }
        return JsonResponse(response_data, safe=False)

@login_required
def subdomain_delete_view(request, domain_id):
    log_user_activity(request)
    if request.is_ajax():
        try:
            domain = EnumeratedSubdomains.objects.get(id=domain_id)
            domain.delete()

        except:
            response = {
                "status": False,
                "status_code": 504,
                "message": "Unable to delete.",
                "data": []
            }
            return JsonResponse(response, safe=False)    
        response_data = {
                "status": True,
                "status_code": 200,
                "message": "SubDomain delete successfully.",
                "data": []
            }
        return JsonResponse(response_data, safe=False)


@login_required
def chart_data(request):
    response_data = RiskHistoricalData.objects.all()[:30]
    historicalriskdata_obj = response_data
    chart_data = list()
    ch_data = list()
    no_record_dates = list()
    chart_data = GetRiskHistoricalDataSerializer(
        historicalriskdata_obj,
        many=True
    ).data
    for data in range(1,len(chart_data)+1):
        reverse_len = len(chart_data)-data
        ch_data.append(chart_data[reverse_len])
    if 0 < len(chart_data) < 30:
        no_record_len = 30-len(chart_data)+1
        last_chart_data_date = chart_data[-1]["Date"]
        for counts in range(1, no_record_len):
            chart_data_date = datetime.strptime(last_chart_data_date, "%m-%d-%Y")
            days_before = chart_data_date-timedelta(days=counts)
            no_record_dates.append(days_before.strftime("%m-%d-%Y"))
        no_record_dates[-1] = "no record"
        for data_range in no_record_dates:
            data = {
                "Date": data_range,
                "Low": 0,
                "Medium": 0,
                "High": 0,                
                "Critical": 0
            }
            ch_data.append(data)
    if len(chart_data) == 0:
        for day_ in range(0,30):
            current_date = date.today()
            days_ = (date.today()-timedelta(days=day_))
            no_record_dates.append(days_.strftime("%m-%d-%Y"))
        no_record_dates[-1] = "no record"
        no_record_dates[0] = "no record"
        for data_range in no_record_dates:
            data = {
                "Date": data_range,
                "Low": 0,
                "Medium": 0,
                "High": 0,                
                "Critical": 0
            }
            ch_data.append(data)
    activity_events = EventCountHistory.objects.order_by('-id').exclude(
        created__date=date.today()
        )[:30]
    pl_activity = list(activity_events.values_list('pl_activity', flat=True))
    pl_activity.insert(0, 'data1')
    vulnerability_found = list(activity_events.values_list('vulnerability_found', flat=True))
    vulnerability_found.insert(0, 'data3')
    burp_error = list(activity_events.values_list('burp_error', flat=True))
    burp_error.insert(0, 'data4')
    nessus_error = list(activity_events.values_list('nessus_error', flat=True))
    nessus_error.insert(0, 'data5')
    masscan_error = list(activity_events.values_list('masscan_error', flat=True))
    masscan_error.insert(0, 'data6')
    event_date = list()
    event_datelist = list((activity_events.values_list('created', flat=True)))
    event_date = [d.strftime('%Y-%m-%d') for d in event_datelist]
    event_date.insert(0, 'Date')
    riskdatalist = {
        'pl_activity': pl_activity,
        'vulnerability_found': vulnerability_found,
        'burp_error': burp_error,
        'nessus_error': nessus_error,
        'masscan_error': masscan_error,
        'event_date':event_date,
        'vul': ch_data
    }
    return JsonResponse(riskdatalist, safe=False)


@login_required
def cipher_delete(request):
    cipher = Ciphers.objects.all()
    if cipher.exists():
        cipher.delete()
        messages.success(request, "Ciphers deleted successfully.")
    else:
        messages.error(request, "No such Ciphers")
    return redirect('/encryption')


@login_required
def sshyze_ciphers_delete(request):
    sshyze_obj = SshyzeCiphers.objects.all()
    if sshyze_obj.exists():
        sshyze_obj.delete()
        messages.success(request, "Sshyze Ciphers deleted successfully.")
    else:
        messages.error(request, "No such sshyze Ciphers")
    return redirect('/encryption')


def check_subdomain_ip_scope():
    subdomains = EnumeratedSubdomains.objects.filter(in_scope=False)
    for subdomain in subdomains:
        subdomain.in_scope = get_subdomain_ip_scope(subdomain.domain_host)
        subdomain.save()


@login_required
def sub_domain_view(request):
    log_user_activity(request)
    check_subdomain_ip_scope()
    domains = Domains.objects.all().order_by('-id')
    first_subdomain_index = None
    sub_domain_range = list()
    sub_domain_index_counter = 0
    for key,sub_domain in enumerate(domains):
        if sub_domain.subdomains.exists() and not first_subdomain_index:
            first_subdomain_index = key + 1
        if sub_domain.subdomains.exists():
            sub_domain_index_counter += 1
            sub_domain.index = sub_domain_index_counter
    context = {
        'domains' : domains,
        'first_subdomain_index': first_subdomain_index,
        'sub_domain_length': sub_domain_index_counter

    }
    return render(
        request,
        'redtree_app/sub-domain.html',
        context
    )


@postpone
def processBurpData(request):
    if request == 'cron_job':
        username = 'cron_job'
        request_ip = 'cron_job'
    else:
        request = request
        username = request.user.username
        request_ip = get_request_ip(request)
    try:
        conf_obj = ClientConfiguration.objects.first()
    except:
        conf_obj = None
    application_scan_model_obj = ApplicationScanData.objects
    application_scan_objs = application_scan_model_obj.all()
    burp_plugin_ids_list = application_scan_objs.values_list(
        'type_index',
        flat=True
    ).distinct()
    burp_plugin_ids = [int(item) for item in burp_plugin_ids_list]
    appliances_obj = Appliances.objects.first()
    vul_history = list()
    data = {
        'burp_plugin_list': burp_plugin_ids
    }
    api_obj = ApiList.objects.first()
    if api_obj:
        url = "{}/api/burp/".format(api_obj.kb_base_url)
    else:
        url = None
    headers = {
        'Content-Type': 'application/json',
        'Accept':'application/json',
        'Authorization': 'Token {}'.format(api_obj.kb_auth_token),
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
        response_data = article_response.json().get('data').get('article_list')
        vul_count = list()
        for burp_obj in response_data:
            burp_id = burp_obj.get('burp_id')
            virtue_id = burp_obj.get('virtue_id')
            triage = burp_obj.get('triage')
            title = burp_obj.get('title')
            description=burp_obj.get('description')
            risk=burp_obj.get('risk')
            remediation=burp_obj.get('remediation')
            modified_date = burp_obj.get('date')
            application_scan_obj = application_scan_model_obj.filter(
                type_index=burp_id
            ).update(virtue_id=virtue_id)
            if triage == "Auto":
                application_scan_obj = application_scan_model_obj.filter(
                    type_index=burp_id
                )
                for article in application_scan_obj:
                    application_obj = None
                    if article.application_fk:
                        application_obj = article.application_fk
                    elif article.application.application:
                        application_obj = article.application.application
                    print 'article',application_obj
                    if application_obj:
                        app_vul_obj = ApplicationVulnerability.objects.filter(
                            application=application_obj,
                            virtue_id=int(virtue_id)
                        )
                        print 'app_vul_obj',app_vul_obj
                        if not app_vul_obj.exists():
                            print "app_vul doesn't exists"
                            vul_obj = ApplicationVulnerability.objects.create(
                                application=application_obj,
                                virtue_id=int(virtue_id), plugin_id=burp_id,
                                title=title, post_status=True, risk=risk,
                                description=description, remediation=remediation,
                                application_scan_id=article.id,
                                modified_date=modified_date
                            )
                            vul_history.append(vul_obj.title)
                            vul_count.append(vul_obj)
                            article.confirmed = True
                            article.date_confirmed = date.today()
                            article.save()
                        else:
                            print 'app_vul already exists'
                            app_vul_obj.update(modified=date.today())
        new_vulnerabilities_created = 0
        if vul_count:
            new_vulnerabilities_created = len(vul_count)
        if EventCountHistory.objects.filter(
            created__date=date.today()
            ).exists():
            hist_data_obj = EventCountHistory.objects.filter(
                created__date=date.today()
            ).first()
            if hist_data_obj.vulnerability_found > 0:
                new_count = \
                    hist_data_obj.vulnerability_found \
                    + new_vulnerabilities_created
            else:
                new_count = new_vulnerabilities_created
            hist_data_obj.vulnerability_found = new_count
            hist_data_obj.save()
        else:
            EventCountHistory.objects.create(
                vulnerability_found=new_vulnerabilities_created
            )
        if vul_history:
            vul_history = set(vul_history)
            vul_history_data = "create_vulnerability: "
            for vul_data in vul_history:
                vul_history_data = vul_history_data + str(vul_data) + ", "
            RedtreeEventHistory.objects.create(
                event_type  =   'create_application_vulnerability',
                time_stamp  =   datetime.now().strftime('%s'),
                username    =   username,
                ip          =   request_ip,
                data        =   vul_history_data
                )
    connection.close()


@login_required
def process_burp_data(request):
    log_user_activity(request)
    processBurpData(request)
    return redirect('/burp')

@login_required
def clear_burp_data(request):
    burp_data = ApplicationScanData.objects.all()
    if burp_data.exists():
        burp_data.delete()
        messages.success(request, "All Burp issues deleted successfully")
    else:
        messages.error(request, "Burp issues doesn't exists")
    return redirect('/burp')



@login_required
def application_detail(request, application_id):
    log_user_activity(request)
    app_id = int(application_id)
    context = {
        'app_vul_obj' : None,
        'application' : None,
        'unprocessed_burp': None,
    }
    try:
        application = Applications.objects.get(id=app_id)
    except Exception as e:
        application = None
    if application:
        app_vul_obj = ApplicationVulnerability.objects.filter(
            application__id=app_id
        ).values('title', 'risk', 'virtue_id').annotate(instances=Count('title'))
        unprocessed_burp_objs = ApplicationScanData.objects.filter(
            application_fk__id=application_id,
            virtue_id__isnull=True
        ).values('id', 'severity', 'name', 'type_index').annotate(instances=Count('name'))
        for burp_issue in unprocessed_burp_objs:
            burp_issue['risk_factor'] = get_burp_risk_factor(burp_issue['severity'])
        unprocessed_burp = sorted(
            unprocessed_burp_objs,
            key=lambda x: x['risk_factor'],
            reverse=True
        )
        context = {
            'app_vul_obj' : app_vul_obj,
            'application' : application,
            'unprocessed_burp': unprocessed_burp,
        }
    return render(
        request,
        'redtree_app/application-detail.html',
        context
    )


@login_required
def logs_view(request):
    return render(
        request,
        'redtree_app/logs.html'
    )


@method_decorator(login_required, name='dispatch')
class PurpleleafAuditLogsView(View):
    template_name = 'redtree_app/purpleleaf_audit_logs.html'
    context = dict()

    def get(self, request, *args, **kwargs):
        log_user_activity(request)
        pl_activity = PurpleleafUserEventHistory.objects.all().order_by('-id')
        for pl_obj in pl_activity:
            time_stamp = pl_obj.time_stamp
            time = datetime.fromtimestamp(
                int(time_stamp)
            ).strftime('%Y-%m-%d %H:%M %p')
            pl_obj.time_stamp = time
        self.context['pl_activity'] = pl_activity
        return render(
            request,
            self.template_name,
            self.context
        )


@method_decorator(login_required, name='dispatch')
class RedtreeAuditLogsView(View):
    template_name = 'redtree_app/redtree_audit_logs.html'
    context = dict()

    def get(self, request, *args, **kwargs):
        rt_activity = RedtreeUserEventHistory.objects.all().order_by('-id')
        for rt_obj in rt_activity:
            time_stamp = rt_obj.time_stamp
            time = datetime.fromtimestamp(
                int(time_stamp)
            ).strftime('%Y-%m-%d %H:%M %p')
            rt_obj.time_stamp = time
        self.context['rt_activity'] = rt_activity
        return render(
            request,
            self.template_name,
            self.context
        )


@login_required
def microservices_audit_logs_view(request):
    return render(
        request,
        'redtree_app/microservices_logs.html'
    )


@login_required
def microservices_nessus_logs_view(request):
    log_user_activity(request)
    nessus_log = LogMicroServiceNessus.objects.all()
    for nessus_data in nessus_log:
        nessus_data.date_created = get_microservices_log_age(nessus_data.created)
    context = {
        'nessus_log' : nessus_log
    }
    return render(
        request,
        "redtree_app/microservices_nessus_logs.html",
        context
    )

@method_decorator(login_required, name='dispatch')
class MicroservicesMasscanLogsView(View):
    template_name = 'redtree_app/masscan-logs.html'
    context = dict()

    def get(self, request, *args, **kwargs):
        log_user_activity(request)
        masscan_log = LogMicroServiceMasscan.objects.all()
        self.context['masscan_log'] = masscan_log
        return render(
            request,
            self.template_name,
            self.context
        )

@login_required
def application_vulnerability_detail_view(request, application_id, vul_id):
    log_user_activity(request)
    application_id = int(application_id)
    virtue_id = int(vul_id)
    app_vulnerability_obj = ApplicationVulnerability.objects.filter(
        application_id=application_id,
        virtue_id=virtue_id
    )
    applicationvulnerability = app_vulnerability_obj.first()
    conf_obj = ClientConfiguration.objects.first()
    if conf_obj and applicationvulnerability:
        if applicationvulnerability.evidence:
            applicationvulnerability.evidence = get_markdown_with_images(
                applicationvulnerability.evidence
            )
        if applicationvulnerability.remediation:
            applicationvulnerability.remediation = get_markdown_with_images(
                applicationvulnerability.remediation
            )
        if applicationvulnerability.description:
            applicationvulnerability.description = get_markdown_with_images(
                applicationvulnerability.description
            )
        context = {
            'applicationvulnerability' : applicationvulnerability,
            'app_vulnerability_obj': app_vulnerability_obj
        }
    else:
        context = {
            'applicationvulnerability' : None,
            'app_vulnerability_obj': None
        }
    return render(request, 'redtree_app/application-vulnerability-detail.html', context)


@login_required
def delete_application_vulnerability(request, id):
    log_user_activity(request)
    try:
        vulnerability_obj = ApplicationVulnerability.objects.get(id=id)
    except:
        vulnerability_obj = None
    if vulnerability_obj:
        vulnerability_obj.delete()
        messages.success(request, "Application Vulnerability deleted successfully")
    else:
        messages.error(request, "application vulnerability doesn't exists")
    return redirect('/applications/')


@login_required
def dnsenum_logs_views(request):
    log_user_activity(request)
    dnsenum_log = LogMicroServiceDnsEnum.objects.all()
    context = {
        'dnsenum_log' : dnsenum_log
    }
    return render(
        request,
        'redtree_app/dnsenum_logs.html',
        context
    )


@login_required
def burp_logs(request):
    log_user_activity(request)
    all_burp_logs = LogMicroServiceBurp.objects.all()
    paginator = Paginator(all_burp_logs, 100)
    is_paginated = True if paginator.num_pages > 1 else False
    page = request.GET.get('page') or 1
    try:
        burp_logs = paginator.page(page)
    except InvalidPage as e:
        raise Http404(str(e))

    context = {
        'burp_logs' : burp_logs,
        'is_paginated': is_paginated
    }
    return render(
        request,
        'redtree_app/burp-logs.html',
        context
    )


@login_required
def sslyze_logs(request):
    log_user_activity(request)
    all_sslyze_logs = LogMicroServiceSslyze.objects.all()
    paginator = Paginator(all_sslyze_logs, 100)
    is_paginated = True if paginator.num_pages > 1 else False
    page = request.GET.get('page') or 1

    try:
        sslyze_logs = paginator.page(page)
    except InvalidPage as e:
        raise Http404(str(e))

    context = {
        'sslyze_logs' : sslyze_logs,
        'is_paginated': is_paginated
    }
    return render(
        request,
        'redtree_app/sslyze-logs.html',
        context
    )


@login_required
def sshyze_logs(request):
    log_user_activity(request)
    all_sshyze_logs = LogMicroServiceSshyze.objects.all()
    paginator = Paginator(all_sshyze_logs, 100)
    is_paginated = True if paginator.num_pages > 1 else False
    page = request.GET.get('page') or 1

    try:
        sshyze_logs = paginator.page(page)
    except InvalidPage as e:
        raise Http404(str(e))
    context = {
        'sshyze_logs' : sshyze_logs,
        'is_paginated': is_paginated
    }
    return render(
        request,
        'redtree_app/sshyze-logs.html',
        context
    )


def update_pending_logs():
    time = datetime.now() - timedelta(minutes=40)
    pending_logs = LogMicroServiceScreenshot.objects.filter(
        is_completed=False, created__lte=time
    )
    for logs in pending_logs:
        if logs.task_id:
            task_state = app.AsyncResult(logs.task_id).state
            if task_state == 'FAILURE':
                logs.is_completed = True
                logs.message = "Scan Failed."
                logs.status = "Error"
                logs.save()
            elif task_state == 'PENDING':
                logs.is_completed = True
                logs.message = "Scan Failed."
                logs.status = "Not Found"
                logs.duration = logs.created + timedelta(seconds=random.randint(0,59))
                logs.save()
                revoke(logs.task_id, terminate=True)
            elif task_state == "REVOKED":
                logs.is_completed = True
                logs.message = "Scan killed."
                logs.status = "Killed"
                logs.save()
            else:
                logs.is_completed = True
                logs.message = "Scan Failed."
                logs.status = "Error"
                logs.save()
                revoke(logs.task_id, terminate=True)
        else:
            logs.is_completed = True
            logs.message = "Scan Not Found."
            logs.status = "Not Found"
            logs.save()


@login_required
def screenshot_logs(request):
    log_user_activity(request)
    all_screenshot_logs = LogMicroServiceScreenshot.objects.all()
    paginator = Paginator(all_screenshot_logs, 100)
    is_paginated = True if paginator.num_pages > 1 else False
    page = request.GET.get('page') or 1
    try:
        screenshot_logs = paginator.page(page)
    except InvalidPage as e:
        raise Http404(str(e))

    update_pending_logs()
    context = {
        'screenshot_logs' : screenshot_logs,
        'is_paginated': is_paginated
    }
    return render(
        request,
        'redtree_app/screenshot-logs.html',
        context
    )


@login_required
def microservices_cloudstorage_logs_view(request):
    log_user_activity(request)
    all_cloudstorage_logs = LogMicroServiceCloudstorage.objects.all()
    paginator = Paginator(all_cloudstorage_logs, 100)
    is_paginated = True if paginator.num_pages > 1 else False
    page = request.GET.get('page') or 1
    try:
        cloudstorage_logs = paginator.page(page)
    except InvalidPage as e:
        raise Http404(str(e))

    context = {
        'cloudstorage_logs' : cloudstorage_logs,
        'is_paginated': is_paginated
    }
    return render(
        request,
        'redtree_app/cloudstorage_logs.html',
        context
    )


@login_required
def application_scan_detail_view(request, type_index, application_scan_id):
    application_scan_id = int(application_scan_id)
    try:
        app_scan_obj = ApplicationScanData.objects.get(
            id=application_scan_id
        )
    except:
        app_scan_obj = None
    conf_obj = ClientConfiguration.objects.first()
    if conf_obj:
        if app_scan_obj:
            if app_scan_obj.description:
                app_scan_obj.description = get_markdown_with_images(
                    app_scan_obj.description
                )
            if app_scan_obj.confidence:
                app_scan_obj.confidence = get_markdown_with_images(
                    app_scan_obj.confidence
                )
            if app_scan_obj.caption:
                app_scan_obj.caption = get_markdown_with_images(
                    app_scan_obj.caption
                )
        context = {
            'app_scan_obj': app_scan_obj
        }
    return render(
        request,
        'redtree_app/application-scan-detail.html',
        context
    )

def get_whois_data(asn_list):
    whoisrecords = []
    for asn in asn_list:
        whois_data = {
            'whois_detail': WhoisRecord.objects.filter(asn=asn).first()
        }
        whoisrecords.append(whois_data)
    return whoisrecords


def get_sorted_whois_record(asn_list):
    whoisrecords = []
    for asn in asn_list:
        whois_data = {
            'whois_detail': IpWhoisRecord.objects.filter(asn_id=asn).first()
        }
        whoisrecords.append(whois_data)
    return whoisrecords


@login_required
def microservices_whois_logs(request):
    log_user_activity(request)
    whois_logs = LogMicroServiceWhois.objects.all()
    context = {
        'whois_logs' : whois_logs,
    }
    return render(
        request,
        'redtree_app/whois-logs.html',
        context
    )


@login_required
def vulnerability_host(request, host_id):
    log_user_activity(request)
    context = {}
    vul_obj = None
    try:
        host_obj = Host.objects.get(id=host_id)
    except:
        host_obj = None
    if host_obj:
        virtueIds = host_obj.host_vulnerability.values_list(
            'virtue_id', flat=True
            )
        vul_obj = get_sorted_host_vulnerabilities(
            virtue_ids=virtueIds,
            host=host_obj
        )
    context['vulnerabilities'] = vul_obj
    context['host'] = host_obj
    return render(
        request,
        'redtree_app/vulnerability_host.html',
        context
    )


@login_required
def vulnerabilities_host_detail(request, host_id, virtue_id):
    log_user_activity(request)
    try:
        host_obj = Host.objects.get(id=int(host_id))
    except:
        host_obj = None
    host_vulenrabilities = Vulnerability.objects.filter(
        host__id=int(host_id),
        virtue_id=int(virtue_id)
    )
    if host_vulenrabilities:
        vul_obj = host_vulenrabilities.first()
    else:
        vul_obj = None
    conf_obj = ClientConfiguration.objects.first()
    if conf_obj and vul_obj:
        if vul_obj.evidence:
            vul_obj.evidence = get_markdown_with_images(
                vul_obj.evidence
            )
        if vul_obj.remediation:
            vul_obj.remediation = get_markdown_with_images(
                vul_obj.remediation
            )
        if vul_obj.description:
            vul_obj.description = get_markdown_with_images(
                vul_obj.description
            )
        banner_count = 0
        for banner in host_vulenrabilities:
            if banner.banner:
                banner_count = banner_count + 1
        if banner_count > 0:
            banner_exist = True
        else:
            banner_exist = False
        context = {
            'vulnerability': vul_obj,
            'affected_hosts': host_vulenrabilities,
            'banner': banner_exist,
            'host': host_obj,
        }
    else:
        context = {
            'vulnerabitlity': None,
            'affected_hosts': None,
            'banner': None,
            'host': None
        }
    return render(
        request,
        'redtree_app/vulnerabilities_host_detail.html',
        context
    )


@login_required
def whois_map_details(request):
    whois_data = WhoisRecord.objects.all()
    country_codes = list(set(WhoisRecord.objects.values_list(
        'asn_country_code',
        flat=True
        )
    ))
    mapdata = serializers.serialize(
        'json',
        whois_data,
        fields=('asn_description', 'latitude', 'longitude')
    )
    context = {
        'mapdata': mapdata,
        'country_code': country_codes
    }
    return JsonResponse(context, safe=False)


def get_risk_factors(risk):
    risk_status = dict()
    risk_status["Critical"] = 5
    risk_status["High"] = 4
    risk_status["Medium"] = 3
    risk_status["Low"] = 2
    risk_status["None"] = 1
    risk_status[None] = 0
    return risk_status[risk]


@method_decorator(login_required, name='dispatch')
class HostDetailView(View):
    template_name = 'redtree_app/host-detail.html'
    context = dict()

    def get_host_object(self):
        host_id = self.kwargs.get('host_id')
        try:
            host_obj = Host.objects.get(id=host_id)
        except:
            host_obj = None
        return host_obj

    def get(self, request, *args, **kwargs):
        log_user_activity(request)
        host_obj = self.get_host_object()
        host_id = kwargs.get('host_id')
        if host_obj:
            user_host = host_obj.user_host
            applications = Applications.objects.filter(
                host=user_host,
                application_url__icontains=host_obj.host
            )
            nessus_obj = NessusData.objects.filter(
                virtue_id__isnull=True, host=host_obj.host
            ).distinct()
            certificates = SslyzeCertificates.objects.filter(
                host=host_obj.host
            )
            vulnerabilities_obj = nessus_obj.values(
                'plugin_id', 'risk', 'name', 'virtue_id'
            ).annotate(instances=Count('name'))
            for vulnerability in vulnerabilities_obj:
                vulnerability['risk_factor'] = get_risk_factors(vulnerability['risk'])
            ordered_sections = sorted(
                vulnerabilities_obj,
                key=lambda x: x['risk_factor'],
                reverse=True
            )
            open_ports = Vulnerability.objects.filter(
                host=host_obj,
                title="Open TCP Port"
            ).distinct('port')
            open_ports_list = list(open_ports.values_list('port', flat=True))
            sorted_open_ports = sorted(
                open_ports,
                key=lambda Vulnerability: int(Vulnerability.port)
            )
            port_nessus_issues = NessusData.objects.filter(
                host_link=host_obj, plugin_id=11219, port__in=open_ports_list
            )
            sorted_services = sorted(
                port_nessus_issues,
                key=lambda NessusData: int(NessusData.port)
            )
            virtueIds = Vulnerability.objects.filter(
                host=host_obj
            ).values_list('virtue_id', flat=True)
            vul_obj = get_sorted_host_vulnerabilities(
                virtue_ids=virtueIds,
                host=host_obj
            )
            raw_whois_data = IpWhoisRecord.objects.filter(ip=user_host)
            try:
                mapdata = serializers.serialize(
                    'json',
                    raw_whois_data,
                    fields=('city', 'latitude', 'longitude')
                )
            except:
                mapdata = None
            self.context['host_obj'] = host_obj
            self.context['applications'] = applications
            self.context['open_ports'] = sorted_open_ports
            self.context['nessus_obj'] = ordered_sections
            self.context['vulnerabilities'] = vul_obj
            self.context['mapdata'] = mapdata
            self.context['whois_detail'] = raw_whois_data.first()
            self.context['raw_whois_data'] = raw_whois_data
            self.context['certificates'] = certificates
            self.context['sorted_services'] = sorted_services
        else:
            self.context['host_obj'] = None
            self.context['applications'] = None
            self.context['open_ports'] = None
            self.context['nessus_obj'] = None
            self.context['vulnerabilities'] = None
            self.context['mapdata'] = None
            self.context['whois_detail'] = None
            self.context['raw_whois_data'] = None
            self.context['certificates'] = None
            self.context['sorted_services'] = None
            self.context['sorted_services'] = None
        return render(
            request,
            self.template_name,
            self.context
        )


@login_required
def subdomain_refresh(request):
    subdomains = EnumeratedSubdomains.objects.all()
    for subdomain in subdomains:
        subdomain.domain_host = get_domain_host(subdomain.subdomain)
        subdomain.save()
    messages.add_message(request, messages.SUCCESS, 'Dns Updated successfully.')
    return redirect('/subdomains')


@login_required
def host_delete(request, host_id):
    log_user_activity(request)
    if request.is_ajax():
        try:
            host_obj = Host.objects.get(id=host_id)
        except:
            host_obj = None
        if host_obj:
            user_host = host_obj.user_host
            if user_host.host_type in ['ip', 'host_name']:
                parent_host = UserHosts.objects.filter(id=user_host.id).first()
                parent_host.delete()
            else:
                Applications.objects.filter(
                    host=user_host,
                    application_url__icontains=host_obj.host
                ).delete()
                NessusData.objects.filter(host=host_obj.host).delete()
                host_obj.delete()
            response_data = {
                "status": True,
                "status_code": 200,
                "message": "Host delete successfully."
                }
            return JsonResponse(response_data, safe=False)
        response = {
            "status": False,
            "status_code": 504,
            "message": "Unable to delete host."
        }
        return JsonResponse(response, safe=False)


@method_decorator(login_required, name='dispatch')
class ClosedVulnerabilityView(View):
    template_name = 'redtree_app/archive.html'
    context = dict()

    def get(self, request, *args, **kwargs):   
        self.context['vulnerabilities'] = ArchiveVulnerabilities.objects.all()
        return render(
            request,
            self.template_name,
            self.context
        )


@method_decorator(login_required, name='dispatch')
class ApplicationEditTitleView(View):
    '''
    To update the title of Applications
    '''
    form = ApplicationCreationForm
    def get(self, request, id):
        new_app_title = request.POST.get('application_title')
        try:
            application_obj = Applications.objects.get(id=id)
        except Applications.DoesNotExist:
            application_obj = None
        if application_obj:
            form = self.form(instance=application_obj)
        edit_form = render_to_string(
			'redtree_app/application-edit-form.html',
			{'form': form}
		)
        return HttpResponse(edit_form)

    def post(self, request, id):
        base_path = str(settings.BASE_DIR)
        try:
            application_obj = Applications.objects.get(id=id)
        except Applications.DoesNotExist:
            application_obj = None
        if application_obj:
            form = self.form(request.POST)
            if form.is_valid():
                screenshot_image = find_markdown_images(form.cleaned_data['screenshot'])
                screenshot = ''
                if screenshot_image:
                    for image in screenshot_image:
                        image_path = base_path + str(image)
                        image_file = File(open(image_path, 'rb'))
                        screenshot = os.path.basename(image_file.name)
                        if client_conf_obj and client_conf_obj.storage_type=="S3":
                            image_key = ''.join(['screenshots/',
                            os.path.basename(image_file.name)]
                        )
                            if not S3Uploads.objects.filter(key=image_key).exists():
                                media_uploader = MediaUploader(client_conf_obj,
                                    image_key, image_file
                                )
                                result = media_uploader.upload()
                                if result == "success":
                                    S3Uploads.objects.create(
                                        key=image_key,
                                        filename=os.path.basename(image_file.name)
                                    )
                        application_obj.screenshot_filename = screenshot
                        application_obj.screenshot_path = os.path.join(
                            "/media/screenshots/",
                            screenshot
                        )
                application_obj.host = form.cleaned_data.get('host')
                application_obj.host_link = form.cleaned_data.get('host_link')
                application_obj.application_url = form.cleaned_data.get('application_url')
                application_obj.application_title = form.cleaned_data.get('application_title')
                application_obj.scope = form.cleaned_data.get('scope')
                application_obj.network_type = form.cleaned_data.get('network_type')
                application_obj.screenshot_title = form.cleaned_data.get('screenshot_title')
                application_obj.save()
                response = {
                    'status': True,
                    'status_code': 200,
                    'message': 'Application updated successfully.',
                }
        else:
            response = {
                'status': False,
                'status_code': 404,
                'message': 'Application not found.'
            }
        return JsonResponse(response, safe=False)


@method_decorator(login_required, name='dispatch')
class ApplicationScopeToggleView(View):
    '''
    To update the scope of Applications
    '''

    def post(self, request, id):
        application_scope = request.POST.get('application_scope')
        try:
            application_obj = Applications.objects.get(id=id)
        except Applications.DoesNotExist:
            application_obj = None
        if application_obj and application_scope:
            if application_scope == "black":
                new_scope = "grey"
            else:
                new_scope = "black"
            application_obj.scope = new_scope
            application_obj.save()
            response = {
                'status': True,
                'status_code': 200,
                'message': 'Application Scope updated successfully.',
                'data': {
                    'application_id': application_obj.id,
                    'application_scope': application_obj.scope
                }
            }
        else:
            response = {
                'status': False,
                'status_code': 404,
                'message': 'Application not found.'
            }
        return JsonResponse(response, safe=False)


@method_decorator(login_required, name='dispatch')
class UnscannedPortsView(View):
    template_name = 'redtree_app/unscanned-ports.html'
    context = dict()

    def get(self, request, *args, **kwargs):
        unscanned_host_list = list()
        unscanned_hosts_list = list()
        unscanned_dict = dict()
        key_list = list()
        unscannedhost_nessus = NessusData.objects.filter(plugin_id=11219)
        for data in unscannedhost_nessus:
            if data.host in unscanned_dict:
                unscanned_dict[data.host].append(data.port)
            else:
                unscanned_dict[data.host] = [data.port]
            if data.host not in key_list:
                key_list.append(data.host)
        host_vulnerability = Vulnerability.objects.filter(host_ip__in=key_list)
        unscanned_port_dict = dict()
        for data in host_vulnerability:
            host = data.host_ip
            port = data.port
            if host in unscanned_dict and int(port) not in unscanned_dict[host]:
                if host in unscanned_port_dict:
                    if port not in unscanned_port_dict[host]:
                        unscanned_port_dict[host].append(port)
                else:
                    unscanned_port_dict[host] = [port]
        for key, value in unscanned_port_dict.items():
            port_dict = {
                'host': key,
                'ports': value
            }
            unscanned_host_list.append(port_dict)
        self.context['unscanned_host_list'] = unscanned_host_list
        return render(
            request,
            self.template_name,
            self.context
        )


@method_decorator(login_required, name='dispatch')
class MicroLogsDeleteView(View):
    
    def get(self, request):
        LogMicroServiceBurp.objects.all().delete()
        LogMicroServiceCloudstorage.objects.all().delete()
        LogMicroServiceDnsEnum.objects.all().delete()
        LogMicroServiceMasscan.objects.all().delete()
        LogMicroServiceNessus.objects.all().delete()
        LogMicroServiceScreenshot.objects.all().delete()
        LogMicroServiceSshyze.objects.all().delete()
        LogMicroServiceSslyze.objects.all().delete()
        LogMicroServiceWhois.objects.all().delete()
        messages.success(request, "Logs deleted successfully.")
        return redirect('/logs/microservices/')



@login_required
def encryption_chart_data(request):
    sshyze_ciphers = SshyzeCiphers.objects.distinct('ciphers').count()
    sslyze_ciphers = Ciphers.objects.distinct('cipher').count()
    riskdatalist = {
        'secure_sh_ciphers': sshyze_ciphers,
        'secure_ly_ciphers': sslyze_ciphers,
        'ciphers_proto': get_ciphers_strength(),
        'cipher_strength':get_strength_count()
    }
    return JsonResponse(riskdatalist, safe=False)


@login_required
def application_chart_data(request):
    app_vul_data = ApplicationVulnerabilityChart.objects.all()[:30]
    app_ch_data = list()
    no_app_record_dates = list()
    app_chart_data = GetAppVulnerabilityHistoricalDataSerializer(
        app_vul_data,
        many=True
    ).data
    
    for data in range(1,len(app_chart_data)+1):
        reverse_len = len(app_chart_data)-data
        app_ch_data.append(app_chart_data[reverse_len])
    if 0 < len(app_chart_data) < 30:
        no_record_len = 30-len(app_chart_data)+1
        last_chart_data_date = app_chart_data[-1]["Date"]
        for counts in range(1, no_record_len):
            chart_data_date = datetime.strptime(last_chart_data_date, "%m-%d-%Y")
            days_before = chart_data_date-timedelta(days=counts)
            no_app_record_dates.append(days_before.strftime("%m-%d-%Y"))
        no_app_record_dates[-1] = "no record"
        for data_range in no_app_record_dates:
            data = {
                "Date": data_range,
                "Low": 0,
                "Medium": 0,
                "High": 0,                
                "Critical": 0
            }
            app_ch_data.append(data)
    if len(app_chart_data) == 0:
        for day_ in range(0,30):
            current_date = date.today()
            days_ = (date.today()-timedelta(days=day_))
            no_app_record_dates.append(days_.strftime("%m-%d-%Y"))
        no_app_record_dates[-1] = "no record"
        no_app_record_dates[0] = "no record"
        for data_range in no_app_record_dates:
            data = {
                "Date": data_range,
                "Low": 0,
                "Medium": 0,
                "High": 0,                
                "Critical": 0
            }
            app_ch_data.append(data)
    riskdatalist = {
        'app_vul': app_ch_data
    }
    return JsonResponse(riskdatalist, safe=False)


@method_decorator(login_required, name='dispatch')
class ApplicationVulnerabilityView(View):
    template_name = 'redtree_app/application-vulnerability-detail.html'
    context = dict()
    def get(self, request, *args, **kwargs):
        log_user_activity(request)
        virtue_id = int(kwargs.get('virtue_id'))
        applications = ApplicationVulnerability.objects.filter(
            virtue_id=virtue_id)
        vulnerability = applications.first()
        conf_obj = ClientConfiguration.objects.first()
        if conf_obj and applications:
            for vulnerability in applications:
                if vulnerability.evidence:
                    markdown_evidence = get_markdown_with_images(
                        vulnerability.evidence
                    )
                    vulnerability.evidence = markdownify(markdown_evidence)
        if conf_obj and vulnerability:
            if vulnerability.remediation:
                markdown_remediation = get_markdown_with_images(
                    vulnerability.remediation
                )
                vulnerability.remediation = markdownify(markdown_remediation)
            if vulnerability.description:
                markdown_description = get_markdown_with_images(
                    vulnerability.description
                )
                vulnerability.description = markdownify(markdown_description)
        page = request.GET.get('page', 1)
        paginator = Paginator(applications.order_by('-id'), 1000)
        try:
            applications = paginator.page(page)
        except PageNotAnInteger:
            applications = paginator.page(1)
        except EmptyPage:
            applications = paginator.page(paginator.num_pages)
        show_application = True
        self.context['show_application'] = show_application
        self.context['applicationvulnerability'] = vulnerability
        self.context['app_vulnerability_obj'] = applications
        return render(
            request,
            self.template_name,
            self.context
        )


@method_decorator(login_required, name='dispatch')
class ApplicationVulnerabilityUpdateView(View):
    template_name = 'redtree_app/application-vulnerability-edit.html'
    context = dict()

    def get(self, request, *args, **kwargs):
        log_user_activity(request)
        vul_id = self.kwargs.get('id')
        try:
            vul_obj = ApplicationVulnerability.objects.get(id=vul_id)
            virtue_id = vul_obj.virtue_id
        except ApplicationVulnerability.DoesNotExist:
            vul_obj = None
            virtue_id = None

        form = ApplicationVulnerabilityEditForm(instance=vul_obj)
        self.context['form'] = form
        self.context['virtue_id'] = virtue_id
        return render(
            request,
            self.template_name,
            self.context
        )

    def post(self, request, *args, **kwargs):
        vul_id = self.kwargs.get('id')
        client_conf_obj = ClientConfiguration.objects.first()
        try:
            vulnerability_obj = ApplicationVulnerability.objects.get(id=vul_id)
            virtue_id = vulnerability_obj.virtue_id
        except ApplicationVulnerability.DoesNotExist:
            vulnerability_obj = None
            virtue_id = None
        form = ApplicationVulnerabilityEditForm(request.POST, instance=vulnerability_obj)
        if form.is_valid() and form.has_changed():
            vulnerability_obj.application = form.cleaned_data.get('application')
            vulnerability_obj.title = form.cleaned_data.get('title')
            vulnerability_obj.risk = form.cleaned_data.get('risk')
            vulnerability_obj.description = change_media_path(
                form.cleaned_data.get('description')
            )
            vulnerability_obj.remediation = change_media_path(
                form.cleaned_data.get('remediation')
            )
            vulnerability_obj.evidence = change_media_path(
                form.cleaned_data.get('evidence')
            )
            vulnerability_obj.risk = form.cleaned_data.get('risk')
            vulnerability_obj.save()
            if vulnerability_obj.evidence:
                evidence_images = find_markdown_images(vulnerability_obj.evidence)
            else:
                evidence_images = []
            if vulnerability_obj.remediation:
                remediation_images = find_markdown_images(vulnerability_obj.remediation)
            else:
                remediation_images = []
            if vulnerability_obj.description:
                description_images = find_markdown_images(vulnerability_obj.description)
            else:
                description_images = []

            all_images = evidence_images + remediation_images + description_images
            base_path = str(settings.BASE_DIR)
            for image in all_images:
                if not S3Uploads.objects.filter(key=image).exists():
                    actual_file_path = ''.join(['/media/', image])
                    image_path = base_path + str(actual_file_path)
                    image_file = File(open(image_path, 'rb'))
                    if client_conf_obj and client_conf_obj.storage_type=="S3":
                        image_key = ''.join(['screenshots/', os.path.basename(
                            image_file.name)]
                        )
                        media_uploader = MediaUploader(
                            client_conf_obj, image_key, image_file
                        )
                        result = media_uploader.upload()
                        if result == "success" and not S3Uploads.objects.filter(
                                key=image_key
                            ).exists():
                            S3Uploads.objects.create(
                                key=image_key,
                                filename=os.path.basename(image_file.name)
                            )
            redirect_url = "/applications/vulnerabilities/{}/".format(virtue_id)
            return redirect(redirect_url)
        elif form.is_valid() and not form.has_changed():
            redirect_url = "/applications/vulnerabilities/{}/".format(virtue_id)
            return redirect(redirect_url)
        self.context['form'] = form
        self.context['virtue_id'] = virtue_id
        return render(
            request,
            self.template_name,
            self.context
        )
