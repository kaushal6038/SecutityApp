from __future__ import unicode_literals,division
from django.http import HttpResponseRedirect, JsonResponse, QueryDict
from django.shortcuts import render, redirect
from .forms import *
from .models import *
from django.contrib.auth.hashers import check_password
from django.utils import timezone
import pyotp
import re
from django.conf import settings
from .ip_validator import *
from .alerts import send_mail
from django.db.models import Count
import requests
from django.views import View
from django.core.urlresolvers import reverse
from django.forms.utils import ErrorList
from django.contrib import messages
from account.models import *
from django.contrib.auth import get_user_model
from utils.views import LoginRequiredView, TwoFaLoginRequiredView
from utils.mail_template import invitation_header
from utils.helpers import get_private_request_header
from datetime import datetime
from utils.log_user_activity import *
from datetime import date, timedelta
import datetime
from django.core.paginator import (
    Paginator,
    EmptyPage,
    PageNotAnInteger
)

User = get_user_model()



def error_404(request):
    return render(request, 'purpleleaf_app/404.html')
 

class HomeView(TwoFaLoginRequiredView):
    
    def get(self, request, *args, **kwargs):
        return redirect('/dashboard')


def get_request_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


class DashBoardView(TwoFaLoginRequiredView):
    context = {
        'title' : 'Dashboard'
    }
    template_name = 'purpleleaf_app/dashboard.html'
    config_model_class = Configuration

    def get(self, request, *args, **kwargs):
        log_user_activity(request)
        response_data = dict()
        configurationObj = self.config_model_class.objects.first()
        conf_obj = PrivateConfiguration.objects.first()
        if conf_obj:
            request_url = "{}/private/dashboard".format(
                conf_obj.redtree_base_url,
                )
            try:
                response = requests.get(
                    request_url,
                    headers=get_private_request_header()
                )
            except Exception as e:
                response = None
            if response:
                response_data = response.json()
                response_data['configuration'] = configurationObj
        else:
            response_data['configuration'] = configurationObj
        return render(
            request,
            self.template_name,
            response_data
        )


class VulnerabilitiesView(TwoFaLoginRequiredView):
    template_name = 'purpleleaf_app/vulnerabilities.html'
    context = {
        'title': "Vulnerabilities"
    }

    def get(self, request, *args, **kwargs):
        log_user_activity(request)
        conf_obj = PrivateConfiguration.objects.first()
        if conf_obj:
            request_url = "{}/private/vulnerabilities".format(
                conf_obj.redtree_base_url,
                )
            try:
                response = requests.get(
                    request_url,
                    headers=get_private_request_header()
                )
            except Exception as e:
                response = None
            if response and response.status_code == 200:
                response_data = response.json()
                self.context['datalist'] = response_data.get('vulnerabilities')
                self.context['networks'] = response_data.get('networks')
            else:
                self.context['datalist'] = None
                self.context['networks'] = None
        return render(request, self.template_name, self.context)


class HostsView(TwoFaLoginRequiredView):
    template_name = 'purpleleaf_app/hosts.html'
    context = {
        'title': "Hosts"
    }
    config_model_class = Configuration
    asset_form_class = CloudAssetsForm

    def get(self, request, *args, **kwargs):
        log_user_activity(request)
        confObj = self.config_model_class.objects.first()
        cloud_assets_form = self.asset_form_class()
        self.context['hosts'] = ""
        self.context['total_host'] = ""
        self.context['total_exclude'] = ""
        self.context['application_data'] = ""
        self.context['cloud_assets_form'] = cloud_assets_form
        self.context['total_applications'] = ""
        self.context['total_assets'] = ""
        self.context['network_data'] = None
        self.context['total_networks'] = ""
        self.context['configuration'] = confObj
        self.context['total_domains'] = ""

        conf_obj = PrivateConfiguration.objects.first()
        if conf_obj:
            try:
                post_url = "{}/private/update-count".format(conf_obj.redtree_base_url)
                response = requests.get(
                    post_url,
                    headers=get_private_request_header()
                )
            except:
                response = {
                    "status_code": 504,
                    "message": "Unable to fetch detail no reponse from host.",
                }
                return JsonResponse(response, safe=False)
            if response and response.status_code == 200:
                response_data = response.json()
                self.context['total_host'] = response_data.get('total_host')
                self.context['total_applications'] = response_data.get('total_applications')
                self.context['total_assets'] = response_data.get('total_assets')
                self.context['total_networks'] = response_data.get('total_network')
                self.context['total_domains'] = response_data.get('total_domains')
                self.context['total_exclude'] = ""
                self.context['network_data'] = response_data.get('network_detail')
            else:
                self.context['total_host'] = None
                self.context['total_applications'] = None
                self.context['total_assets'] = None
                self.context['total_networks'] = None
                self.context['total_domains'] = None
                self.context['total_exclude'] = None
                self.context['network_data'] = None
        return render(
            request,
            self.template_name,
            self.context
            )


class IpsInfoDetailView(TwoFaLoginRequiredView):

    def post(self, request, *args, **kwargs):
        hostid = request.POST.get('hostid', None)
        
        conf_obj = PrivateConfiguration.objects.first()
        if conf_obj and hostid:
            try:
                post_url = "{}/private/subhost-info/{}".format(conf_obj.redtree_base_url,hostid)
                response = requests.get(
                    post_url,
                    headers=get_private_request_header()
                )
                ips=response.json()
                return JsonResponse(ips, safe=False)
            except:
                response = {
                    "status_code": 504,
                    "message": "Unable to fetch ips detail no reponse from host.",
                }
                return JsonResponse(response, safe=False)
        return JsonResponse(False, safe=False)


class DeleteHostView(TwoFaLoginRequiredView):
    privateconf_model_class = PrivateConfiguration

    def get(self, request, *args, **kwargs):
        host_ids = request.GET.getlist('host_id[]')
        if "on" in host_ids:
            host_ids.remove("on")
        data = {
            'host_ids': host_ids
        }
        conf_obj = PrivateConfiguration.objects.first()
        if conf_obj:
            try:
                post_url = "{}/private/delete-host".format(conf_obj.redtree_base_url)
                response = requests.get(
                    post_url,
                    headers=get_private_request_header(),
                    json=data
                )
            except:
                response = {
                    "status": False,
                    "status_code": 504,
                    "message": "Unable to fetch reponse from host.",
                    "data": []
                }
                return JsonResponse(response, safe=False)
            if response.status_code == 200:
                response_data = response.json()
            elif response.status_code == 400:
                response_data = response.json()
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
                    "message": "Unable to fetch reponse from host.",
                    "data": []
                }
            return JsonResponse(response_data, safe=False)
        response_data = {
            "status": False,
            "status_code": 500,
            "message": "No configuration set for host.",
            "data": []
        }
        return JsonResponse(response_data, safe=False)

    def delete(self, request, *args, **kwargs):
        delete = QueryDict(request.body)
        request_ip = get_request_ip(request)
        host_id = delete.getlist('host_id[]')
        if "on" in host_id:
            host_id.remove("on")
        conf_obj = PrivateConfiguration.objects.first()
        if conf_obj:
            time_stamp = timezone.now().strftime('%s')
            data = {
                'host_ids': host_id,
                'event_data': {
                    'event_type': 'delete_range',
                    'time_stamp': time_stamp,
                    'username': request.user.email,
                    'ip': request_ip
                }
            }
            try:
                post_url = "{}/private/delete-host".format(
                    conf_obj.redtree_base_url
                    )
                response = requests.delete(
                    post_url,
                    headers=get_private_request_header(),
                    json=data
                )
            except:
                response = {
                    "status": False,
                    "status_code": 504,
                    "message": "Unable to add network no reponse from host.",
                    "data": []
                }
                return JsonResponse(response, safe=False)
            if response.status_code == 200:
                response_data = response.json()
            elif response.status_code == 400:
                response_data = response.json()
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
                    "message": "Unable to get reponse from host.",
                    "data": []
                }
            return JsonResponse(response_data, safe=False)
        response_data = {
            "status": False,
            "status_code": 500,
            "message": "No configuration set for host.",
            "data": []
        }
        return JsonResponse(response_data, safe=False)


def get_risk_factor(risk):
    risk_status = dict()
    risk_status["Critical"] = 4
    risk_status["High"] = 3
    risk_status["Medium"] = 2
    risk_status["Low"] = 1
    risk_status["Note"] = 0
    return risk_status[risk]


class AnaylyticsView(TwoFaLoginRequiredView):
    template_name = 'purpleleaf_app/analytics.html'
    error_template = 'purpleleaf_app/404.html'
    model_class = Configuration

    def get(self, request, *args, **kwargs):
        log_user_activity(request)
        confObj = self.model_class.objects.first()
        if confObj and confObj.analytics_status:
            return render(
                request,
                self.template_name
                )
        messages.add_message(request, messages.WARNING, "You Don't have permission to access this page")

        return render(
            request,
            self.error_template
            )


class ApplicationsView(TwoFaLoginRequiredView):
    template_name = 'purpleleaf_app/applications.html'
    error_template = 'purpleleaf_app/404.html'
    context = dict()

    def get(self, request, *args, **kwargs):
        log_user_activity(request)
        conf_obj = PrivateConfiguration.objects.first()
        if conf_obj:
            page = request.GET.get('page')
            if not page:
                request_url = "{}/private/application".format(
                    conf_obj.redtree_base_url
                )
            else:
                request_url = "{}/private/application?page={}".format(
                    conf_obj.redtree_base_url,
                    page
                )
            headers = {'data-auth-key': conf_obj.data_auth_key}
            try:
                response = requests.get(request_url, headers=headers)
            except Exception as e:
                response = None
            if response:
                response_data = response.json()
                paginator_content = {
                    'page_range': response_data['page_range'],
                    'has_other_pages': response_data['has_other_pages'],
                    'has_previous': response_data['has_previous'],
                    'previous_page_number': response_data['previous_page_number'],
                    'page_number': response_data['page_number'],
                    'has_next': response_data['has_next'],
                    'next_page_number': response_data['next_page_number'],
                    'count': response_data['count'],
                    'next': response_data['next'],
                    'previous': response_data['previous']
                } 
                self.context['paginator_content'] = paginator_content
                self.context['application_page'] = response_data['results']
                self.context['chart_exist'] = response_data['chart_exist']
            else:
                self.context['paginator_content'] = None
                self.context['application_page'] = None
                self.context['chart_exist']=None
        return render(
            request,
            self.template_name,
            self.context
            )
        messages.add_message(request, messages.WARNING, "You Don't have permission to access this page")
        return render(
            request,
            self.error_template
            )


class ReportsListView(TwoFaLoginRequiredView):
    template_name = 'purpleleaf_app/reports.html'
    context = dict()

    def get(self, request, *args, **kwargs):
        log_user_activity(request)
        conf_obj = PrivateConfiguration.objects.first()
        if conf_obj:
            headers = {'data-auth-key': conf_obj.data_auth_key}
            request_url = "{}/private/reports".format(
                conf_obj.redtree_base_url
                )
            try:
                response = requests.get(
                    request_url,
                    headers=headers
                )
            except Exception as e:
                response = None
            if response and response.status_code == 200:
                response_data = response.json()
                self.context['external_reports'] = response_data.get('external_reports')
                self.context['internal_reports'] = response_data.get('internal_reports')
            else:
                self.context['external_reports'] = None
                self.context['internal_reports'] = None
        return render(
            request,
            self.template_name,
            self.context
        )


class SettingsView(TwoFaLoginRequiredView):
    template_name =  'purpleleaf_app/settings.html'
    context = {
        'title': "Settings"
    }
    config_model_class = Configuration
    password_form_class = ChangePasswordForm
    timezone_form_class = TimezoneForm

    def get(self, request, *args, **kwargs):
        log_user_activity(request)
        user = request.user
        timezone_intial_data = {'timezone': user.time_zone}
        timezoneform = self.timezone_form_class(timezone_intial_data, auto_id=False)
        changePassworForm = self.password_form_class()
        self.context['timezoneform'] = timezoneform
        self.context['form'] = changePassworForm

        return render(
            request,
            self.template_name,
            self.context
            )


    def post(self, request, *args, **kwargs):
        user = request.user
        form_type = request.POST.get('form_type')
        timezoneform = self.timezone_form_class(request.POST)
        form = self.password_form_class(request.POST)
        if form_type == "change_password":
            if form.is_valid():
                password = form.cleaned_data.get("password")
                new_password = form.cleaned_data.get("new_password")
                if check_password(password, user.password):
                    user.set_password(new_password)
                    user.twofa_status = False
                    user.save()
                    
                    if AccessAttempt.objects.filter(email=user.email).exists():
                        AccessAttempt.objects.filter(email=user.email).delete()
                    reciever = user.email
                    subject = 'Your password has been changed'
                    invitation_template = invitation_header
                    send_mail(reciever, subject, invitation_template)
                    messages.add_message(request, messages.SUCCESS, "Password Changed successfully")
                    return HttpResponseRedirect(reverse('purpleleaf:dashboard'))
                errors = form._errors.setdefault("password", ErrorList())
                errors.append(u"Wrong password supplied.")
        elif form_type == "timezone":
            
            if timezoneform.is_valid() and timezoneform.has_changed():
                user.time_zone = timezoneform.cleaned_data.get('timezone')
                user.save()
                messages.add_message(request, messages.SUCCESS, "Password Changed successfully")
                request.session['django_timezone'] = timezoneform.cleaned_data.get('timezone')

            return HttpResponseRedirect(reverse('purpleleaf:settings'))

        self.context['timezoneform'] = timezoneform
        self.context['form'] = form

        return render(
            request,
            self.template_name,
            self.context
            )


class AffectedHostVulnerabilityView(TwoFaLoginRequiredView):
    template_name = 'purpleleaf_app/affectedHosts.html'
    context = dict()

    def get(self, request, *args, **kwargs):
        self.context['hosts'] = None
        self.context['banner'] = None
        self.context['vulnerability'] = None
        self.context['evidence_count'] = None
        log_user_activity(request)
        request_url = request.path_info
        if "/external/" in request_url:
            network_type = "external"
        elif "/internal/" in request_url:
            network_type = "internal"
        banner_count = 0
        virtue_id = kwargs.get('virtue_id')
        conf_obj = PrivateConfiguration.objects.first()
        if conf_obj:
            headers = {'data-auth-key': conf_obj.data_auth_key}
            request_url = "{}/private/vulnerabilities/{}/{}".format(
                conf_obj.redtree_base_url,
                network_type,
                virtue_id
            )
            try:
                response = requests.get(
                    request_url,
                    headers=headers
                )
            except Exception as e:
                response = None

            if response and response.status_code == 200:
                response_data = response.json()
                self.context['hosts'] = response_data.get('affected_hosts')
                self.context['banner'] = response_data.get('banner')
                self.context['vulnerability'] = response_data.get('vulnerability')
                self.context['evidence_count'] = response_data.get('evidence_count')
            else:
                self.context['hosts'] = None
                self.context['banner'] = None
                self.context['vulnerability'] = None
                self.context['evidence_count'] = None
        return render(
            request,
            self.template_name,
            self.context
        )


class UpdateScanningView(TwoFaLoginRequiredView):
    privateconfig_model_class = PrivateConfiguration
    config_model_class = Configuration

    def post(self, request, *args, **kwargs):        
        conf_obj = self.privateconfig_model_class.objects.first()
        if conf_obj:
            post_url = "{}/private/api/toggle_activity".format(
                conf_obj.redtree_base_url
            )
            try:
                response = requests.post(
                    post_url,
                    headers=get_private_request_header()
                )
            except:
                response = None
            if response and response.status_code == 200:
                response_data = response.json()
                scanning_status = response_data.get('data').get('scanning_status')
                configuration_obj = Configuration.objects.first()
                configuration_obj.active = scanning_status
                configuration_obj.save()
                return JsonResponse(configuration_obj.active, safe=False)
        return JsonResponse("error", safe=False, status=400)


class AnalyticsDataView(TwoFaLoginRequiredView):

    def get(self, request, *args, **kwargs):
        log_user_activity(request)
        firewall = {
            'risk': 'Requires action',
            'description': 'This is sample text, there may be a few sentences here. '
                           'This is sample text, there may be a few sentences here. '
                           'This is sample text, there may be a few sentences here.'
        }
        encryption_analysis = {
            'risk': 'No issues identified',
            'description': 'This is sample text2'
        }
        exposure_analysis = {
            'risk': 'Above average',
            'description': 'This is sample text3'
        }
        analytics_data_obj = {
            'firewall_data': firewall,
            'encryption_analysis_data': encryption_analysis,
            'exposure_analysis_data': exposure_analysis
        }
        return JsonResponse(analytics_data_obj, safe=False)


class VulnerabilityDetailView(TwoFaLoginRequiredView):
    template_name = "purpleleaf_app/affected-host-detail.html"
    error_template = "purpleleaf_app/404.html"
    context = dict()
    context['vulnerability'] = None

    def get(self, request, *args, **kwargs):
        log_user_activity(request)
        virtue_id = kwargs.get('virtue_id')
        vul_id = kwargs.get('vul_id')
        conf_obj = PrivateConfiguration.objects.first()
        if conf_obj:
            headers = {'data-auth-key': conf_obj.data_auth_key}
            request_url = "{}/private/vulnerabilities/{}/{}".format(
                conf_obj.redtree_base_url,
                virtue_id,
                vul_id
            )
        try:
            response = requests.get(
            request_url,
            headers=headers
            )
        except Exception as e:
            response = None
        if response and response.status_code == 200:
            response_data = response.json()
            self.context['vulnerability'] = response_data.get('vulnerability')
            return render(
                request,
                self.template_name,
                self.context
            )
        else:
            self.context['vulnerability'] = None
            return render(
                request,
                self.template_name,
                self.context
            )


class HostVulnerabilityDetail(TwoFaLoginRequiredView):
    template_name = "purpleleaf_app/affected-host-detail.html"
    error_template = "purpleleaf_app/404.html"
    context = dict()

    def get(self, request, *args, **kwargs):
        log_user_activity(request)
        vul_id = kwargs.get('vul_id')
        conf_obj = PrivateConfiguration.objects.first()
        if conf_obj:
            headers = {'data-auth-key': conf_obj.data_auth_key}
            request_url = "{}/private/host/vulnerability/{}".format(
                conf_obj.redtree_base_url,
                vul_id
            )
        try:
            response = requests.get(
            request_url,
            headers=headers
            )
        except Exception as e:
            response = None
        if response and response.status_code == 200:
            response_data = response.json()
            self.context['vulnerability'] = response_data.get('vulnerability')
            return render(
                request,
                self.template_name,
                self.context
            )
        else:
            messages.add_message(request, messages.WARNING, "Vulnerability does not exists.")
            return render(
                request,
                self.error_template,
                self.context
            )


class RetestVulnerabilityView(TwoFaLoginRequiredView):

    def post(self, request, *args, **kwargs):
        log_user_activity(request)
        vul_id = kwargs.get('vul_id')
        conf_obj = PrivateConfiguration.objects.first()
        if conf_obj:
            request_url = "{}/private/api/retest/{}".format(
                conf_obj.redtree_base_url,
                vul_id
            )
            data = {
                "status": "Requested"
            }
            try:
                response = requests.post(
                    request_url,
                    headers=get_private_request_header(),
                    data=data
                )
            except Exception as e:
                response = None
            if response.status_code == 200:
                data = response.json()
                messages.add_message(request, messages.SUCCESS, data.get('message'))
                return JsonResponse(data, safe=False)
        data = {
            'status_code': 400,
            'status': False
        }
        return JsonResponse(data, safe=False)



class GetNotificationsView(View):
    model_class = Notifications

    def get(self, request, *args, **kwargs):
        twofaKey = self.request.session.get('twofa_status')
        if request.user.is_authenticated and twofaKey:
            notificationObj = self.model_class.objects.filter(seen=False).\
                values('issue', 'status', 'issue_virtue_id', 'issue_network_type').annotate(
                    instances=Count('issue')
                )
            notification_list = list()
            if notificationObj:
                for notification in notificationObj:
                    data = {
                        'issue': notification['issue'],
                        'count': notification['instances'],
                        'virtue_id': notification['issue_virtue_id'],
                        'status': notification['status'],
                        'network_type': notification['issue_network_type']
                    }
                    notification_list.append(data)
                notificationList = {
                    'status': True,
                    'status_code': 200,
                    'notification_list': notification_list
                    }
            else:
                notificationList = {
                    'status': False,
                    'status_code': 200
                }
            return JsonResponse(notificationList, status=200, safe=False)
        else:
            notificationList = {
                'status': False,
                'status_code': 401
            }
            return JsonResponse(notificationList, status=401, safe=False)


class UpdateNotificationView(TwoFaLoginRequiredView):
    model_class = Notifications

    def get(self, request, *args, **kwargs):
        self.model_class.objects.filter(seen=False, issue=request.GET.get('title')).update(seen=True)
        return JsonResponse(True, safe=False)


class CloudAssetView(TwoFaLoginRequiredView):

    def post(self, request, *args, **kwargs):
        conf_obj = PrivateConfiguration.objects.first()
        if conf_obj:
            bucket = request.POST.get('bucket')
            category = request.POST.get('category')
            object_list = get_objects_list(bucket)
            for bucket_obj in object_list:
                if re.search("\r\n", bucket_obj) or re.search("\r", bucket_obj) or re.search("\n", bucket_obj):
                    if re.search("\r\n", bucket_obj):
                        bucket_obj = bucket_obj.replace("\r\n","")
                    if re.search("\n", bucket_obj):
                        bucket_obj = bucket_obj.replace("\n", "")
                    if re.search("\r", bucket_obj):
                        bucket_obj = bucket_obj.replace("\r", "")
                bucket_obj = bucket_obj.rstrip()
                data = {
                    'bucket': bucket_obj,
                    'category': category
                }
                post_url = "{}/private/cloud-assets".format(conf_obj.redtree_base_url)
                try:
                    response = requests.post(
                        post_url,
                        data = data,
                        headers = get_private_request_header()
                        )
                except:
                    response = {
                        'status': False,
                        'messages': "Unable to process the request. No response from Host."
                    }
                    return JsonResponse(response, safe=False)
                if response and response.status_code == 201:
                    response_data = response.json()
                    return JsonResponse(response_data, safe=False)
                elif response.status_code == 400:
                    response_data = response.json()
                return JsonResponse(response_data, safe=False)
        return JsonResponse(False, safe=False)

    def get(self, request, *args, **kwargs):
        conf_obj = PrivateConfiguration.objects.first()
        post_url = "{}/private/cloud-assets".format(conf_obj.redtree_base_url)
        try:
            response = requests.get(
                post_url,
                headers = get_private_request_header()
            )
        except:
            response = None
        if response and response.status_code == 200:
            assets_dict = response.json()
        else:
            assets_dict = {
                'Azure': None,
                'S3': None,
                'GCP': None,
                'aws_data': None
            }
        return JsonResponse(assets_dict, safe=False)


class CloudAssetsDetailView(TwoFaLoginRequiredView):

    def delete(self, request, *args, **kwargs):
        asset_id = kwargs.get('asset_id')
        conf_obj = PrivateConfiguration.objects.first()
        post_url = "{}/private/cloud-assets/{}".format(conf_obj.redtree_base_url, asset_id)
        try:
            response = requests.delete(
                post_url,
                headers=get_private_request_header()
            )
        except:
            response_data = {
                'status': False,
                'message': "Unable to process request, No response from host."
            }
            return JsonResponse(
                response_data,
                safe=False
                )
        if response.status_code == 200:
            response_data = response.json()
        elif response.status_code == 404:
            response_data = response.json()
        return JsonResponse(
            response_data,
            safe=False
            )


class UpdateHostCountView(TwoFaLoginRequiredView):

    def get(self, request, *args, **kwargs):
        conf_obj = PrivateConfiguration.objects.first()
        response_data = {
            'total_host': "",
            'total_applications': "",
            'total_assets': "",
            'total_domains': "",
            'total_network': "",
            'total_exclude': "",
        }
        if conf_obj:
            try:
                post_url = "{}/private/update-count".format(conf_obj.redtree_base_url)
                response = requests.get(
                    post_url,
                    headers=get_private_request_header()
                )
            except:       
                return JsonResponse(response_data, safe=False)
            if response.status_code == 200:
                response_data = response.json()
                response_data['total_exclude'] = 0
        return JsonResponse(response_data, safe=False)


class DashboardHistoricalDataView(TwoFaLoginRequiredView):
    privateconf_model_class = PrivateConfiguration

    def get(self, request, *args, **kwargs):
        datalist = dict()
        no_record_dates = list()
        no_app_record_dates = list()
        datalist = {
            'open_ports': None,
            'active_ips': None
        }
        riskdatalist = dict()
        riskdatalist = {
            'critical_risk': None,
            'medium_risk': None,
            'high_risk': None,
            'low_risk': None,
            'date': None,
            'vul': []
        }
        confObj = self.privateconf_model_class.objects.first()
        post_url = "{}/private/api/charts/dashboard_history".format(
            confObj.redtree_base_url
        )
        try:
            status = requests.get(
                post_url,
                headers=get_private_request_header()
            )
        except:
            status = None
        if status and status.status_code == 200:
            response_data = status.json()
        else:
            response_data = None
        if response_data:
            chart_data = response_data.get('risk_historical_data')
            app_chart_data = response_data.get('app_vul_data')
            app_ch_data = list()
            ch_data = list()
            for data in range(1,len(chart_data)+1):
                reverse_len = len(chart_data)-data
                ch_data.append(chart_data[reverse_len])
            if 0 < len(chart_data) < 30:
                no_record_len = 30-len(chart_data)+1
                last_chart_data_date = chart_data[-1]["Date"]
                for counts in range(1, no_record_len):
                    chart_data_date = datetime.datetime.strptime(last_chart_data_date, "%m-%d-%Y")
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
                for day_ in range(1,31):
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

            for data in range(1,len(app_chart_data)+1):
                reverse_len = len(app_chart_data)-data
                app_ch_data.append(app_chart_data[reverse_len])
            if 0 < len(app_chart_data) < 30:
                no_record_len = 30-len(app_chart_data)+1
                last_chart_data_date = app_chart_data[-1]["Date"]
                for counts in range(1, no_record_len):
                    chart_data_date = datetime.datetime.strptime(last_chart_data_date, "%m-%d-%Y")
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
                for day_ in range(1,31):
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
                'vul': ch_data,
                'app_vul':app_ch_data
            }
            historical_data_obj = response_data.get('historical_data')
            historicalactiveipslist = []
            historicalopenportslist = []
            for historical_data in historical_data_obj:
                historicalactiveipslist.append(historical_data.get('active_ips'))
                historicalopenportslist.append(historical_data.get('open_ports'))
            datalist = {
                'open_ports': historicalopenportslist,
                'active_ips': historicalactiveipslist
            }
        response = {
            'riskdatalist': riskdatalist,
            'datalist': datalist
        }
        return JsonResponse(response, safe=False)


class ClosedVulnerabilityView(TwoFaLoginRequiredView):
    template_name = 'purpleleaf_app/closed-vulnerabilities.html'

    def get(self, request, *args, **kwargs):
        log_user_activity(request)
        response_data = dict()
        conf_obj = PrivateConfiguration.objects.first()
        if conf_obj:
            request_url = "{}/private/history".format(
                conf_obj.redtree_base_url,
                )
            try:
                response = requests.get(
                    request_url,
                    headers=get_private_request_header()
                )
            except Exception as e:
                response = None
            if response and response.status_code == 200:
                response_data = response.json()
                data = response_data.get('data')
                response_data['vulnerabilities'] = data.get('closed_vulnerabilities')
                response_data['activity'] = data.get('activity')
                response_data['archived']= data.get('archive_vulnerabilities')
            else:
                response_data['vulnerabilities'] = None
                response_data['activity'] = None
                response_data['archived'] = None
        else:
            response_data['vulnerabilities'] = None
            response_data['activity'] = None
            response_data['archived'] = None
            
        return render(
            request,
            self.template_name,
            response_data
        )


class ApplicationView(TwoFaLoginRequiredView):

    def get(self, request, *args, **kwargs):
        log_user_activity(request)
        response_data = dict()
        response_data['count'] = 0
        conf_obj = PrivateConfiguration.objects.first()
        if conf_obj:
            try:
                post_url = "{}/private/applications".format(conf_obj.redtree_base_url)
                response = requests.get(
                    post_url,
                    headers=get_private_request_header()
                )
            except:
                response = {
                    "status": False,
                    "status_code": 504,
                    "message": "Unable to add network no reponse from host.",
                    "data": []
                }
                return JsonResponse(response, safe=False)
            if response.status_code == 200:
                response_data = response.json()
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
                    "message": "Unable to get reponse from host.",
                    "data": []
                }
            return JsonResponse(response_data, safe=False)

    def post (self, request, *args ,**kwargs):
        request_ip = get_request_ip(request)
        conf_obj = PrivateConfiguration.objects.first()
        if conf_obj:
            application_url = request.POST.get('application_url')
            application_network_type = request.POST.get('network_type')
            time_stamp = timezone.now().strftime('%s')
            data = {
                'application_url': application_url,
                'network_type': application_network_type,
                'event_data': {
                    'event_type': 'add_application',
                    'time_stamp': time_stamp,
                    'username': request.user.email,
                    'ip': request_ip
                }
            }
            try:
                post_url = "{}/private/applications".format(conf_obj.redtree_base_url)
                response = requests.post(
                    post_url,
                    json=data,
                    headers=get_private_request_header()
                    )
            except:
                response = {
                    "status": False,
                    "status_code": 504,
                    "message": "Unable to fetch application detail no reponse from host.",
                    "data": []
                }
                return JsonResponse(response, safe=False)
            if response.status_code == 201:
                response_data = response.json()
            elif response.status_code == 400:
                response_data = response.json()
            elif response.status_code == 403:
                response_data = {
                    "status": False,
                    "status_code": 403,
                    "message": "Unable to authenticate the processed request.",
                    "data": []
                }
            return JsonResponse(response_data, safe=False)
        else:
            response_data = {
                "status": False,
                "status_code": 500,
                "message": "Unable to get reponse from host.",
                "data": []
            }
        return JsonResponse(response_data, safe=False)


class DomainView(TwoFaLoginRequiredView):

    def get(self, request, *args, **kwargs):
        response_data = dict()
        response_data['count'] = 0
        conf_obj = PrivateConfiguration.objects.first()
        if conf_obj:
            try:
                post_url = "{}/private/domain".format(conf_obj.redtree_base_url)
                response = requests.get(
                    post_url,
                    headers=get_private_request_header()
                )
            except:
                response = {
                    "status": False,
                    "status_code": 504,
                    "message": "Unable to add network no reponse from host.",
                    "data": []
                }
                return JsonResponse(response, safe=False)
            if response.status_code == 200:
                response_data = response.json()
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
                    "message": "Unable to get reponse from host.",
                    "data": []
                }
            return JsonResponse(response_data, safe=False)
    
    def post (self, request, *args ,**kwargs):
        request_ip = get_request_ip(request)
        conf_obj = PrivateConfiguration.objects.first()
        if conf_obj:
            domain = request.POST.get('domain_name')
            network_type = request.POST.get('network_type')
            data = {
                'domain_name': domain.lower(),
                'network_type': network_type
            }
            try:
                post_url = "{}/private/domain".format(conf_obj.redtree_base_url)
                response = requests.post(
                    post_url,
                    data=data,
                    headers=get_private_request_header()
                    )
            except:
                response = {
                    "status": False,
                    "status_code": 504,
                    "message": "Unable to add domain, no reponse from host.",
                    "data": []
                }
                return JsonResponse(response, safe=False)
            if response.status_code == 201:
                response_data = response.json()
                EventHistory.objects.create(
                    event_type='add_domain',
                    time_stamp=timezone.now().strftime('%s'),
                    data=response_data.get('data').get('domain_name'),
                    username=request.user,
                    ip=request_ip,
                    created_by=request.user
                )
            elif response.status_code == 400:
                response_data = response.json()
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
                    "message": "Unable to add domain, no reponse from host.",
                    "data": []
                }
            return JsonResponse(response_data, safe=False)
        else:
            response_data = {
                "status": False,
                "status_code": 500,
                "message": "Unable to get reponse from host.",
                "data": []
            }
        return JsonResponse(response_data, safe=False)


class DomainDetailView(TwoFaLoginRequiredView):
    def delete(self, request, *args, **kwargs):
        domain_id = kwargs.get('domain_id')
        conf_obj = PrivateConfiguration.objects.first()
        if conf_obj:
            try:
                post_url = "{}/private/domains/{}".format(
                    conf_obj.redtree_base_url,
                    kwargs.get('domain_id')
                    )
                response = requests.delete(
                    post_url,
                    headers=get_private_request_header()
                )
            except:
                response = {
                    "status": False,
                    "status_code": 504,
                    "message": "Unable to add network no reponse from host.",
                    "data": []
                }
                return JsonResponse(response, safe=False)
            if response.status_code == 200:
                response_data = response.json()
            elif response.status_code == 400:
                response_data = response.json()
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
                    "message": "Unable to get reponse from host.",
                    "data": []
                }
            return JsonResponse(response_data, safe=False)
        response_data = {
            "status": False,
            "status_code": 500,
            "message": "No configuration set for host.",
            "data": []
        }
        return JsonResponse(response_data, safe=False)


class HostsCreateListView(TwoFaLoginRequiredView):
    privateconf_model_class = PrivateConfiguration
    event_model_class = EventHistory

    def get(self, request, *args, **kwargs):
        conf_obj = PrivateConfiguration.objects.first()
        if conf_obj:
            try:
                post_url = "{}/private/host".format(conf_obj.redtree_base_url)
                response = requests.get(
                    post_url,
                    headers=get_private_request_header()
                )
            except:
                response = {
                    "status": False,
                    "status_code": 504,
                    "message": "Unable to fetch host no reponse from host.",
                    "data": []
                }
                return JsonResponse(response, safe=False)
            if response.status_code == 200:
                response_data = response.json()
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
                    "message": "Unable to get reponse from host.",
                    "data": []
                }
            return JsonResponse(response_data, safe=False)

    def post(self, request, *args, **kwargs):
        request_ip = get_request_ip(request)
        network_id = request.POST.get('network_id')
        if not network_id:
            response_data = {
                    "status": False,
                    "status_code": 400,
                    "message": "Unable to add host!",
                    "errors": "Please Select Network Type.",
                    "data": []
                }
            return JsonResponse(response_data, safe=False)
        host_response = dict()
        confObj = self.privateconf_model_class.objects.first()
        rawIps = request.POST.get('ip_address')
        ipsList = get_objects_list(rawIps)
        multicast_ip_list = list()
        multicast_status = False
        for ip in ipsList:
            if re.search("\r\n", ip) or re.search("\r", ip) or re.search("\n", ip):
                if re.search("\r\n", ip):
                    ip = ip.replace("\r\n", "")
                if re.search("\n", ip):
                    ip = ip.replace("\n", "")
                if re.search("\r", ip):
                    ip = ip.replace("\r", "")
            ip = ip.strip()
            ip_type = get_range_type(ip)
            if ip_type == "ip":
                multicast_status = ipaddress.ip_address(
                    unicode(ip)
                ).is_multicast
            if multicast_status:
                multicast_ip_list.append(ip)
        conf_obj = PrivateConfiguration.objects.first()
        if conf_obj and multicast_ip_list:
            if len(multicast_ip_list) == 1:
                message = "{} is a multicast address and cannot be"\
                    " scanned.".format(multicast_ip_list[0])
            else:
                multicast_ips = ", ".join(multicast_ip_list)
                message = "{} are multicast addresses and cannot be"\
                    " scanned.".format(multicast_ips)
            response_data = {
                "status": False,
                "status_code": 500,
                "message": message,
                "data": []
            }
        elif conf_obj and not multicast_ip_list:
            domain = request.POST.get('domain_name')
            network_type = request.POST.get('network_type')
            time_stamp = timezone.now().strftime('%s')   
            data = {
                'ips': ipsList,
                'network_id': network_id,
                'event_data': {
                    'event_type': 'add_range',
                    'time_stamp': time_stamp,
                    'username': request.user.email,
                    'ip': request_ip
                }

            }
            try:
                post_url = "{}/private/host".format(conf_obj.redtree_base_url)
                response = requests.post(
                    post_url,
                    json=data,
                    headers=get_private_request_header()
                    )
            except:
                response = {
                    "status": False,
                    "status_code": 504,
                    "message": "Unable to create hosts no reponse from host.",
                    "data": []
                }
                return JsonResponse(response, safe=False)
            if response.status_code == 201:
                response_data = response.json()
            elif response.status_code == 400:
                response_data = response.json()
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
                    "message": "Unable to get reponse from host.",
                    "data": []
                }
            return JsonResponse(response_data, safe=False)
        else:
            response_data = {
                "status": False,
                "status_code": 500,
                "message": "Unable to get reponse from host.",
                "data": []
            }
        return JsonResponse(response_data, safe=False)


class NetworkCreateListView(TwoFaLoginRequiredView):

    def get(self, request, *args, **kwargs):
        conf_obj = PrivateConfiguration.objects.first()
        if conf_obj:
            try:
                post_url = "{}/private/network".format(conf_obj.redtree_base_url)
                response = requests.get(
                    post_url,
                    headers=get_private_request_header()
                )
            except:
                response = {
                    "status": False,
                    "status_code": 504,
                    "message": "Unable to add network no reponse from host.",
                    "data": []
                }
                return JsonResponse(response, safe=False)
            if response.status_code == 200:
                response_data = response.json()
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
                    "message": "Unable to get reponse from host.",
                    "data": []
                }
            return JsonResponse(response_data, safe=False)

    
    def post(self, request, *args, **kwargs):
        request_ip = get_request_ip(request)
        network = request.POST.get('network')
        network_type = request.POST.get('network_type')
        conf_obj = PrivateConfiguration.objects.first()
        time_stamp = timezone.now().strftime('%s')
        data = {
            'network': network,
            'network_type': network_type,
            'event_data': {
                'event_type': 'add_network',
                'time_stamp': time_stamp,
                'username': request.user.email,
                'ip': request_ip
            }
        }
        if conf_obj:
            try:
                post_url = "{}/private/network".format(conf_obj.redtree_base_url)
                response = requests.post(
                    post_url,
                    json=data,
                    headers=get_private_request_header()
                    )
            except:
                response = {
                    "status": False,
                    "status_code": 504,
                    "message": "Unable to add network no reponse from host.",
                    "data": []
                }
                return JsonResponse(response, safe=False)
            if response.status_code == 201:
                response_data = response.json()
            elif response.status_code == 400:
                response_data = response.json()
            elif response.status_code == 403:
                response_data = {
                    "status": False,
                    "status_code": 403,
                    "message": "Unable to authenticate the processed request.",
                    "data": []
                }
            return JsonResponse(response_data, safe=False)
        else:
            response_data = {
                "status": False,
                "status_code": 500,
                "message": "Unable to get reponse from host.",
                "data": []
            }
        return JsonResponse(response_data, safe=False)


class NetworkDetailView(TwoFaLoginRequiredView):

    def get(self, request, *args, **kwargs):
        network_id = kwargs.get('network_id')
        conf_obj = PrivateConfiguration.objects.first()
        if conf_obj:
            try:
                post_url = "{}/private/network/{}".format(conf_obj.redtree_base_url, network_id)
                response = requests.get(
                    post_url,
                    headers=get_private_request_header()
                )
            except:
                response = {
                    "status": False,
                    "status_code": 504,
                    "message": "Unable to fetch network no reponse from host.",
                    "data": []
                }
                return JsonResponse(response, safe=False)
            if response.status_code == 200:
                response_data = response.json()
            elif response.status_code == 400:
                response_data = response.json()
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
                    "message": "Unable to get reponse from host.",
                    "data": []
                }
            return JsonResponse(response_data, safe=False)
        response_data = {
            "status": False,
            "status_code": 500,
            "message": "No configuration set for host.",
            "data": []
        }
        return JsonResponse(response_data, safe=False)

    def patch(self, request, *args, **kwargs):
        data = QueryDict(request.body)
        network_id = kwargs.get('network_id')
        conf_obj = PrivateConfiguration.objects.first()
        if conf_obj:
            try:
                data = {
                    'network': data.get('network_name'),               
                    'network_type': data.get('network_type')
                }
                post_url = "{}/private/network/{}".format(conf_obj.redtree_base_url, network_id)
                response = requests.patch(
                    post_url,
                    data=data,
                    headers=get_private_request_header()
                )
            except:
                response = {
                    "status": False,
                    "status_code": 504,
                    "message": "Unable to add network no reponse from host.",
                    "data": []
                }
                return JsonResponse(response, safe=False)
            if response.status_code == 200:
                response_data = response.json()
            elif response.status_code == 400:
                response_data = response.json()
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
                    "message": "Unable to get reponse from host.",
                    "data": []
                }
            return JsonResponse(response_data, safe=False)
        response_data = {
            "status": False,
            "status_code": 500,
            "message": "No configuration set for host.",
            "data": []
        }
        return JsonResponse(response_data, safe=False)

    def delete(self, request, *args, **kwargs):
        network_id = kwargs.get('network_id')
        conf_obj = PrivateConfiguration.objects.first()
        request_ip = get_request_ip(request)
        if conf_obj:
            time_stamp = timezone.now().strftime('%s')
            data = {
                'event_data': {
                    'event_type': 'delete_network',
                    'time_stamp': time_stamp,
                    'username': request.user.email,
                    'ip': request_ip
                }
            }
            try:
                post_url = "{}/private/network/{}".format(
                    conf_obj.redtree_base_url,
                    kwargs.get('network_id')
                    )
                response = requests.delete(
                    post_url,
                    headers=get_private_request_header(),
                    json=data
                )
            except:
                response = {
                    "status": False,
                    "status_code": 504,
                    "message": "Unable to add network no reponse from host.",
                    "data": []
                }
                return JsonResponse(response, safe=False)
            if response.status_code == 200:
                response_data = response.json()
            elif response.status_code == 400:
                response_data = response.json()
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
                    "message": "Unable to get reponse from host.",
                    "data": []
                }
            return JsonResponse(response_data, safe=False)
        response_data = {
            "status": False,
            "status_code": 500,
            "message": "No configuration set for host.",
            "data": []
        }
        return JsonResponse(response_data, safe=False)


class HostNetworkUpdateView(TwoFaLoginRequiredView):
    privateConfiguration = PrivateConfiguration

    def patch(self, request, *args, **kwargs):
        data = QueryDict(request.body)
        network_id = data.get('network_id')
        host_id = data.get('host_id')
        conf_obj = self.privateConfiguration.objects.first()
        if conf_obj:
            try:
                data = {
                    'network_id': network_id
                }
                post_url = "{}/private/update-host-network/{}".format(conf_obj.redtree_base_url, host_id)
                response = requests.patch(
                    post_url,
                    data=data,
                    headers=get_private_request_header()
                )
            except:
                response = {
                    "status": False,
                    "status_code": 504,
                    "message": "Unable to update network no reponse from host.",
                    "data": []
                }
                return JsonResponse(response, safe=False)
            if response.status_code == 200:
                response_data = response.json()
            elif response.status_code == 400:
                response_data = response.json()
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
                    "message": "Unable to get reponse from host.",
                    "data": []
                }
            return JsonResponse(response_data, safe=False)
        response_data = {
            "status": False,
            "status_code": 500,
            "message": "No configuration set for host.",
            "data": []
        }
        return JsonResponse(response_data, safe=False)


class NetworkVulnerabilitiesDetailView(TwoFaLoginRequiredView):
    template_name = "purpleleaf_app/network-vulnerabilities-detail.html"
    context = dict()

    def get(self, request, *args, **kwargs):
        log_user_activity(request)
        network_id = kwargs.get('network_id')
        conf_obj = PrivateConfiguration.objects.first()
        if conf_obj:
            headers = {'data-auth-key': conf_obj.data_auth_key}
            request_url = "{}/private/vulnerabilities/network/{}".format(
                conf_obj.redtree_base_url,
                network_id
            )
        try:
            response = requests.get(
                request_url,
                headers=headers
            )
        except Exception as e:
            response = None
        if response and response.status_code == 200:
            response_data = response.json()
            self.context['vulnerabilities'] = response_data.get("sorted_vulnerabilities")
            self.context['network'] = response_data.get("network")
        else:
            self.context['vulnerabilities'] = None
            self.context['network'] = None
        return render(
            request,
            self.template_name,
            self.context
        )


class VulnerabilityNetworkDetailView(TwoFaLoginRequiredView):
    template_name = "purpleleaf_app/affectedHosts.html"
    context = dict()

    def get(self, request, *args, **kwargs):
        log_user_activity(request)
        network_id = kwargs.get('network_id')
        virtue_id = kwargs.get('virtue_id')
        conf_obj = PrivateConfiguration.objects.first()
        if conf_obj:
            headers = {'data-auth-key': conf_obj.data_auth_key}
            request_url = "{}/private/vulnerabilities/network/{}/{}".format(
            conf_obj.redtree_base_url,
            network_id,
            virtue_id
            )
        try:
            response = requests.get(
            request_url,
            headers=headers
            )
        except Exception as e:
            response = None
        if response:
            response_data = response.json()
            self.context['hosts'] = response_data.get('affected_hosts')
            self.context['banner'] = response_data.get('banner')
            self.context['vulnerability'] = response_data.get('vulnerability')
            self.context['evidence_count'] = response_data.get('evidence_count')

        else:
            self.context['hosts'] = None
            self.context['banner'] = None
            self.context['vulnerability'] = None
            self.context['evidence_count'] = None
        return render(
            request,
            self.template_name,
            self.context
        )


class EncryptionView(TwoFaLoginRequiredView):
    template_name = 'purpleleaf_app/encryption.html'
    context = dict()

    def get(self, request, *args, **kwargs):
        log_user_activity(request)
        conf_obj = PrivateConfiguration.objects.first()
        if conf_obj:
            headers = {'data-auth-key': conf_obj.data_auth_key}
            request_url = "{}/private/encryption".format(
            conf_obj.redtree_base_url,
            )
        try:
            response = requests.get(
                request_url,
                headers=headers
            )
        except Exception as e:
            response = None
        if response and response.status_code == 200:
            response_data = response.json()
            self.context['total_ciphers'] = response_data.get("total_ciphers")
            self.context['total_certificates'] = response_data.get("total_certificates")
            self.context['ciphers'] = response_data.get("ciphers")
            self.context['certificates'] = response_data.get("certificate_data")
            self.context['host'] = None
            self.context['https_enc_count'] = response_data.get("https_enc_count")
            self.context['ssh_enc_count'] = response_data.get("ssh_enc_count")
        else:
            self.context['total_ciphers'] = None
            self.context['total_certificates'] = None
            self.context['ciphers'] = None
            self.context['certificates'] = None
            self.context['host'] = None
            self.context['https_enc_count'] = None
            self.context['ssh_enc_count'] = None

        return render(
            request,
            self.template_name,
            self.context
        )


class EncryptionProtocolDetailView(TwoFaLoginRequiredView):
    template_name = 'purpleleaf_app/encryptiondetail.html'

    def get(self, request, *args, **kwargs):
        protocol = kwargs.get('protocol')
        conf_obj = PrivateConfiguration.objects.first()
        if conf_obj:
            headers = {'data-auth-key': conf_obj.data_auth_key}
            request_url = "{}/private/encryption/proto/{}".format(
            conf_obj.redtree_base_url,
            protocol
            )
        try:
            response = requests.get(
                request_url,
                headers=headers
            )
        except Exception as e:
            response = None
        if response:
            response_data = response.json()
            context={
                'protocol': protocol,
                'host_ciphers': response_data.get("host_ciphers"),
                'supported_ciphers': response_data.get("supported_ciphers")

            }
        else:
            context={
                'protocol': None,
                'ciphers': None
            }
        return render(
            request,
            self.template_name,
            context
            )


class AwsAssetsCreateListView(TwoFaLoginRequiredView):
    configuration = Configuration
    privateConfiguration = PrivateConfiguration

    def post (self, request, *args ,**kwargs):
        request_ip = get_request_ip(request)
        conf_obj = self.privateConfiguration.objects.first()
        if conf_obj:
            aws_access_token_id = request.POST.get('aws_access_token_id')
            aws_secret_token_id = request.POST.get('aws_secret_token_id')
            aws_access_token_description = request.POST.get('aws_access_token_description')
            post_url = "{}/private/aws-assets".\
                format(conf_obj.redtree_base_url)
            data = {
                'client_aws_access_token': aws_access_token_id,
                'client_aws_secret_token': aws_secret_token_id,
                'token_description': aws_access_token_description 
            }
            try:
                response = requests.post(
                    post_url,
                    json=data,
                    headers=get_private_request_header()
                )
            except:
                response = {
                    "status": False,
                    "status_code": 504,
                    "message": "Unable to add aws assets no reponse from host.",
                    "data": []
                }
                return JsonResponse(response, safe=False)
            if response.status_code == 201:
                response_data = response.json()
            elif response.status_code == 400:
                response_data = response.json()
            elif response.status_code == 403:
                response_data = {
                    "status": False,
                    "status_code": 403,
                    "message": "Unable to authenticate the processed request.",
                    "data": []
                }
            return JsonResponse(response_data, safe=False)
        else:
            response_data = {
                "status": False,
                "status_code": 500,
                "message": "Unable to get reponse from host.",
                "data": []
            }
        return JsonResponse(response_data, safe=False)


class NotificationsView(TwoFaLoginRequiredView):
    notifications_model_class = Notifications
    template_name = 'purpleleaf_app/notifications.html'

    def get(self, request, *args, **kwargs):
        self.notifications_model_class.objects.all().update(seen=True)
        allNotifications = self.notifications_model_class.objects.all().order_by('-id')
        context = {'allnotifications':allNotifications}
        return render(
            request,
            self.template_name,
            context
        )


def error_403_view(request, exception):
    return render(request,'purpleleaf_app/403.html')


def error_404_view (request):
    return render(request,'purpleleaf_app/404.html')


def e_handler500(request):
    return render(request,'purpleleaf_app/500.html')


class ApplicationByIdView(TwoFaLoginRequiredView):
    template_name = 'purpleleaf_app/application_detail.html'
    context = {
        'title': "Application Vulnerabilities"
    }

    def get(self, request, *args, **kwargs):
        application_id = kwargs.get('application_id')
        conf_obj = PrivateConfiguration.objects.first()
        if conf_obj:
            request_url = "{}/private/applications/{}".format(
                conf_obj.redtree_base_url,
                application_id
            )
            try:
                response = requests.get(
                    request_url,
                    headers=get_private_request_header()
                )
            except Exception as e:
                response = None
            if response and response.status_code == 200:
                response_data = response.json()
                self.context['datalist'] = response_data.get('app_vul_obj')
                self.context['app_obj'] = response_data.get('app_obj')
            else:
                self.context['datalist'] = None
                self.context['app_obj'] = None
        return render(request, self.template_name, self.context)


class ReportDetailView(TwoFaLoginRequiredView):
    response = dict()

    def get(self, request, *args, **kwargs):
        log_user_activity(request)
        conf_obj = PrivateConfiguration.objects.first()
        if conf_obj:
            request_url = "{}/private/report/{}".format(
                conf_obj.redtree_base_url,
                kwargs.get('report_id')
            )
            try:
                response = requests.get(
                    request_url,
                    headers=get_private_request_header()
                )
            except Exception as e:
                response = None
            if response and response.status_code == 200:
                response_data = response.json()
                self.response['link'] = response_data.get('file_key')
            else:
                self.response['link'] = None   
            return JsonResponse(self.response, safe=False)
        return JsonResponse(False, safe=False)

    def delete(self, request, *args, **kwargs):
        conf_obj = PrivateConfiguration.objects.first()
        if conf_obj:
            request_url = "{}/private/report/{}".format(
                conf_obj.redtree_base_url,
                kwargs.get('report_id')
                )
            try:
                response = requests.delete(
                    request_url,
                    headers=get_private_request_header()
                )
            except Exception as e:
                response = None
            if response and response.status_code == 200:
                return JsonResponse(True, safe=False)        
        return JsonResponse(False, safe=False)


class EncryptionSsh(TwoFaLoginRequiredView):
    template_name = 'purpleleaf_app/encryption-ssh.html'
    context = dict()

    def get(self, request, *args, **kwargs):
        log_user_activity(request)
        conf_obj = PrivateConfiguration.objects.first()
        if conf_obj:
            headers = {'data-auth-key': conf_obj.data_auth_key}
            get_url = "{}/private/ssh-encryption".format(conf_obj.redtree_base_url)
            try:
                response = requests.get(get_url, headers=headers)
            except Exception as e:
                response = None
            if response and response.status_code == 200:
                response_data = response.json()
                self.context['encryption'] = response_data
            else:
                self.context['encryption'] = None
        return render(
            request,
            self.template_name,
            self.context
            )


class EncryptionCipher(TwoFaLoginRequiredView):
    template_name = 'purpleleaf_app/encryptioncipher.html'
    context = dict()

    def get(self, request, *args, **kwargs):
        log_user_activity(request)
        cipher = kwargs.get('cipher')
        conf_obj = PrivateConfiguration.objects.first()
        if conf_obj:
            headers = {'data-auth-key': conf_obj.data_auth_key}
            request_url = "{}/private/encryption/{}".format(conf_obj.redtree_base_url,cipher)
            try:
                response = requests.get(request_url, headers=headers)
            except Exception as e:
                response = None
            if response:
                response_data = response.json()
                self.context['ciphers'] = response_data.get("ciphers")
                self.context['cipher_name'] = cipher
            else:
                self.context['ciphers'] = None
                self.context['cipher_name'] = None
        else:
            self.context['ciphers'] = None
            self.context['cipher_name'] = None
        return render(
            request,
            self.template_name,
            self.context
            )


class EncryptionSshDetailView(TwoFaLoginRequiredView):
    template_name = "purpleleaf_app/ssh-encryption-detail.html"
    context = dict()

    def get(self, request, *args, **kwargs):
        log_user_activity(request)
        cipher_type = kwargs.get('type')
        cipher = kwargs.get('cipher')
        conf_obj = PrivateConfiguration.objects.first()
        if conf_obj:
            headers = {'data-auth-key': conf_obj.data_auth_key}
            request_url = "{}/private/ssh-encryption/{}/{}".format(
                conf_obj.redtree_base_url,
                kwargs.get('type'),
                kwargs.get('cipher')
                )
            try:
                response = requests.get(
                    request_url,
                    headers=headers
                )
            except Exception as e:
                response = None
            if response:
                response_data = response.json()
                self.context['ciphers'] = response_data
            else:
                self.context['ciphers'] = None
        else:
            self.context['ciphers'] = None
        self.context['cipher'] = cipher
        return render(
            request,
            self.template_name,
            self.context
        )


class ApplicationDetailView(TwoFaLoginRequiredView):

    def delete(self, request, *args, **kwargs):
        request_ip = get_request_ip(request)
        id = kwargs.get('id')
        conf_obj = PrivateConfiguration.objects.first()
        post_url = "{}/private/application/{}".format(conf_obj.redtree_base_url, id)
        time_stamp = timezone.now().strftime('%s')
        data = {
            'event_data': {
                'event_type': 'delete_application',
                'time_stamp': time_stamp,
                'username': request.user.email,
                'ip': request_ip
            }
        }
        try:
            response = requests.delete(
                post_url,
                headers=get_private_request_header(),
                json=data
            )
        except:
            response_data = {
                'status': False,
                'message': "Unable to process request, No response from host."
            }
            return JsonResponse(
                response_data,
                safe=False
                )
        if response.status_code == 200:
            response_data = response.json()
        elif response.status_code == 404:
            response_data = response.json()
        return JsonResponse(
            response_data,
            safe=False
            )


class AWSKeyStatusDetailView(TwoFaLoginRequiredView):

    def get(self, request, *args, **kwargs):
        aws_id = kwargs.get('id')
        response_data = dict()
        conf_obj = PrivateConfiguration.objects.first()
        if conf_obj:
            try:
                post_url = "{}/private/aws/aws-key-status/{}".\
                    format(conf_obj.redtree_base_url,aws_id)
                response = requests.get(
                    post_url,
                    headers=get_private_request_header()
                )
            except:
                response = {
                    "status": False,
                    "status_code": 504,
                    "message": "Unable to fetch aws key status no reponse from host.",
                    "data": []
                }
                return JsonResponse(response, safe=False)
            if response.status_code == 200:
                response_data = response.json()
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
                    "message": "Unable to get reponse from host.",
                    "data": []
                }
            return JsonResponse(response_data, safe=False)

    def delete(self, request, *args, **kwargs):
        aws_id = kwargs.get('id')
        response_data = dict()
        conf_obj = PrivateConfiguration.objects.first()
        if conf_obj:
            try:
                post_url = "{}/private/aws/aws-key-status/{}".\
                    format(conf_obj.redtree_base_url,aws_id)
                response = requests.delete(
                    post_url,
                    headers=get_private_request_header()
                )
            except:
                response = {
                    "status": False,
                    "status_code": 504,
                    "message": "Unable to fetch aws key status no reponse from host.",
                    "data": []
                }
                return JsonResponse(response, safe=False)
        if response.status_code == 200:
            response_data = response.json()
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
                "message": "Unable to get reponse from host.",
                "data": []
            }
        return JsonResponse(response_data, safe=False)


class ApplicationVulnerabilityDetailView(TwoFaLoginRequiredView):
    template_name = "purpleleaf_app/application_vulnerability_detail.html"
    error_template = "purpleleaf_app/404.html"
    context = dict()

    def get(self, request, *args, **kwargs):
        app_id = kwargs.get('application_id')
        virtue_id = kwargs.get('virtue_id')
        conf_obj = PrivateConfiguration.objects.first()
        if conf_obj:
            headers = {'data-auth-key' : conf_obj.data_auth_key}
            request_url = "{}/private/application/{}/vulnerabilities/{}".format(
                conf_obj.redtree_base_url,
                app_id,
                virtue_id
            )
            try:
                response = requests.get(
                    request_url,
                    headers=headers
                )
            except Exception as e:
                response = None
            if response and response.status_code == 200:
                response_data = response.json()
                self.context['vul_obj'] = response_data.get('application_vul_obj')
                self.context['app_vul'] = response_data.get('application_vul')
                
                return render(
                    request,
                    self.template_name,
                    self.context
                )
        messages.add_message(request, messages.WARNING, "Application Vulnerability does not exists.")
        return render(
            request,
            self.error_template,
            self.context
        )


class HostEncryptionCipherDetail(TwoFaLoginRequiredView):
    template_name = 'purpleleaf_app/encryption.html'
    context = dict()

    def get(self, request, *args, **kwargs):
        log_user_activity(request)
        conf_obj = PrivateConfiguration.objects.first()
        if conf_obj:
            headers = {'data-auth-key': conf_obj.data_auth_key}
            request_url = "{}/private/encryption/?host={}".format(
            conf_obj.redtree_base_url,
            kwargs.get('host_id')
            )
        try:
            response = requests.get(
                request_url,
                headers=headers
            )
        except Exception as e:
            response = None
        if response and response.status_code == 200:
            response_data = response.json()
            self.context['ciphers'] = response_data.get("ciphers")
            self.context['host'] = response_data.get("host")
        else:
            self.context['ciphers'] = None
            self.context['host'] = None
        return render(
            request,
            self.template_name,
            self.context
        )


class VulnerabilityHostView(TwoFaLoginRequiredView):
    template_name = 'purpleleaf_app/vulnerabilities_host.html'
    context = dict()

    def get(self, request, *args, **kwargs):
        host_id = kwargs.get('host_id')
        log_user_activity(request)
        conf_obj = PrivateConfiguration.objects.first()
        if conf_obj:
            request_url = "{}/private/vulnerabilities/host/{}".format(
                conf_obj.redtree_base_url,
                host_id
            )
            try:
                response = requests.get(
                    request_url,
                    headers=get_private_request_header()
                )
            except Exception as e:
                response = None
            if response and response.status_code == 200:
                response_data = response.json()
                data = response_data.get('data')
                self.context['host_id']=host_id
                self.context['data'] = data
            else:
                self.context['data'] = None
        return render(request, self.template_name, self.context)


class HostVulnerabilitiesDetailView(TwoFaLoginRequiredView):
    configuration_model_class = Configuration
    template_name = "purpleleaf_app/vulnerabilities_host_detail.html"
    error_template = "purpleleaf_app/404.html"
    context = dict()

    def get(self, request, *args, **kwargs):
        log_user_activity(request)
        host_id = kwargs.get('host_id')
        virtue_id = kwargs.get('virtue_id')
        conf_obj = PrivateConfiguration.objects.first()
        if conf_obj:
            headers = {'data-auth-key': conf_obj.data_auth_key}
            request_url = "{}/private/vulnerabilities/host/{}/{}".format(
                conf_obj.redtree_base_url,
                host_id,
                virtue_id
            )
        try:
            response = requests.get(
                request_url,
                headers=headers
            )
        except Exception as e:
            response = None
        if response and response.status_code == 200:
            response_data = response.json()
            self.context['hosts'] = response_data.get('affected_hosts')
            self.context['banner'] = response_data.get('banner')
            self.context['vulnerability'] = response_data.get('vulnerability')
        else:
            self.context['hosts'] = None
            self.context['banner'] = None
            self.context['vulnerability'] = None
        return render(
            request,
            self.template_name,
            self.context
        )


class CloudDetailView(TwoFaLoginRequiredView):
    template_name = 'purpleleaf_app/cloud.html'
    context = {
        'title': "Cloudstorage"
    }

    def get(self, request, *args, **kwargs):
        log_user_activity(request)
        conf_obj = PrivateConfiguration.objects.first()
        if conf_obj:
            try:
                post_url = "{}/private/cloud".format(
                    conf_obj.redtree_base_url
                )
                response = requests.get(
                    post_url,
                    headers=get_private_request_header()
                )
            except:
                response = None
            if response and response.status_code == 200:
                response_data = response.json().get('data')
                self.context['cloud_storage_data'] = response_data.get('cloud_storage_data')
                self.context['cloud_storage_gcp_data'] = response_data.get('gcp_serializer_data')
                self.context['cloud_storage_azure_data'] = response_data.get('azure_serializer_data')
                self.context['aws_api_data'] = response_data.get('aws_api_data')
                self.context['aws_rds_data'] = response_data.get('aws_rds_data')
                self.context['aws_domains_data'] = response_data.get('aws_domains_data')
                self.context['s3_bucket_count'] = response_data.get('s3_bucket_count')
                self.context['s3_pass_percentage'] = response_data.get('s3_pass_percentage')
                self.context['aws_token_loaded_status'] = response_data.get('aws_token_loaded_status')
                self.context['aws_api_gateway_count'] = response_data.get('aws_api_gateway_count')
                self.context['aws_rds_databases_count'] = response_data.get('aws_rds_databases_count')
            else:
                self.context['cloud_storage_data'] = None
                self.context['cloud_storage_gcp_data'] = None
                self.context['cloud_storage_azure_data'] = None
                self.context['aws_api_data'] = None
                self.context['aws_rds_data'] = None
                self.context['aws_domains_data'] = None
                self.context['s3_bucket_count'] = None
                self.context['s3_pass_percentage'] = None
                self.context['aws_token_loaded_status'] = None
                self.context['aws_api_gateway_count'] = None
                self.context['aws_rds_databases_count'] = None
        return render(
            request,
            self.template_name,
            self.context
        )


class CloudAssetDetailView(TwoFaLoginRequiredView):
    template_name = 'purpleleaf_app/cloud_asset_detail.html'
    context = {
        'title': "Cloudstorage"
    }

    def get(self, request, *args, **kwargs):
        log_user_activity(request)
        conf_obj = PrivateConfiguration.objects.first()
        cloud_asset_id = kwargs.get('cloud_asset_id')
        if conf_obj:
            try:
                post_url = "{}/private/cloud/s3/{}".format(
                    conf_obj.redtree_base_url,
                    cloud_asset_id

                )
                response = requests.get(
                    post_url,
                    headers=get_private_request_header()
                )
            except:
                response = None
            if response and response.status_code == 200:
                response_data = response.json().get('data')
                self.context['cloud_asset_data'] = response_data.get('cloud_asset_data')
                self.context['cloud_storage_files'] = response_data.get('cloud_storage_files')
            else:
                self.context['cloud_asset_data'] = None
                self.context['cloud_storage_files'] = None
        return render(
            request,
            self.template_name,
            self.context
        )


class UpdateApplicationScanStatusView(TwoFaLoginRequiredView):
    privateconfig_model_class = PrivateConfiguration
    config_model_class = Configuration

    def post(self, request, *args, **kwargs):
        app_scan_status = request.POST.get('scan_status')
        application_id = kwargs.get('application_id')
        conf_obj = self.privateconfig_model_class.objects.first()
        if app_scan_status == "Active":
            scan_status = "Inactive"
        elif app_scan_status == "Inactive":
            scan_status = "Active"
        data = {
            'scan_status': scan_status,
            'application_id': application_id
        }
        if conf_obj:
            try:
                post_url = "{}/private/application/{}/toggle_active".format(
                    conf_obj.redtree_base_url,
                    application_id,
                    scan_status
                )
                response = requests.post(
                    post_url,
                    data=data,
                    headers=get_private_request_header()
                )
            except:
                response = {
                    "status": False,
                    "status_code": 504,
                    "message": "Unable to update active status no reponse from host.",
                    "data": []
                }
                return JsonResponse(response, safe=False)
            if response.status_code == 200:
                response_data = response.json()
            elif response.status_code == 400:
                response_data = response.json()
            elif response.status_code == 403:
                response_data = {
                    "status": False,
                    "status_code": 403,
                    "message": "Unable to authenticate the processed request.",
                    "data": []
                }
            return JsonResponse(response_data, safe=False)
        else:
            response_data = {
                "status": False,
                "status_code": 500,
                "message": "Unable to get reponse from host.",
                "data": []
            }
        return JsonResponse(response_data, safe=False)


class HostDetailView(TwoFaLoginRequiredView):
    template_name = 'purpleleaf_app/host_detail.html'
    context = {
        'title': "Host Detail"
    }

    def get(self, request, *args, **kwargs):
        host_id = kwargs.get('host_id')
        conf_obj = PrivateConfiguration.objects.first()
        if conf_obj:
            request_url = "{}/private/host/{}".format(
                conf_obj.redtree_base_url,
                host_id
            )
            headers = get_private_request_header()
            headers['Content-Type'] = 'application/json'
            try:
                response = requests.get(
                    request_url,
                    headers=get_private_request_header()
                )
            except Exception as e:
                response = None
            if response and response.status_code == 200:
                response_data = response.json()
                host_record = response_data['host']
                self.context['mapdata'] = host_record.get('whois_detail').get('map_data')
                self.context['host_obj'] = host_record
                self.context['open_ports'] = host_record.get('open_ports')
                self.context['whois_detail'] = host_record.get('whois_detail').get('basic_record')
                self.context['vulnerabilities'] = host_record.get('vulnerabilities')
                self.context['applications'] = host_record.get('applications')
            else:
                self.context['host_obj'] = None

        return render(request, self.template_name, self.context)


class HostsWhoisMapView(TwoFaLoginRequiredView):

    def get(self, request, *args, **kwargs):
        conf_obj = PrivateConfiguration.objects.first()
        if conf_obj:
            try:
                post_url = "{}/private/host/whois".format(conf_obj.redtree_base_url)
                response = requests.get(
                    post_url,
                    headers=get_private_request_header()
                )
            except:
                response = {
                    "status": False,
                    "status_code": 504,
                    "message": "Unable to fetch whois-map data no reponse from whois-map.",
                    "data": []
                }
                return JsonResponse(response, safe=False)
            if response.status_code == 200:
                response_data = response.json()
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
                    "message": "Unable to get reponse from host.",
                    "data": []
                }
            return JsonResponse(response_data, safe=False)


class EncryptionChartView(TwoFaLoginRequiredView):

    def get(self, request, *args):
        conf_obj = PrivateConfiguration.objects.first()
        if conf_obj:
            try:
                post_url = "{}/private/api/charts/encryption".format(
                    conf_obj.redtree_base_url
                )
                response = requests.get(
                    post_url,
                    headers=get_private_request_header()
                )
            except:
                response = {
                    "status": False,
                    "status_code": 504,
                    "message": "Unable to ciphers chart data.",
                    "data": []
                }
                return JsonResponse(response, safe=False)
            if response.status_code == 200:
                data_ = response.json()
                response_data = {
                    'status': True,
                    'status_code': 200,
                    'message': 'Data processed successfully.',
                    'data': data_
                }
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
                    "message": "Unable to get reponse from host.",
                    "data": []
                }
            return JsonResponse(response_data, safe=False)


class EncryptionCipherView(TwoFaLoginRequiredView):
    template_name = 'purpleleaf_app/encryption_cipher.html'
    context = dict()

    def get(self, request, *args, **kwargs):
        log_user_activity(request)
        conf_obj = PrivateConfiguration.objects.first()
        if conf_obj:
            headers = {'data-auth-key': conf_obj.data_auth_key}
            request_url = "{}/private/encryption/ciphers/".format(
            conf_obj.redtree_base_url,
            )
        try:
            response = requests.get(
                request_url,
                headers=headers
            )
        except Exception as e:
            response = None
        if response and response.status_code == 200:
            response_data = response.json()
            self.context['ciphers'] = response_data.get("ciphers")
        else:
            self.context['ciphers'] = None

        return render(
            request,
            self.template_name,
            self.context
        )


class EncryptionCertificateView(TwoFaLoginRequiredView):
    template_name = 'purpleleaf_app/encryption_certificates.html'
    context = dict()

    def get(self, request, *args, **kwargs):
        log_user_activity(request)
        conf_obj = PrivateConfiguration.objects.first()
        if conf_obj:
            headers = {'data-auth-key': conf_obj.data_auth_key}
            request_url = "{}/private/encryption/certificates/".format(
            conf_obj.redtree_base_url,
            )
        try:
            response = requests.get(
                request_url,
                headers=headers
            )
        except Exception as e:
            response = None
        if response and response.status_code == 200:
            response_data = response.json()
            self.context['certificates'] = response_data.get("certificate_data")
        else:
            self.context['certificates'] = None

        return render(
            request,
            self.template_name,
            self.context
        )
