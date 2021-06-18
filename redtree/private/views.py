# -*- coding: utf-8 -*-
from __future__ import unicode_literals, division
from rest_framework.generics import CreateAPIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from redtree_app.models import *
from  playground.models import *
from .serializers import *
from django.conf import settings
from redtree_app.ip_validator import (
    get_host_type,
    get_hosts_list,
    get_host_network_type,
    hosts_count,
    get_host_count,
    check_host_exists,
)
from django.db.models import Q
from redtree_app.alerts import send_host_mail, send_mail
import base64
import os
from datetime import datetime, timedelta
from collections import Counter
from utils.permissions import (
    is_valid_request,
    CustomAuthentication
)
from django.db.models import Count
from django.core.mail import EmailMessage
from utils.helpers import (
    get_risk_factor,
    get_sorted_cipher,
    get_sorted_vulnerabilities,
    get_sorted_host_vulnerabilities,
    application_vulnerability_count
)
from rest_framework.permissions import IsAuthenticated
from django.core import serializers
from rest_framework.exceptions import (
    NotFound,
)
from redtree_app.tasks import (
    send_host_add_mail,
    send_loopback_ip_add_mail,
    check_aws_asset_status,
    send_application_add_mail
)
from django.core.validators import URLValidator, validate_ipv46_address
from django.core.exceptions import ValidationError
from urlparse import urlsplit
from utils.WhoisScanHelper import (
    ips_whois_scan,
    ips_whois_host
)
from utils.views import (
    get_strength_count,
    get_ciphers_strength,
    get_paginated_data,
)
from rest_framework.pagination import PageNumberPagination
from collections import OrderedDict
# Create your views here.

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


class RetestVulnerabilityApiView(APIView):
    """
    This will create the retest of given vulnerability
    """
    authentication_classes = (CustomAuthentication,)
    permission_classes = (IsAuthenticated,)

    def get_object(self):
        """
        Retrive the vulnerability object
        """
        vul_id = self.kwargs.get('vul_id')
        try:
            return Vulnerability.objects.get(id=vul_id)
        except:
            response_data = {
                'status': False,
                'message': "No such vulnerability available please refresh the page."
            }
            raise NotFound(response_data)

    def post(self, request, *args, **kwargs):
        """
        ## Note: 
        We are providing custom auth for the api's so add "data-auth-key" in the request header
        ### Response(Error with no key)
        ```
        {
            "detail": "Authentication credentials were not provided."
        }
        ```
        ### Response(Error with invalid key)
        ```
        {
            "detail": "Invalid Authentication key provided"
        }
        ```
        ### Response(Success)
        ```
        {
            "status": true,
            "status_code": 200,
            "message": "Retest request generated successfully.",
            "data": {
                "id": 45,
                "title": "This is ye",
                "formatted_description": "<p>test</p>",
                "formatted_remediation": "<p>test</p>",
                "formatted_evidence": "<p>test</p>",
                "virtue_id": 50001,
                "port": "80",
                "host_ip": "10.3.6",
                "banner": null
            }
        }
        ```
        ### Response(Error)
        ```
        {
            "status": "False",
            "message": "No such vulnerability available please refresh the page."
        }
        ```
        """
        vul_obj = self.get_object()
        try:
            retest_obj = vul_obj.retest
        except RetestVulnerabilities.DoesNotExist:
            retest_obj = RetestVulnerabilities.objects.create(
                vulnerability=vul_obj
            )
        retest_obj.status = "Requested"
        retest_obj.host = vul_obj.host_ip
        retest_obj.save()
        serializer = VulnerabilityDetailSerailizer(vul_obj)
        response_data = {
            'status_code': 200,
            'status': True,
            'message': 'Retest request generated successfully.',
            'data': serializer.data
        }
        return Response(
            response_data,
            status=status.HTTP_200_OK
        )


class ScanStatusApiView(APIView):
    authentication_classes = (CustomAuthentication,)
    permission_classes = (IsAuthenticated,)
    serializer_class = ConfigurationsSerializer

    def post(self, request, *args, **kwargs):
        notification_list = list(NotificationEmails.objects.values_list(
                'email', flat=True
            ))
        client_obj = ClientConfiguration.objects.first()
        conf_obj = Configuration.objects.first()
        if not conf_obj:
            Configuration.objects.create()
        conf = Configuration.objects.first()
        if conf.scanning_status:
            data = {
                'scanning_status': False
            }
        elif not conf.scanning_status:
            data = {
                'scanning_status': True
            }
        serializer = self.serializer_class(instance=conf, data=data)
        if serializer.is_valid():
            serializer.save()
            if client_obj:
                try:
                    if conf.scanning_status:
                        html_content = "[{0}]Scanning is Enabled".format(
                            client_obj.client_name
                        ) 
                        subject = "[{0}] Scanning is Enabled".format(
                            client_obj.client_name
                        ) 
                    else:
                        html_content = "[{0}]Scanning is disabled".format(
                            client_obj.client_name
                        )
                        subject = "[{0}] Scanning is Disabled".format(
                            client_obj.client_name
                        )
                    reciever = notification_list
                    send_mail(reciever, subject, html_content)
                except:
                    pass
            data = {
                'data': serializer.data,
                'status': True,
                'status_code': 200,
                'message': "Scanning status updated successfully."

            }
            return Response(data, status=status.HTTP_200_OK)
        data = {
            'data': [],
            'status': False,
            'status_code': 200,
            'message': "Unable to update Scanning status."
        }
        return Response(data, status=status.HTTP_400_BAD_REQUEST)


class ApplicationsListAPiView(APIView):
    authentication_classes = (CustomAuthentication,)
    permission_classes = (IsAuthenticated,)
    serializer_class = ApplicationSerializer
    event_serializer_class = RedtreeEventHistorySerializer

    def ip_validate(self , url):
        try:
            if url.startswith('http'):
                url = urlsplit(url)
                netlocc = url.netloc
                url = netlocc.split(':')
                app_url = url[0]
            else:
                url = url.split(':')
                app_url = url[0]
            validate_ipv46_address(app_url)
            return True
        except:
            return False


    def url_validate(self , url):
        validater = URLValidator(schemes=('http', 'https', 'ftp', 'ftps', 'rtsp', 'rtmp', 'www'))
        try:
            validater(url)
            return True
        except:
            return False

    def get(self, request, *args, **kwargs):
        applications = Applications.objects.all().order_by('-id')
        serializer = self.serializer_class(
            applications,
            many=True
        )
        return Response(
            serializer.data,
            status=status.HTTP_200_OK
        )



    def post(self, request, *args, **kwargs):
        """
        ## Note: 
        We are providing custom auth for the api's so add "data-auth-key" in the request header
        ### Response(Error with no key)
        ```
        {
            "detail": "Authentication credentials were not provided."
        }
        ```
        ### Response(Error with invalid key)
        ```
        {
            "detail": "Invalid Authentication key provided"
        }
        ```
        ### Body
        ```
        {
            'application_url': 'test',
            'network_type': 'External',
            'event_data': {
                'username': 'rajinder.ameo@gmail.com',
                'time_stamp': '2019-04-08 11:40 AM',
                'event_type': 'add_application',
                'ip': '127.0.0.1'
            }
        }

        ```
        ### Response(Success)
        ```
        {
            'status': True,
            'status_code': 201,
            'message': 'Application Added successfully.',
            'data': {
                'application_url': 'test',
                'id': 689,
                'network_type': 'External'
            }
        }

        ```
        ### Response(Error)
        ```
        {
            "status": false,
            "status_code": 400,
            "message": "Unable to add Application.",
            "errors": {
                "application_url": [
                    "This field is required."
                ],
                "network_type": [
                    "This field is required."
                ]
            }
        }
        ```
        ### Response(Error)
        ```
        {
            "status": false,
            "status_code": 400,
            "message": "Unable to add Application.",
            "errors": "Application already exists."
        }
        ```
        """
        data = request.data.copy()
        url = data['application_url']
        ip_validate = self.ip_validate(url)
        url_validate = self.url_validate(url)
        if ip_validate == True:
            url_status = "valid"
        elif url_validate == True:
            url_status = "valid"
        else:
            url_status = "invalid"

        event_data = data.get('event_data')
        serializer = self.serializer_class(data=data)
        if url_status == "valid":
            if serializer.is_valid():
                serializer.save()
                created_applications = list()
                application_url = serializer.data.get('application_url')
                created_applications.append('<br>' + application_url)
                send_application_add_mail(application_urls=created_applications)
                if event_data:
                    event_data['data'] = application_url
                    event_serializer = self.event_serializer_class(
                        data=event_data
                    )
                    if event_serializer.is_valid():
                        event_serializer.save()
                response = {
                    'status': True,
                    'message': "Application Added successfully.",
                    'status_code': 201,
                    'data': serializer.data
                }
                return Response(
                    response,
                    status=status.HTTP_201_CREATED
                )
            response = {
                'status': False,
                'message': "Unable to add Application.",
                'status_code': 400,
                'errors': serializer.errors
            }
        else:
            notification_email_objs = NotificationEmails.objects.values_list(
                'email', flat=True
            )
            notification_list = [str(email) for email in notification_email_objs]
            reciever = notification_list
            subject = "An invalid URL has been rejected"
            html_content = "An invalid Application is rejected <BR><BR> username : {},<BR>URL added : {},<BR>IP address : {}".\
                format(
                    event_data["username"],url,
                    event_data["ip"]
                )
            send_mail(reciever, subject, html_content)
            response = {
                'status': False,
                'message': "Unable to add Application.",
                'status_code': 400,
                'errors': "The application does not appear to be a valid URL."
            }
        return Response(
            response,
            status=status.HTTP_400_BAD_REQUEST
        )


class ApplicationsCreateListAPiView(APIView):
    """
    To create or list Application
    """
    authentication_classes = (CustomAuthentication,)
    permission_classes = (IsAuthenticated,)
    serializer_class = ApplicationSerializer
    detail_serializer_class = ApplicationDetailSerializer
    app_vul_chart_class = ApplicationVulnerabilityChart
    event_serializer_class = RedtreeEventHistorySerializer

    def get(self, request, *args, **kwargs):
        """
        ## Note: 
        We are providing custom auth for the api's so add "data-auth-key" in the request header
        ### Response(Error with no key)
        ```
        {
            "detail": "Authentication credentials were not provided."
        }
        ```
        ### Response(Error with invalid key)
        ```
        {
            "detail": "Invalid Authentication key provided"
        }
        ```
        ### Body
        ```
        {
            'application_url': 'test',
            'network_type': 'External',
            'event_data': {
                'username': 'rajinder.ameo@gmail.com',
                'time_stamp': '2019-04-08 11:40 AM',
                'event_type': 'add_application',
                'ip': '127.0.0.1'
            }
        }

        ```
        ### Response(Success)
        ```
        [
            {
                "id": 9,
                "application_title": null,
                "application_url": "apple.com",
                "s3_image": null,
                "critical_vulnerabilities": 0,
                "high_vulnerabilities": 0,
                "medium_vulnerabilities": 0,
                "low_vulnerabilities": 0,
                "scope": "black",
                "network_type": "External"
            },
            {
                "id": 10,
                "application_title": null,
                "application_url": "apple.com",
                "s3_image": null,
                "critical_vulnerabilities": 0,
                "high_vulnerabilities": 0,
                "medium_vulnerabilities": 0,
                "low_vulnerabilities": 0,
                "scope": "black",
                "network_type": "External"
            },
            {
                "id": 11,
                "application_title": null,
                "application_url": "apple.com",
                "s3_image": null,
                "critical_vulnerabilities": 0,
                "high_vulnerabilities": 0,
                "medium_vulnerabilities": 0,
                "low_vulnerabilities": 0,
                "scope": "black",
                "network_type": "External"
            }   
        ]
        ```
        """
        applications = Applications.objects.all().order_by('-scope','-id')

        if self.app_vul_chart_class.objects.all():
            chart_exist = True
        else:
            chart_exist = False
        af_data = get_paginated_data(
            self.detail_serializer_class,
            applications,
            request,
            self,
        )
        af_data['results'] = application_vulnerability_count(af_data['results'])
        af_data['chart_exist'] = chart_exist
        return Response(
            af_data,
            status=status.HTTP_200_OK
        )


class ApplicationsDetailApiView(APIView):
    """
    Delete Application
    """
    event_serializer_class = RedtreeEventHistorySerializer

    def get_objects(self):
        id = self.kwargs.get('id')
        try:
            return Applications.objects.get(id=id)
        except:
            response_data = {
                'status': False,
                'message': "No such application available please refresh the applications"
            }
            raise NotFound(response_data)

    def delete(self, request, *args, **kwargs):
        """
        ## Note: 
        We are providing custom auth for the api's so add "data-auth-key" in the request header
        ### Body
        ```
        {
            'event_data': {
                'username': 'rajinder.ameo@gmail.com',
                'time_stamp': '2019-04-08 11:13 AM',
                'event_type': 'delete_application',
                'ip': '127.0.0.1'
            }
        }
        ```
        ### Response(Error with no key)
        ```
        {
            "detail": "Authentication credentials were not provided."
        }
        ```
        ### Response(Error with invalid key)
        ```
        {
            "detail": "Invalid Authentication key provided"
        }
        ```
        ### Response(Success)
        ```
        {
            "status": true,
            "message": "Application removed successfully!"
        }
        ```
        """
        event_data = self.request.data.get('event_data')
        application_obj = self.get_objects()
        if event_data:
            event_data['data'] = application_obj.application_url
            serializer = self.event_serializer_class(data=event_data)
            if serializer.is_valid():
                serializer.save()
        application_obj.delete()
        response_data = {
            'status': True,
            'message': "Application removed successfully!"
        }
        return Response(
            response_data,
            status=status.HTTP_200_OK
        ) 
 

class DeleteHostsApi(APIView):
    """
    This is to delete hosts
    """
    authentication_classes = (CustomAuthentication,)
    permission_classes = (IsAuthenticated,)
    event_serializer_class = RedtreeEventHistorySerializer

    def get(self, request,*args, **kwargs):
        """
        ## Note: 
        We are providing custom auth for the api's so add "data-auth-key" in the request header
        ### Body
        ```
        {
            "host_ids": ["1105","1106"]
        }
        ```
        ### Response(Error with no key)
        ```
        {
            "detail": "Authentication credentials were not provided."
        }
        ```
        ### Response(Error with invalid key)
        ```
        {
            "detail": "Invalid Authentication key provided"
        }
        ```
        ### Response(Success)
        ```
        {
            "vul_count": 0,
            "ips_count": 44
        }
        ]
        ```
        """
        host_ids = request.data.get('host_ids')
        ipsCount = 0
        ip_count = 0
        hosts_count = 0
        hosts = UserHosts.objects.filter(id__in=host_ids)
        if hosts:
            hosts_count = hosts.aggregate(hosts_sum=Sum('count'))['hosts_sum']
        risks = ['High', 'Medium', 'Low', 'Note']
        vulCount = Vulnerability.objects.filter(
            host__user_host__id__in=host_ids,
            risk__in=risks
            ).count()
        response = {
            'status': True,
            'status_code': 200,
            'message': 'Count fetch successfully',
            'ips_count': hosts_count,
            'vul_count': vulCount
        }
        return Response(response, status=status.HTTP_200_OK)

    def delete(self, request,  *args, **kwargs):
        """
        ## Note: 
        We are providing custom auth for the api's so add "data-auth-key" in the request header
        ### Body
        ```
        {
            'host_ids': ['1254'],
            'event_data': {
                'username': 'rajinder.ameo@gmail.com',
                'time_stamp': '2019-04-08 11:13 AM',
                'event_type': 'delete_range',
                'ip': '127.0.0.1'
            }
        }
        ```
        ### Response(Error with no key)
        ```
        {
            "detail": "Authentication credentials were not provided."
        }
        ```
        ### Response(Error with invalid key)
        ```
        {
            "detail": "Invalid Authentication key provided"
        }
        ```
        ### Response(Success)
        ```
        {
            "status": true,
            "message": "Hosts removed successfully!"
        }
        ```
        """
        host_ids = self.request.data.get('host_ids')
        event_data = self.request.data.get('event_data')
        host_obj = UserHosts.objects.filter(id__in=host_ids)
        host_list = [str(item.host) for item in host_obj]
        deleted_hosts = ", ".join(map(str,host_list))
        host_obj.delete()
        if event_data:
            try:
                event_data['data'] = deleted_hosts
                serializer = self.event_serializer_class(data=event_data)
                if serializer.is_valid():
                    serializer.save()
            except:
                pass
        response_data = {
            'status': True,
            'message': "Hosts removed successfully!"
        }
        return Response(response_data, status=status.HTTP_200_OK)


class HostNetworkUpdateApi(APIView):
    """
    This is to update network of host
    """
    authentication_classes = (CustomAuthentication,)
    permission_classes = (IsAuthenticated,)
    serializer_class = UserHostsSerializer

    def get_host_object(self):
        host_id = self.kwargs.get('host_id')
        try:
            return UserHosts.objects.get(
                id=int(host_id)
            )
        except:
            response = {
                'status': False,
                'status_code': 404,
                'message': 'Host not found.'
            }
            raise NotFound(
                response,
                code=status.HTTP_404_NOT_FOUND
            )

    def get_network_object(self):
        network_id = self.request.data.get('network_id')
        try:
            return Networks.objects.get(
                id=int(network_id)
            )
        except:
            response = {
                'status': False,
                'status_code': 404,
                'message': 'Network not found.'
            }
            raise NotFound(
                response,
                code=status.HTTP_404_NOT_FOUND
            )

    def patch(self, request, *args, **kwargs):
        """
        ## Note: 
        We are providing custom auth for the api's so add "data-auth-key" in the request header
        ### Body
        ```
        {
            'network_id': 63
        }
        ```
        ### Response(Error with no key)
        ```
        {
            "detail": "Authentication credentials were not provided."
        }
        ```
        ### Response(Error with invalid key)
        ```
        {
            "detail": "Invalid Authentication key provided"
        }
        ```
        ### Response(Success)
        ```
        {
            "status": true,
            "status_code": 200,
            "message": "Network updated successfully.",
            "data": {
                "id": 1105,
                "network_type": "External",
                "network": 104,
                "network_name": "test",
                "network_id": 104,
                "host_address": "10.3.2.1-24",
                "host_track_info": true
            }
        }
        ```
        ### Response(Error)
        ```
        {
            "status": "False",
            "status_code": "404",
            "message": "Host not found."
        }
        ```
        """
        data = request.data.copy()
        host = self.get_host_object()
        network = self.get_network_object()
        ip_network_type = host.host_network_type
        network_type = network.network_type
        if ip_network_type == "Internal" and network_type == "External":
            response = {
                'status': False,
                'status_code': 400,
                'message': 'Unable to update Host Network',
                'errors': "Internal IPs can only be added to internal networks."
            }
            return Response(
                response,
                status=status.HTTP_400_BAD_REQUEST
            )
        serializer = self.serializer_class(
            host,
            data = {
                'network': network.id
            }
        )
        if serializer.is_valid():
            serializer.save()
            response = {
                'status': True,
                'status_code': 200,
                'message': 'Host Network updated successfully.',
                'data': serializer.data
            }
            return Response(
                response,
                status=status.HTTP_200_OK
            )
        response = {
            'status': False,
            'status_code': 400,
            'message': 'Unable to update Host Network.',
            'errors': serializer.errors
        }
        return Response(
            response,
            status=status.HTTP_400_BAD_REQUEST
        )


class CloudAssetsApiView(APIView):
    """
    Create or list cloud assets
    """
    authentication_classes = (CustomAuthentication,)
    permission_classes = (IsAuthenticated,)
    serializer_class = CloudAssetSerializer
    aws_serializer_class = ClientAwsAssetsSerializer

    def post(self, request, *args, **kwargs):
        """
        ## Note: 
        We are providing custom auth for the api's so add "data-auth-key" in the request header
        ### Body
        ```
        {
            "category": "S3",
            "bucket": "Test"
        }
        ```
        ### Response(Error with no key)
        ```
        {
            "detail": "Authentication credentials were not provided."
        }
        ```
        ### Response(Error with invalid key)
        ```
        {
            "detail": "Invalid Authentication key provided"
        }
        ```
        ### Response(Success)
        ```
        {
            "status": true,
            "message": "Cloud Assets added successfully!",
            "data": {
                "id": 23,
                "category": "S3",
                "bucket": "Test",
                "bucket_type": "Unmanaged"
            }
        }
        ```
        ### Response(Error)
        ```
        {
            "status": false,
            "message": "Unable to add cloud assets.",
            "data": {
                "non_field_errors": [
                    "The fields category, bucket must make a unique set."
                ]
            }
        }
        ```
        """
        data = request.data.copy()
        serializer = self.serializer_class(
            data=data
            )
        if serializer.is_valid():
            serializer.save()
            response_data = {
                'status': True,
                'message': "Cloud Assets added successfully!",
                'data': serializer.data
            }
            return Response(response_data, status=status.HTTP_201_CREATED)
        response_data = {
            'status': False,
            'message': "Unable to add cloud assets.",
            'data': serializer.errors
        }
        return Response(response_data, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request, *args, **kwargs):
        """
        ## Note: 
        We are providing custom auth for the api's so add "data-auth-key" in the request header
        ### Response(Error with no key)
        ```
        {
            "detail": "Authentication credentials were not provided."
        }
        ```
        ### Response(Error with invalid key)
        ```
        {
            "detail": "Invalid Authentication key provided"
        }
        ```
        ### Response(Success)
        ```
        {
            "S3": [
                {
                    "id": 1,
                    "category": "S3",
                    "bucket": "Tests3"
                    "bucket_type": "Stage"
                }
            ],
            "Azure": [],
            "GCP": []
        }
        ```
        """
        aws_asset_objs = ClientAwsAssets.objects.all()
        aws_serializer = self.aws_serializer_class(
            aws_asset_objs,
            many=True
        )
        assetsObj = CloudAssetsData.objects.all()
        gcp_obj = assetsObj.filter(category="GCP")
        azure_obj = assetsObj.filter(category="Azure")
        s3_obj = assetsObj.filter(category="S3")
        gcp_serializer = self.serializer_class(
            gcp_obj,
            many=True
            )
        azure_serializer = self.serializer_class(
            azure_obj,
            many=True
            )
        s3_serializer = self.serializer_class(
            s3_obj,
            many=True
            )
        data = {
            'S3': s3_serializer.data,
            'Azure': azure_serializer.data,
            'GCP': gcp_serializer.data,
            'aws_data': aws_serializer.data,
        }
        return Response(data, status=status.HTTP_200_OK)


class CloudAssetsDetailApiView(APIView):
    """
    Delete cloud assets object
    """
    def get_object(self):
        asset_id = self.kwargs.get('asset_id')
        try:
            return CloudAssetsData.objects.get(id=int(asset_id))
        except:
            response_data = {
                'status': True,
                'message': "No such asset available please refresh the assets"
            }
            raise NotFound(response_data)

    def delete(self, request, *args, **kwargs):
        """
        ## Note: 
        We are providing custom auth for the api's so add "data-auth-key" in the request header
        ### Response(Error with no key)
        ```
        {
            "detail": "Authentication credentials were not provided."
        }
        ```
        ### Response(Error with invalid key)
        ```
        {
            "detail": "Invalid Authentication key provided"
        }
        ```
        ### Response(Success)
        ```
        {
            "status": true,
            "message": "Cloud Assest removed successfully!"
        }
        ```
        ### Response(Error with invalid id)
        ```
        {
            "status": "True",
            "message": "No such asset available please refresh the assets"
        }
        ```
        """
        asset_obj = self.get_object()
        asset_obj.delete()
        response_data = {
            'status': True,
            'message': "Cloud Assest removed successfully!"
        }
        return Response(
            response_data,
            status=status.HTTP_200_OK
            )


class HostCreateListAPiView(CreateAPIView):
    authentication_classes = (CustomAuthentication,)
    permission_classes = (IsAuthenticated, )
    serializer_class = UserHostsDetailSerializer
    event_serializer_class = RedtreeEventHistorySerializer

    def get_network(self):
        network_id = self.request.data.get('network_id')
        try:
            network = Networks.objects.get(id=network_id)
        except:
            response = {
                'status': False,
                'status_code': 404,
                'message': 'Network not found.'
            }
            raise NotFound(
                response,
                code=status.HTTP_404_NOT_FOUND
            )
        return network

    def get_owner(self):
        email = self.request.data.get('event_data').get('username')
        try:
            username = PurpleleafUsers.objects.filter(
                user_email=email
            ).first().user_name
        except:
            username = email
        return username

    def check_loopback(self, ip):
        return ipaddress.ip_address(
                    unicode(ip)
                ).is_loopback

    def check_multicast(self, ip):
        return ipaddress.ip_address(
                    unicode(ip)
                ).is_multicast

    def update_event_data(self, event_data, data, network):
        hosts = ""
        for host in data:
            hosts = hosts + str(host) + ",  "
        host_data = "{} created under network '{}'.".format(hosts, network.network)
        event_data['data'] = str(host_data)
        serializer = self.event_serializer_class(data=event_data)
        if serializer.is_valid():
            serializer.save()

    def get(self, request, *args, **kwargs):
        """
        ## Note: 
        We are providing custom auth for the api's so add "data-auth-key" in the request header
        ### Response(Error with no key)
        ```
        {
            "detail": "Authentication credentials were not provided."
        }
        ```
        ### Response(Error with invalid key)
        ```
        {
            "detail": "Invalid Authentication key provided"
        }
        ```
        ### Response(Success)
        ```
        [
            {
                "id": 1100,
                "network_type": "External",
                "network_name": "External Network",
                "network_id": 68,
                "host_address": "23.94.236.73",
                "host_track_info": false
            },
            {
                "id": 1101,
                "network_type": "External",
                "network_name": "External Network",
                "network_id": 68,
                "host_address": "23.94.236.79",
                "host_track_info": false
            }
        ]
        ]
        ```
        """
        order = ['External', 'Internal']
        ext_hosts = UserHosts.objects.filter(
            network__network_type="External"
        ).order_by('network__network')
        int_hosts = UserHosts.objects.filter(
            network__network_type="Internal"
        ).order_by('network__network')
        networks = Networks.objects.all().order_by('id')
        external_host_detail = self.serializer_class(ext_hosts, many=True)
        internal_host_detail = self.serializer_class(int_hosts, many=True)
        network_detail = NetworkSerializer(networks, many=True)
        response = {
            "external_host_data": external_host_detail.data,
            "internal_host_data": internal_host_detail.data,
            "network_data": network_detail.data
        }
        return Response(response, status=status.HTTP_200_OK)

    def post(self, request, *args, **kwargs):
        """
        ## Note: 
        We are providing custom auth for the api's so add "data-auth-key" in the request header
        ### Response(Error with no key)
        ```
        {
            "detail": "Authentication credentials were not provided."
        }
        ```
        ### Response(Error with invalid key)
        ```
        {
            "detail": "Invalid Authentication key provided"
        }
        ```
        ### Body
        ```
        {
            "network_id": 68,
            "ips": ["192.168.1.1", "192.168.1.2"],
            "event_data": {
                "username": "rajinder.ameo@gmail.com",
                "time_stamp": "2019-04-08 11:30 AM",
                "event_type": "add_range",
                "ip": "127.0.0.1"
            }
        }
        ```
        ### Response(Success)
        ```
        {
            "status": true,
            "status_code": 201,
            "message": "Hosts created successfully.",
            "data": [
                "192.168.1.1",
                "192.168.1.2"
            ]
        }
        ```
        ### Response(Error)
        ```
        {
            "status": false,
            "status_code": 400,
            "message": "Host Already Exists.",
            "errors": "Unable to create host"
        }
        ```
        """
        data = request.data.copy()
        event_data = data.get('event_data')
        excluded_hosts = list()
        loopback_ips = list()
        multicast_ips = list()
        host_data = list()
        created_hosts = list()
        network = self.get_network()
        owner = self.get_owner()
        message = ''
        host_list = data.get('ips')
        for host in host_list:
            if re.search("\r\n", host) or re.search("\r", host) or re.search("\n", host):
                if re.search("\r\n", ip):
                    host = host.replace("\r\n", "")
                if re.search("\n", host):
                    host = host.replace("\n", "")
                if re.search("\r", host):
                    host = host.replace("\r", "")
            host = host.strip()
            host_type = get_host_type(host)
            if host_type != "invalid":
                host_network = get_host_network_type(host, host_type)
                if host_type == "ip":
                    if self.check_loopback(host):
                        loopback_ips.append(host)
                        continue
                    if self.check_multicast(host):
                        multicast_ips.append(host)
                        continue
                if host_type == "host_name":
                    host = host.lower()
                host_record = {
                    'host': host,
                    'host_type': host_type,
                    'network': network,
                    'host_network_type': host_network,
                    'owner': owner
                }
                host_data.append(host_record)
            else:
                excluded_hosts.append(host)

        if multicast_ips:
            if len(multicast_ips) == 1:
                message = "{} is a multicast address and cannot be"\
                    " scanned.".format(multicast_ips[0])
            else:
                multicast_ips = ", ".join(multicast_ips)
                message = "{} are multicast addresses and cannot be"\
                    " scanned.".format(multicast_ips)
            response_data = {
                "status": False,
                "status_code": 500,
                "message": message,
                "data": []
            }
            return Response(
                response_data,
                status=status.HTTP_400_BAD_REQUEST
            )

        if list(filter(lambda d: d['host_network_type'] in "Internal", host_data)):
            if network.network_type == "External":
                response = {
                    'status': False,
                    'message': "Unable to add host",
                    'status_code': 400,
                    'errors': 'Internal IPs can only be added to internal networks.'
                }
                return Response(
                    response,
                    status=status.HTTP_400_BAD_REQUEST
                )

        for host_record in host_data:
            if not check_host_exists(host_record['host'], host_record['host_type']):
                count = get_host_count(host_record['host'], host_record['host_type'])
                host_obj = UserHosts.objects.create(
                    host=host_record['host'],
                    host_type=host_record['host_type'],
                    network=host_record['network'],
                    owner=host_record['owner'],
                    count=count,
                    host_network_type=host_record['host_network_type']
                )
                created_hosts.append(host_obj.id)
            else:
                excluded_hosts.append(host_record['host'])
        if loopback_ips:
            loopback_data = {
                'loopback_ips': loopback_ips
            }
            send_loopback_ip_add_mail.delay(loopback_ip_data=loopback_data)
        if created_hosts or excluded_hosts:
            data = {
                'created_host_id': created_hosts,
                'excluded_hosts': excluded_hosts
            }
            send_host_add_mail.delay(host_data=data)
            if created_hosts:
                all_created_hosts = list(UserHosts.objects.filter(
                    id__in=created_hosts
                    ).values_list('host', flat=True))
                if event_data:
                    self.update_event_data(event_data,all_created_hosts, network)
                if network.network_type == "External":
                    ips_whois_host(created_hosts)
                response = {
                    'status': True,
                    'message': "Hosts created successfully.",
                    'status_code': 201,
                    'data': all_created_hosts
                }
                return Response(
                    response,
                    status=status.HTTP_201_CREATED
                )
            if len(excluded_hosts) >=1:
                message = "Host Already Exists."
            else:
                message = "Hosts Already Exists."
            response = {
                'status': False,
                'message': message,
                'status_code': 400,
                'errors': 'Unable to create host'
            }
            return Response(
                response,
                status=status.HTTP_400_BAD_REQUEST
            )
        response = {
                'status': False,
                'message': "Hosts not created.",
                'status_code': 400,
                'errors': 'Unable to create host'
            } 
        return Response(response, status=status.HTTP_200_OK)


class HostDetailAPiView(APIView):
    """
    Get data of a application vulnerability 
    """
    authentication_classes = (CustomAuthentication,)
    permission_classes = (IsAuthenticated,)
    serializer_class = UserHostDetailSerializer

    def get_host_object(self):
        host_id = self.kwargs.get('id')
        try:
            return Host.objects.get(id=host_id)
        except:
            response = {
                'status': False,
                'status_code': 404,
                'message': 'Host not found.'
            }
            raise NotFound(
                response,
                code=status.HTTP_404_NOT_FOUND
            )

    def get(self, request, *args, **kwargs):
        """
        ## Note:
        We are providing custom auth for the api's so add "data-auth-key" in the request header
        ### Response(Error with no key)
        ```
        {
            "detail": "Authentication credentials were not provided."
        }
        '''
        ### Response(Error with invalid key)
        ```
        {
            "detail": "Invalid Authentication key provided"
        }
        ```
        ### Response(Success)
        ```
        {
            

        }
        ```
        """
        host_obj =  self.get_host_object()
        host_detail = self.serializer_class(host_obj)
        context = {
            'host': host_detail.data
        }
        return Response(context, status=status.HTTP_200_OK)


class HostsWhoisMapView(APIView):
    """
    Get data of a application vulnerability 
    """
    authentication_classes = (CustomAuthentication,)
    permission_classes = (IsAuthenticated,)
  

    def get(self, request, *args, **kwargs):
        """
        ## Note:
        We are providing custom auth for the api's so add "data-auth-key" in the request header
        ### Response(Error with no key)
        ```
        {
            "detail": "Authentication credentials were not provided."
        }
        '''
        ### Response(Error with invalid key)
        ```
        {
            "detail": "Invalid Authentication key provided"
        }
        ```
        ### Response(Success)
        ```
        {
            

        }
        ```
        """
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
        return Response(context, status=status.HTTP_200_OK)


class NetworkCreateListAPiView(CreateAPIView):
    authentication_classes = (CustomAuthentication,)
    permission_classes = (IsAuthenticated, )
    serializer_class = NetworkSerializer
    event_serializer_class = RedtreeEventHistorySerializer

    def post(self, request, format=None):
        """
        ## Note: 
        We are providing custom auth for the api's so add "data-auth-key" in the request header
        ### Response(Error with no key)
        ```
        {
            "detail": "Authentication credentials were not provided."
        }
        ```
        ### Response(Error with invalid key)
        ```
        {
            "detail": "Invalid Authentication key provided"
        }
        ```
        ### Body
        ```
        {
            'network': "test",
            'network_type': "External",
            'event_data': {
                'username': 'rajinder.ameo@gmail.com',
                'time_stamp': '2019-04-08 11:30 AM',
                'event_type': 'add_network',
                'ip': u'127.0.0.1'
            }
        }
        ```
        ### Response(Success)
        ```
        {
            "status": true,
            "status_code": 201,
            "message": "Network created successfully.",
            "data": {
                "id": 29,
                "network": "test",
                "network_type": "External"
            }
        }
        ```
        ### Response(Error)
        ```
        {
            "status": false,
            "status_code": 400,
            "message": "Unable to create network.",
            "errors": {
                "network": [
                    "This field must be unique."
                ]
            }
        }
        ```
        """
        data = request.data.copy()
        serializer = self.serializer_class(data=request.data)
        event_data = self.request.data.get('event_data')
        if serializer.is_valid():
            serializer.save()
            if event_data:
                event_data['data'] = serializer.data.get('network')
                event_serializer = self.event_serializer_class(
                    data=event_data
                )
                if event_serializer.is_valid():
                    event_serializer.save()
            response = {
                'status': True,
                'message': "Network created successfully.",
                'status_code': 201,
                'data': serializer.data
            }
            return Response(
                response,
                status=status.HTTP_201_CREATED
            )
        response = {
            'status': False,
            'message': "Unable to create network.",
            'status_code': 400,
            'errors': serializer.errors
        }
        return Response(
            response,
            status=status.HTTP_400_BAD_REQUEST
        )

    def get(self, request, *args, **kwargs):
        """
        ## Note: 
        We are providing custom auth for the api's so add "data-auth-key" in the request header
        ### Response(Error with no key)
        ```
        {
            "detail": "Authentication credentials were not provided."
        }
        ```
        ### Response(Error with invalid key)
        ```
        {
            "detail": "Invalid Authentication key provided"
        }
        ```
        ### Response(Success)
        ```
        [
            {
                "id": 1,
                "network": "External Network",
                "network_type": "External",
                "vulnerabilities": {
                    "high": 0,
                    "medium": 6,
                    "critical": 0,
                    "low": 8,
                    "hosts": 14
                }
            },
            {
                "id": 23,
                "network": "AWS",
                "network_type": "External",
                "vulnerabilities": {
                    "high": 0,
                    "medium": 0,
                    "critical": 0,
                    "low": 0,
                    "hosts": 0
                }
            }
        ]
        ```
        """
        networks = Networks.objects.all().order_by('id')
        serializer = NetworkDetailSerializer(networks, many=True)

        return Response(serializer.data, status=status.HTTP_200_OK)


class NetworkDetailAPiView(APIView):
    authentication_classes = (CustomAuthentication,)
    permission_classes = (IsAuthenticated, )
    serializer_class = NetworkSerializer
    event_serializer_class = RedtreeEventHistorySerializer

    def get_object(self):
        network_id = self.kwargs.get('network_id')
        try:
            return Networks.objects.get(
                id=int(network_id)
            )
        except:
            response = {
                'status': False,
                'status_code': 404,
                'message': 'Network not found.'
            }
            raise NotFound(
                response,
                code=status.HTTP_404_NOT_FOUND
            )

    def get(self, request, *args, **kwargs):
        network = self.get_object()
        serializer = NetworkDetailSerializer(network)
        response = {
            'status': True,
            'status_code': 200,
            'message': 'Network fetech successfully',
            'data': serializer.data
        }
        return Response(
            response,
            status=status.HTTP_200_OK
        )
    
    def patch(self, request, *args, **kwargs):
        """
        ## Note: 
        We are providing custom auth for the api's so add "data-auth-key" in the request header
        ### Body
        ```
        {
            'network': "AWS",
            'network_type': "External"
        }
        ```
        ### Response(Error with no key)
        ```
        {
            "detail": "Authentication credentials were not provided."
        }
        ```
        ### Response(Error with invalid key)
        ```
        {
            "detail": "Invalid Authentication key provided"
        }
        ```
        ### Response(Success)
        ```
        {
            "status": true,
            "status_code": 200,
            "message": "Network updated successfully.",
            "data": {
                "id": 23,
                "network": "test",
                "network_type": "External"
            }
        }
        ```
        ### Response(Error)
        ```
        {
            "status": false,
            "status_code": 400,
            "message": "Unable to update Network.",
            "errors": {
                "network": [
                    "Network already exists."
                ]
            }
        }
        ```
        ### Response(Error)
        ```
        {
            "status": "False",
            "status_code": "404",
            "message": "Network not found."
        }
        ```
        """
        data = request.data.copy()
        network = self.get_object()
        serializer = self.serializer_class(
            network,
            data=data
            )
        if serializer.is_valid():
            serializer.save()
            response = {
                'status': True,
                'status_code': 200,
                'message': 'Network updated successfully.',
                'data': serializer.data
            }
            return Response(
                response,
                status=status.HTTP_200_OK
            )
        response = {
            'status': False,
            'status_code': 400,
            'message': 'Unable to update Network.',
            'errors': serializer.errors
        }
        return Response(
            response,
            status=status.HTTP_400_BAD_REQUEST
        )

    def delete(self, request, *args, **kwargs):
        """
        ## Note: 
        We are providing custom auth for the api's so add "data-auth-key" in the request header
        ### Body
        ```
        {
            'event_data': {
                'username': 'rajinder.ameo@gmail.com',
                'time_stamp': '2019-04-08 11:13 AM',
                'event_type': 'delete_network',
                'ip': '127.0.0.1'
            }
        }
        ```
        ### Response(Error with no key)
        ```
        {
            "detail": "Authentication credentials were not provided."
        }
        ```
        ### Response(Error with invalid key)
        ```
        {
            "detail": "Invalid Authentication key provided"
        }
        ```
        ### Response(Success)
        ```
        {
            "status": true,
            "status_code": 204,
            "message": "Network deleted successfully."
        }
        ```
        ### Response(Error)
        ```
        {
            "status": "False",
            "status_code": "404",
            "message": "Network not found."
        }
        ```
        """
        event_data = request.data.get('event_data')
        host_list = list()
        hosts_list = list()
        ip_list = list()
        network = self.get_object()
        network.delete()
        if event_data:
            event_data['data'] = network.network
            event_serializer = self.event_serializer_class(
                data=event_data
            )
            if event_serializer.is_valid():
                event_serializer.save()
        response = {
            'status': True,
            'status_code': 200,
            'message': "Network deleted successfully."
        }
        return Response(
            response,
            status=status.HTTP_200_OK
        )


class AwsAssetsCreateListView(APIView):
    authentication_classes = (CustomAuthentication,)
    permission_classes = (IsAuthenticated, )
    serializer_class = ClientAwsAssetsSerializer

    def post(self, request, *args, **kwargs):
        """
        ## Note: 
        We are providing custom auth for the api's so add "data-auth-key" in the request header
        ### Body
        ```
        {
            "domain_name": "abc.com",
            "network_type": "External"
        }
        ```
        ### Response(Error with no key)
        ```
        {
            "detail": "Authentication credentials were not provided."
        }
        ```
        ### Response(Error with invalid key)
        ```
        {
            "detail": "Invalid Authentication key provided"
        }
        ```
        ### Response(Success)
        ```
        {
            "status": true,
            "status_code": 201,
            "message": "Domain Added successfully.",
            "data": {
                "id": 5,
                "domain_name": "abc.com",
                "network_type": "External"
            }
        }
        ```
        ### Response(Error)
        ```
        {
            "status": false,
            "status_code": 400,
            "message": "Unable to add domain.",
            "errors": {
                "domain_name": [
                    "Domain name already exists."
                ]
            }
        }
        ```
        """
        data = request.data.copy()
        serializer = self.serializer_class(data=data)
        if serializer.is_valid():
            serializer.save()
            response = {
                'status': True,
                'message': "AWS Token Added successfully.",
                'status_code': 201,
                'data': serializer.data
            }
            return Response(
                response,
                status=status.HTTP_201_CREATED
            )
        response = {
            'status': False,
            'message': "Unable to add AWS Token.",
            'status_code': 400,
            'errors': serializer.errors
        }
        return Response(
            response,
            status=status.HTTP_400_BAD_REQUEST
        )


class DomainListAPIView(APIView):
    """
    List or create Domains
    """
    authentication_classes = (CustomAuthentication,)
    permission_classes = (IsAuthenticated,)
    serializer_class = DomainSerializer

    def get(self, request, *args, **kwargs):
        """
        ## Note: 
        We are providing custom auth for the api's so add "data-auth-key" in the request header
        ### Response(Error with no key)
        ```
        {
            "detail": "Authentication credentials were not provided."
        }
        ```
        ### Response(Error with invalid key)
        ```
        {
            "detail": "Invalid Authentication key provided"
        }
        ```
        ### Response(Success)
        ```
        [
            {
                "id": 3,
                "domain_name": "Test1.com",
                "network_type": "Internal"
            },
            {
                "id": 2,
                "domain_name": "Test.com",
                "network_type": "External"
            }
        ]
        ```
        """
        domains = Domains.objects.all().order_by('-id')
        serializer = DomainDetailSerializer(
            domains,
            many=True
        )
        first_subdomain_index = None
        sub_domain_range = list()
        sub_domain_index_counter = 0
        for key,sub_domain in enumerate(serializer.data):
            if sub_domain.get('sub_domains') and not first_subdomain_index:
                first_subdomain_index = key + 1
            if sub_domain.get('sub_domains'):
                sub_domain_index_counter += 1
                sub_domain['index'] = sub_domain_index_counter
        context = {
            'domains' : serializer.data,
            'first_subdomain_index': first_subdomain_index,
            'sub_domain_length': sub_domain_index_counter
        }
        return Response(
            context,
            status=status.HTTP_200_OK
        )

    def post(self, request, *args, **kwargs):
        """
        ## Note: 
        We are providing custom auth for the api's so add "data-auth-key" in the request header
        ### Body
        ```
        {
            "domain_name": "abc.com",
            "network_type": "External"
        }
        ```
        ### Response(Error with no key)
        ```
        {
            "detail": "Authentication credentials were not provided."
        }
        ```
        ### Response(Error with invalid key)
        ```
        {
            "detail": "Invalid Authentication key provided"
        }
        ```
        ### Response(Success)
        ```
        {
            "status": true,
            "status_code": 201,
            "message": "Domain Added successfully.",
            "data": {
                "id": 5,
                "domain_name": "abc.com",
                "network_type": "External"
            }
        }
        ```
        ### Response(Error)
        ```
        {
            "status": false,
            "status_code": 400,
            "message": "Unable to add domain.",
            "errors": {
                "domain_name": [
                    "Domain name already exists."
                ]
            }
        }
        ```
        """
        data = request.data.copy()
        serializer = self.serializer_class(data=data)
        if serializer.is_valid():
            serializer.save()
            response = {
                'status': True,
                'message': "Domain Added successfully.",
                'status_code': 201,
                'data': serializer.data
            }
            return Response(
                response,
                status=status.HTTP_201_CREATED
            )
        response = {
            'status': False,
            'message': "Unable to add domain.",
            'status_code': 400,
            'errors': serializer.errors
        }
        return Response(
            response,
            status=status.HTTP_400_BAD_REQUEST
        )


class DomainDetailAPIView(APIView):
    authentication_classes = (CustomAuthentication,)
    permission_classes = (IsAuthenticated,)

    def get_object(self):
        domain_id = self.kwargs.get('domain_id')
        try:
            return Domains.objects.get(id=domain_id)
        except:
            response = {
                'status': False,
                'status_code': 404,
                'message': 'Domain not found.'
            }
            raise NotFound(
                response,
                code=status.HTTP_404_NOT_FOUND
            )

    def delete(self, request, *args, **kwargs):
        domain = self.get_object()
        domain.delete()
        response = {
                'status': True,
                'status_code': 200,
                'message': "Domain deleted successfully."
            }
        return Response(
            response,
            status=status.HTTP_200_OK
        )


class SshEncryptionApi(APIView):
    authentication_classes = (CustomAuthentication,)
    permission_classes = (IsAuthenticated,)

    def get_ciphers_by_count(self, ciphers):
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

    def get(self, request, *args, **kwargs):
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
            'key_exchange': self.get_ciphers_by_count(key_exchange),
            'mac': self.get_ciphers_by_count(mac),
            'encryption': self.get_ciphers_by_count(encryption)
        }

        data.append(data_dict)
        return Response(data, status=status.HTTP_200_OK)


class SshEncryptionDetailApi(APIView):
    authentication_classes = (CustomAuthentication,)
    permission_classes = (IsAuthenticated,)
    serializer_class = SshyzeCiphersSerializer

    def get_obj(self):
        return SshyzeCiphers.objects.filter(
            cipher_type__name=self.kwargs.get('type'),
            ciphers=self.kwargs.get('cipher')
            )

    def get(self, request, *args, **kwargs):
        cipher = self.get_obj()
        serializer = self.serializer_class(
            cipher,
            many=True
        )
        return Response(serializer.data, status=status.HTTP_200_OK)


class GetDashboardHistoricalData(APIView):
    authentication_classes = (CustomAuthentication,)
    permission_classes = (IsAuthenticated,)
    serializer_class = GetRiskHistoricalDataSerializer
    historical_serializer_class = GetHistoricalDataSerializer
    app_vul_serializer_class = GetAppVulnerabilityHistoricalDataSerializer
    riskhistoricaldata_model_class = RiskHistoricalData
    historicaldata_model_class = HistoricalData
    application_chart_model_class = ApplicationVulnerabilityChart

    def get_historical_obj(self):
        return self.historicaldata_model_class.objects.all()[:30]

    def get_risk_historical_obj(self):
        return self.riskhistoricaldata_model_class.objects.all()[:30]

    def get_app_vul_chart_obj(self):
        return self.application_chart_model_class.objects.all()[:30]

    def get(self, request, *args, **kwargs):
        historical_obj = self.get_historical_obj()
        historical_serializer = self.historical_serializer_class(
            historical_obj,
            many=True
        )
        risk_historical_obj = self.get_risk_historical_obj()
        risk_historical_serializer = self.serializer_class(
            risk_historical_obj,
            many=True
        )
        app_vul_obj = self.get_app_vul_chart_obj()
        app_vul_serializer = self.app_vul_serializer_class(
            app_vul_obj,
            many=True
        )
        historical_data = historical_serializer.data
        risk_historical_data = risk_historical_serializer.data
        app_vul_data = app_vul_serializer.data
        response = {
            'historical_data': historical_data,
            'risk_historical_data': risk_historical_data,
            'app_vul_data': app_vul_data
        }
        return Response(response, status=status.HTTP_200_OK)


class EncryptionChartsApiView(APIView):
    authentication_classes = (CustomAuthentication,)
    permission_classes = (IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        secure_sh_ciphers = SshyzeCiphers.objects.distinct('ciphers').count()
        secure_ly_ciphers = Ciphers.objects.distinct('cipher').count()
        response_data = {
            'secure_sh_ciphers': secure_sh_ciphers,
            'secure_ly_ciphers': secure_ly_ciphers,
            'ciphers_proto': get_ciphers_strength(),
            'cipher_strength':get_strength_count()
        }
        return Response(
            response_data,
            status=status.HTTP_200_OK
        )
        


class VulnerabilityListApiView(APIView):
    """
    ## List all the available sorted vulnerabilities
    """
    authentication_classes = (CustomAuthentication,)
    permission_classes = (IsAuthenticated,)
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
            'external_vul_obj': external_vul_obj,
            'internal_vul_obj': internal_vul_obj
        }
        network_obj = Networks.objects.all().order_by('-id')
        return vul_obj, network_obj

    def get(self, request, *args, **kwargs):
        """
        ## Note: 
           We are providing custom auth for the api's so add "data-auth-key" in the request header
        ### Response(Error with invalid key)
        ```
        {
            "detail": "Invalid Authentication key provided"
        }
        ```
        ### Response(Error with no key)
        ```
        {
            "detail": "No Authentication key provided"
        }
        ```
        ### Response(Success)
        ```
        {
            "vulnerabilityDetails": [
                {
                    "instances": 1,
                    "virtue_id": 7,
                    "risk": "Medium",
                    "risk_factor": 2,
                    "title": "SMB Signing Disabled"
                },
                {
                    "instances": 2,
                    "virtue_id": 9,
                    "risk": "Medium",
                    "risk_factor": 2,
                    "title": "Outdated Encryption Protocols Enabled"
                },
                {
                    "instances": 1,
                    "virtue_id": 18,
                    "risk": "Medium",
                    "risk_factor": 2,
                    "title": "Telnet Enabled"
                },
                {
                    "instances": 2,
                    "virtue_id": 19,
                    "risk": "Medium",
                    "risk_factor": 2,
                    "title": "Weak Ciphers Supported"
                },
                {
                    "instances": 6,
                    "virtue_id": 1,
                    "risk": "Low",
                    "risk_factor": 1,
                    "title": "Web Server Version Disclosed"
                }
            ],
            "networks": {
                "internal": [
                    {
                        "id": 24,
                        "network": "Test Network",
                        "network_type": "Internal",
                        "purpleleaf_id": "19"
                    },
                    {
                        "id": 25,
                        "network": "internal Netwrik",
                        "network_type": "Internal",
                        "purpleleaf_id": "20"
                    }
                ],
                "external": [
                    {
                        "id": 1,
                        "network": "External Network",
                        "network_type": "External",
                        "purpleleaf_id": "1"
                    },
                    {
                        "id": 23,
                        "network": "AWS",
                        "network_type": "External",
                        "purpleleaf_id": "18"
                    }
                ]
            }
        }
        ```
        ### Curl 
        ```
        Curl: curl -H "data-auth-key: redtree-auth-key" http://localhost:8000/private/vulnerabilities/
        ```
        """
        vulnerabilities, networks = self.get_object()
        internal_net_serializer = self.serializer_class(
            networks.filter(network_type="Internal"), 
            many=True
        )
        external_net_serializer = self.serializer_class(
            networks.filter(network_type="External"),
            many=True
        )

        json_data = {
            'vulnerabilities': vulnerabilities,
            'networks': {
                'internal': internal_net_serializer.data,
                'external': external_net_serializer.data,
            }
        }
        return Response(json_data, status=status.HTTP_200_OK)


class VulnerabilityDetailListApi(APIView):
    """
    ## List All the vulnerabilities with a given virtue id
    """
    authentication_classes = (CustomAuthentication,)
    permission_classes = (IsAuthenticated,)
    serializer_class = VulnerabilityPartialDetailSerializer
    vuln_serializer_class = VulnerabilityDetailSerailizer

    def get_object(self):
        request_url = self.request.path_info
        network_type = None
        if "/external/" in request_url:
            network_type = "External"
        elif "/internal/" in request_url:
            network_type = "Internal"
        return Vulnerability.objects.filter(
            host__user_host__network__network_type=network_type,
            virtue_id=self.kwargs.get('virtue_id')
        )

    def get(self, request, *args, **kwargs):
        """
        ### List All the vulnerabilities with a given virtue id
        ### Note: 
           We are providing custom auth for the api's so add "data-auth-key" in the request header
        ### Response(Error with invalid key)
        ```
        {
            "detail": "Invalid Authentication key provided"
        }
        ```
        ### Response(Error with no key)
        ```
        {
            "detail": "No Authentication key provided"
        }
        ```
        ### Response(Success)
        ```
        {
            "vulnerability": {
                "id": 36,
                "title": "SMB Signing Disabled",
                "formatted_description": "description",
                "formatted_remediation": "remediation",
                "virtue_id": 7,
                "port": "445",
                "host_ip": "165.227.221.43",
                "banner": ""
            },
            "banner": false,
            "affected_hosts": [
                {
                    "id": 36,
                    "virtue_id": 7,
                    "host_ip": "165.227.221.43",
                    "port": "445",
                    "banner": "",
                    "created": "2019-03-06",
                    "modified": "2019-03-06"
                }
            ]
        }
        ```
        ## Curl
        ```
        curl -H "data-auth-key: redtree-auth-key" http://localhost:8000/private/vulnerability/virtue_id/
        ```
        """
        vul_obj = self.get_object()
        vulnerability = vul_obj.first()
        banner_count = 0
        banner_exist = False
        for banner in vul_obj:
            if banner.banner:
                banner_count = banner_count + 1
        if banner_count > 0:
            banner_exist = True
        else:
            banner_exist = False
        # banner_ext = vul_obj.exclude(banner__isnull=True).count()
        # if banner_ext > 0:
        #     banner_exist = True
        # else:
        #     banner_ext = False
        # af_data = get_paginated_data(
        #     VulnerabilityPartialDetailSerializer,
        #     vul_obj,
        #     request,
        #     self,
        # )
        serializer = self.serializer_class(
            vul_obj,
            many=True
        )
        vulnerability_evidence_objs = vul_obj.values_list(
            'evidence', flat=True
        )
        evidence_list = [evidence for evidence in vulnerability_evidence_objs if evidence]
        evidence_count = len(evidence_list)
        vuln_serializer = self.vuln_serializer_class(
            vulnerability
        )
        context = {
            'affected_hosts': serializer.data,
            'vulnerability': vuln_serializer.data,
            'banner': banner_exist,
            'evidence_count': evidence_count,
        }
        return Response(context, status=status.HTTP_200_OK)


class VulnerabilityDetailAPIView(APIView):
    """
    Get details of a vulnerability 
    """
    authentication_classes = (CustomAuthentication,)
    permission_classes = (IsAuthenticated,)
    vuln_serializer_class = VulnerabilityDetailSerailizer

    def get_object(self):
        try:
            vulnerability_obj = Vulnerability.objects.get(
                id = self.kwargs.get('vul_id'),
                virtue_id=self.kwargs.get('virtue_id')
                )
        except:
            vulnerability_obj = None
        return vulnerability_obj

    def get(self, request, *args, **kwargs):
        """
        ## Note: 
        We are providing custom auth for the api's so add "data-auth-key" in the request header
        ### Response(Error with no key)
        ```
        {
            "detail": "Authentication credentials were not provided."
        }
        ```
        ### Response(Error with invalid key)
        ```
        {
            "detail": "Invalid Authentication key provided"
        }
        ```
        ### Response(Success)
        ```
        {
            "vulnerability": {
                "id": 52,
                "title": "This is test vuln",
                "formatted_description": "<h1>Test case</h1>",
                "formatted_remediation": "<h1>Test case</h1>",
                "formatted_evidence": "<h1>Test case</h1>",
                "virtue_id": 50001,
                "port": "80",
                "host_ip": "10.0.2.3",
                "banner": null,
                "retest": "Closed",
                "retest_notes": [
                    {
                        "note": "This is test",
                        "status": "Leave_Open",
                        "created": "Apr 10 2019 03:51AM"
                    },
                    {
                        "note": "Test",
                        "status": "Leave_Open",
                        "created": "Apr 10 2019 03:58AM"
                    },
                    {
                        "note": "Close",
                        "status": "Closed",
                        "created": "Apr 10 2019 02:17AM"
                    }
                ]
            }
        }
        ```
        """
        vul_obj = self.get_object()
        if vul_obj:
            serializer = self.vuln_serializer_class(
                vul_obj,
            )
            context = {
                'vulnerability': serializer.data
            }
            return Response(context, status=status.HTTP_200_OK)
        return Response(status=status.HTTP_400_BAD_REQUEST)


class NetworkVulnerabilitiesAPIView(APIView):
    authentication_classes = (CustomAuthentication,)
    permission_classes = (IsAuthenticated,)
    serializer_class = NetworkVulnerabilitiesSerializer

    def get_object(self):
        network_id = self.kwargs.get('network_id')
        try:
            return Networks.objects.get(id=int(network_id))
        except:
            response = {
                'status': False,
                'status_code': 404,
                'message': 'Network not found.'
            }
            raise NotFound(
                response,
                code=status.HTTP_404_NOT_FOUND
            )

    def get(self, request, *args, **kwargs):
        network = self.get_object()
        serializer = self.serializer_class(network)
        return Response(serializer.data, status=status.HTTP_200_OK)


class VulnerabilityNetworkDetailAPIView(APIView):
    authentication_classes = (CustomAuthentication,)
    permission_classes = (IsAuthenticated,)
    serializer_class = VulnerabilityPartialDetailSerializer
    vuln_serializer_class = VulnerabilityDetailSerailizer

    def get(self, request, *args, **kwargs):
        network_id = kwargs.get('network_id')
        virtue_id = kwargs.get('virtue_id')
        affected_hosts = Vulnerability.objects.filter(
            host__user_host__network__id=network_id, virtue_id=virtue_id
        )
        vulnerabilities = self.serializer_class(
            affected_hosts,
            many=True
        )
        vulnerability_evidence_objs = affected_hosts.values_list(
            'evidence', flat=True
        )
        evidence_list = [evidence for evidence in vulnerability_evidence_objs if evidence]
        evidence_count = len(evidence_list)
        vulnerability_obj = affected_hosts.first()
        vulnerability = self.vuln_serializer_class(vulnerability_obj)
        banner_count = 0
        for banner in affected_hosts:
            if banner.banner:
                banner_count = banner_count + 1
        if banner_count > 0:
            banner_exist = True
        else:
            banner_exist = False
        context = {
            'vulnerability': vulnerability.data,
            'affected_hosts': vulnerabilities.data,
            'banner': banner_exist,
            'evidence_count': evidence_count
        }
        return Response(context, status=status.HTTP_200_OK)


class EncryptionApi(APIView):
    authentication_classes = (CustomAuthentication,)
    permission_classes = (IsAuthenticated,)
    serializer_class = SslyzeCertificatesSerializer

    def get_raw_ciphers(self, *args, **kwargs):
        host_id = self.request.query_params.get('host')
        if host_id:
            try:
                host_obj = Host.objects.get(pk=host_id)
                host = host_obj.host
                ciphers = Ciphers.objects.filter(
                    host=host_obj.host,
                    key_size__isnull=False).values(
                        'key_size','cipher','strength', 'protocol'
                    ).annotate(cipher_count=Count('host','port'))
                return host,ciphers
            except:
                host = None
                ciphers = Ciphers.objects.filter(key_size__isnull=False).values(
                    'key_size','cipher','strength', 'protocol'
                ).annotate(
                    cipher_count=Count('host','port')
                )
                return host,ciphers
        host = None
        ciphers = Ciphers.objects.filter(key_size__isnull=False).values(
            'key_size','cipher','strength', 'protocol'
            ).annotate(
                cipher_count=Count('host','port')
            )
        return host,ciphers


    def get(self, request, *args, **kwargs):
        https_enc_count = Ciphers.objects.filter(
            key_size__isnull=False
        ).distinct('host','port').count()
        ssh_enc_count = SshyzeCiphers.objects.all().distinct('host','port').count()
        host,raw_ciphers = self.get_raw_ciphers()
        certificates = SslyzeCertificates.objects.all().order_by('-id')
        serializer = self.serializer_class(
            certificates[:5],
            many = True
        )
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
        if not host:
            sorted_by_count_ciphers =  sorted(ciphers[:5], key=lambda x: x['cipher_count'], reverse=True) #sorting on secondary key
        else:
            sorted_by_count_ciphers =  sorted(ciphers, key=lambda x: x['cipher_count'], reverse=True) #sorting on secondary key
        sorted_ciphers = sorted(sorted_by_count_ciphers, key=lambda x: x['key_size'], reverse=True) #sorting on primary key 
        sorted_ciphers = sorted(sorted_ciphers, key=lambda x: x['risk_factor'], reverse=True) #sorting on risk
        total_ciphers = len(ciphers)
        total_certificates = len(certificates)
        json_data = {
            "total_ciphers": total_ciphers,
            "total_certificates" : total_certificates,
            "ciphers": sorted_ciphers,
            "host": host,
            "certificate_data": serializer.data,
            "https_enc_count": https_enc_count,
            "ssh_enc_count": ssh_enc_count
        }
        return Response(json_data, status=status.HTTP_200_OK)


class EncryptionProtocolDetailApi(APIView):
    authentication_classes = (CustomAuthentication,)
    permission_classes = (IsAuthenticated,)
    serializer_class = EncryptionSerializer
    encryption_host_serializers_class = EncryptionHostSerializer

    def get_object(self):
        return Ciphers.objects.filter(
            protocol=self.kwargs.get('protocol'),
            key_size__isnull=False
        )

    def get(self, request, *args, **kwargs):
        cipher_objs = self.get_object()
        host_ciphers = cipher_objs.values(
            'host','port'
        ).annotate(cipher_count=Count('cipher'))
        host_cipher_serializer = self.encryption_host_serializers_class(
            host_ciphers,
            many = True
        )
        supported_ciphers = cipher_objs.values(
            'cipher','key_size'
        ).annotate(cipher_count=Count('cipher'))
        supported_cipher_serializer = self.serializer_class(
            supported_ciphers,
            many = True
        )
        data = {
            "host_ciphers" : host_cipher_serializer.data,
            "supported_ciphers": supported_cipher_serializer.data
        }
        return Response(data, status=status.HTTP_200_OK)


class EncryptionCipherApi(APIView):
    authentication_classes = (CustomAuthentication,)
    permission_classes = (IsAuthenticated,)
    serializer_class = EncryptionDetailSerializer

    def get_object(self):
        cipher = self.kwargs.get('cipher')
        raw_ciphers = Ciphers.objects.filter(
            cipher=cipher,key_size__isnull=False
        ).distinct('host', 'port')
        return raw_ciphers

    def get(self, request, *args, **kwargs):
        ciphers = self.get_object()
        serializer = self.serializer_class(
                ciphers,
                many=True
            )
        json_data = {
            "ciphers" : serializer.data
        }
        return Response(json_data, status=status.HTTP_200_OK)


class ReportsApi(APIView):
    """
    List all the available reports
    """
    authentication_classes = (CustomAuthentication,)
    permission_classes = (IsAuthenticated,)
    serializer_class = ReportsSerializer

    def get(self, request, *args, **kwargs):
        external_report_obj = Reports.objects.filter(
            network_type='External'
        ).order_by('-created')
        internal_report_obj = Reports.objects.filter(
            network_type='Internal'
        ).order_by('-created')
        external_report_serializer = self.serializer_class(
                external_report_obj,
                many = True
            )
        internal_report_serializer = self.serializer_class(
                internal_report_obj,
                many = True
            )
        data = {
            "external_reports": external_report_serializer.data,
            "internal_reports": internal_report_serializer.data
        }
        return Response(data, status=status.HTTP_200_OK)


class ReportDetailApiView(APIView):
    """
    fetech or delete a report object
    """
    authentication_classes = (CustomAuthentication,)
    permission_classes = (IsAuthenticated,)
    serializer_class = ReportDetailSerializer

    def get_object(self):
        try:
            reports = Reports.objects.get(
                id=self.kwargs.get('id')
                )
        except:
            reports = None
        return reports

    def get(self, request, *args, **kwargs):
        rep_obj = self.get_object()
        if rep_obj:
            serializer = self.serializer_class(
                rep_obj
            )
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(status=status.HTTP_400_BAD_REQUEST)


    def delete(self, request, *args, **kwargs):
        rep_obj = self.get_object()
        if rep_obj:
            rep_obj.delete()
            return Response(status=status.HTTP_200_OK)
        return Response(status=status.HTTP_400_BAD_REQUEST)


class RegistraionMail(APIView):
    authentication_classes = (CustomAuthentication,)
    permission_classes = (IsAuthenticated,)

    def post(self, request, *args, **kwargs):
        username =  self.request.data.get('username')
        user_email =  self.request.data.get('user_email')
        purpleleaf_user = PurpleleafUsers.objects.get(user_email = user_email)
        purpleleaf_user.active = True
        purpleleaf_user.save()
        clint_conf_obj = ClientConfiguration.objects.first()
        notification_list = list()
        emails = NotificationEmails.objects.all()
        try:
            for email in emails:
                notification_list.append(email)
                html_content = "[{0}] has registered".format(username)
                subject = "[{0}] User registered".format(clint_conf_obj.client_name)
                reciever = notification_list 
                send_mail(reciever, subject, html_content)
        except:
            pass           
        return Response(status=status.HTTP_200_OK)


class UpdateCountListApi(APIView):
    """
    ## Ensures we can get count of host, applications, cloudassets, networks, domains
    """
    authentication_classes = (CustomAuthentication,)
    permission_classes = (IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        """
        ## Note: 
        We are providing custom auth for the api's so add "data-auth-key" in the request header
        ### Response(Error with no key)
        ```
        {
            "detail": "Authentication credentials were not provided."
        }
        ```
        ### Response(Error with invalid key)
        ```
        {
            "detail": "Invalid Authentication key provided"
        }
        ```
        ### Response(Success)
        ```
        {
             "network_detail": [
                {
                    "id": 68,
                    "network": "External Network",
                    "network_type": "External"
                },
                {
                    "id": 105,
                    "network": "test1",
                    "network_type": "External"
                }
            ],
            "total_network": 3,
            "total_host": 37,
            "total_assets": 4,
            "total_applications": 1,
            "total_domains": 11
        }
        ```
        """
        response = dict()
        total_hosts = 0
        hosts_count = UserHosts.objects.all().aggregate(
            hosts_sum=Sum('count')
        )
        if hosts_count['hosts_sum']:
            total_hosts = hosts_count['hosts_sum']
        else:
            total_hosts = 0
        total_applications = Applications.objects.all().count()
        total_assets = CloudAssetsData.objects.all().count()
        total_domains = Domains.objects.all().count()
        networks = Networks.objects.all()
        network_detail = NetworkSerializer(networks, many=True)
        total_network = networks.count()
        response = {
            'total_host': total_hosts,
            'total_applications': total_applications,
            'total_assets': total_assets,
            'total_domains': total_domains,
            'total_network': total_network,
            'network_detail': network_detail.data,
        }
        return Response(response, status=status.HTTP_200_OK)


class SubHostInfoListApi(APIView):
    """
    ## Ensures we can get detail of subhosts for a particular host
    """
    authentication_classes = (CustomAuthentication,)
    permission_classes = (IsAuthenticated,)

    def get(self, request, host_id, *args, **kwargs):
        """
        ## Note: 
        We are providing custom auth for the api's so add "data-auth-key" in the request header
        ### Response(Error with no key)
        ```
        {
            "detail": "Authentication credentials were not provided."
        }
        ```
        ### Response(Error with invalid key)
        ```
        {
            "detail": "Invalid Authentication key provided"
        }
        ```
        ### Response(Success)
        ```
        [
            {
                "ip": "10.3.2.1",
                "id": ""
            },
            {
                "ip": "10.3.2.2",
                "id": ""
            }
        ]
        ```
        """
        try:
            host_obj = UserHosts.objects.get(pk=host_id)
        except:
            host_obj = None
        ips = list()
        ips = [{'ip': '', 'id': ''}]
        if host_obj and host_id:
            host_type = host_obj.host_type
            if host_type == "host_name":
                ips = get_host_name_range(host_obj.host)[:300]
            elif host_type == "cidr":
                ips = get_cidr_range(host_obj.host)[:300]

            elif host_type == "loose_a":
                ips = get_loose_a_range(host_obj.host)[:300]
            elif host_type == "loose_b":
                ips = get_loose_b_range(host_obj.host)[:300]
        return Response(ips, status=status.HTTP_200_OK)


class DashBoardAPIView(APIView):
    authentication_classes = (CustomAuthentication,)
    permission_classes = (IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        external_appliance_obj = Appliances.objects.filter(
            network_type="External"
        ).first()
        internal_appliance_obj = Appliances.objects.filter(
            network_type="Internal"
        ).first()
        if external_appliance_obj:
            external_appliance = external_appliance_obj.appliance_ip
        else:
            external_appliance = None
        if internal_appliance_obj:
            internal_appliance = internal_appliance_obj.source_ip
        else:
            internal_appliance = "N/A"
        activity_objs = ActivityLog.objects.all().order_by('-id')
        activity_serializer = ActivityLogSerializer(
            activity_objs,
            many=True
        )
        configurationObj = ClientConfiguration.objects.first()
        vul_obj = Vulnerability.objects.all()
        vulnerabilities_obj = vul_obj.order_by('-created').exclude(risk='Note')[:6]
        detail = VulnerabilityPartialDetailSerializer(vulnerabilities_obj, many=True)
        critical_vul = vul_obj.filter(risk="Critical").count()
        high_vul = vul_obj.filter(risk="High").count()
        medium_vul = vul_obj.filter(risk="Medium").count()
        low_vul = vul_obj.filter(risk="Low").count()
        active_ips = vul_obj.values_list('host_ip', flat=True).distinct().count()
        open_ports = vul_obj.filter(title__icontains="Open TCP Port").count()
        latest_service_identified = vul_obj.filter(
            title__icontains="Open TCP Port"
        ).order_by('-created')[:5]
        latest_vulnerabilities = VulnerabilityPartialDetailSerializer(
            latest_service_identified,
            many=True
        )
        try:
            manual_percent = ((float(configurationObj.manual_hours_remaining)\
                / int(configurationObj.manual_hours_purchased)) *100)
        except:
            manual_percent = None
        try:
            ips_percent = ((float(active_ips) / float(configurationObj.max_ips))* 100)
        except:
            ips_percent = None
        if manual_percent == 0 and ips_percent == 0:
            manual_percent = None
            ips_percent = None
        data = {
            'critical': vul_obj.filter(risk="Critical").count(),
            'high': vul_obj.filter(risk="High").count(),
            'medium': vul_obj.filter(risk="Medium").count(),
            'low': vul_obj.filter(risk="Low").count(),
            'active_ips': vul_obj.values_list('host_ip', flat=True).distinct().count(),
            'open_ports': vul_obj.filter(title__icontains="Open TCP Port").count(),
            'vulnerabilities_table': detail.data,
            'latest_service_identified': latest_vulnerabilities.data,
            'ips_percent': ips_percent,
            'manual_percent': manual_percent,
            'internal_appliance': internal_appliance,
            'external_appliance': external_appliance,
            'activity': activity_serializer.data
            }
        return Response(data=data, status=status.HTTP_200_OK)


class PurpleleafHistoryAPIView(APIView):
    authentication_classes = (CustomAuthentication,)
    permission_classes = (IsAuthenticated,)
    activity_serializer_class = ActivityLogSerializer
    vul_serializer_class = ClosedVulnerabilitiesSerializer
    archive_serializer = ArchiveVulnerabilitiesSeralizer

    def get(self, request, *args, **kwargs):
        """
        ## Note: 
        We are providing custom auth for the api's so add "data-auth-key" in the request header
        ### Response(Error with no key)
        ```
        {
            "detail": "Authentication credentials were not provided."
        }
        ```
        ### Response(Error with invalid key)
        ```
        {
            "detail": "Invalid Authentication key provided"
        }
        ```
        ### Response(Success)
        ```
        {
            "status": true,
            "status_code": 200,
            "data": {
                "closed_vulnerabilities": [
                    {
                        "title": "This is test vuln",
                        "host": "10.0.2.3",
                        "port": 80,
                        "risk": "Critical",
                        "retest_note": "test note",
                        "closed_date": "2019-04-10 04:12:AM"
                    }
                ],
                "activity": [
                    {
                        "activity": "Test",
                        "created_at": "2019-04-10 05:56:AM"
                    }
                ]
            }
        }
        ```
        """
        activity_obj = ActivityLog.objects.all().order_by('-id')
        activity_serializer = self.activity_serializer_class(
            activity_obj,
            many=True
            )
        closed_vul = ClosedVulnerabilities.objects.all()
        vul_serializer = self.vul_serializer_class(
            closed_vul,
            many=True
            )
        archived_vul = ArchiveVulnerabilities.objects.all()
        archived_serializer = self.archive_serializer(
            archived_vul,
            many=True
        )
        data = {
            'status': True,
            'status_code': 200,
            'data': {
                'activity': activity_serializer.data,
                'closed_vulnerabilities': vul_serializer.data,
                'archive_vulnerabilities' : archived_serializer.data
            }
        }
        return Response(data, status=status.HTTP_200_OK)


class HostVulnerabilityDetailAPIView(APIView):
    """
    Get details of a vulnerability 
    """
    authentication_classes = (CustomAuthentication,)
    permission_classes = (IsAuthenticated,)
    vuln_serializer_class = VulnerabilityDetailSerailizer

    def get_object(self):
        try:
            vulnerability_obj = Vulnerability.objects.get(
                id = self.kwargs.get('vul_id')
                )
        except:
            vulnerability_obj = None
        return vulnerability_obj

    def get(self, request, *args, **kwargs):
        """
        ## Note: 
        We are providing custom auth for the api's so add "data-auth-key" in the request header
        ### Response(Error with no key)
        ```
        {
            "detail": "Authentication credentials were not provided."
        }
        ```
        ### Response(Error with invalid key)
        ```
        {
            "detail": "Invalid Authentication key provided"
        }
        ```
        ### Response(Success)
        ```
        {
            "vulnerability": {
                "id": 52,
                "title": "This is test vuln",
                "formatted_description": "<h1>Test case</h1>",
                "formatted_remediation": "<h1>Test case</h1>",
                "formatted_evidence": "<h1>Test case</h1>",
                "virtue_id": 50001,
                "port": "80",
                "host_ip": "10.0.2.3",
                "banner": null,
                "retest": "Closed",
                "retest_notes": [
                    {
                        "note": "This is test",
                        "status": "Leave_Open",
                        "created": "Apr 10 2019 03:51AM"
                    },
                    {
                        "note": "Test",
                        "status": "Leave_Open",
                        "created": "Apr 10 2019 03:58AM"
                    },
                    {
                        "note": "Close",
                        "status": "Closed",
                        "created": "Apr 10 2019 02:17AM"
                    }
                ]
            }
        }
        ```
        """
        vul_obj = self.get_object()
        if vul_obj:
            serializer = self.vuln_serializer_class(
                vul_obj,
            )
            context = {
                'vulnerability': serializer.data
            }
            return Response(context, status=status.HTTP_200_OK)
        return Response(status=status.HTTP_400_BAD_REQUEST)


class AWSKeyStatusAPIView(APIView):
    """
    Get aws key status 
    """
    authentication_classes = (CustomAuthentication,)
    permission_classes = (IsAuthenticated,)

    def get_object(self):
        try:
            return ClientAwsAssets.objects.get(
                id = self.kwargs.get('id')
            )
        except:
            response_data = {
                'status': False,
                'message': "No such AWS asset available please refresh the page."
            }
            raise NotFound(response_data)

    def get(self, request, *args, **kwargs):
        """
        ## Note: 
        We are providing custom auth for the api's so add "data-auth-key" in the request header
        ### Response(Error with no key)
        ```
        {
            "detail": "Authentication credentials were not provided."
        }
        ```
        ### Response(Error with invalid key)
        ```
        {
            "detail": "Invalid Authentication key provided"
        }
        ```
        ### Response(Success)
        ```
        {
            "vulnerability": {
                "id": 52,
                "title": "This is test vuln",
                "formatted_description": "<h1>Test case</h1>",
                "formatted_remediation": "<h1>Test case</h1>",
                "formatted_evidence": "<h1>Test case</h1>",
                "virtue_id": 50001,
                "port": "80",
                "host_ip": "10.0.2.3",
                "banner": null,
                "retest": "Closed",
                "retest_notes": [
                    {
                        "note": "This is test",
                        "status": "Leave_Open",
                        "created": "Apr 10 2019 03:51AM"
                    },
                    {
                        "note": "Test",
                        "status": "Leave_Open",
                        "created": "Apr 10 2019 03:58AM"
                    },
                    {
                        "note": "Close",
                        "status": "Closed",
                        "created": "Apr 10 2019 02:17AM"
                    }
                ]
            }
        }
        ```
        """
        response = {
            "aws_status": "Loading"
        }
        aws_asset_obj = self.get_object()
        if aws_asset_obj:
            if not aws_asset_obj.scan_status and\
                    aws_asset_obj.scan_state == "NotInitiated":
                check_aws_asset_status.delay(aws_asset_id=aws_asset_obj.id)
            if aws_asset_obj.scan_status and aws_asset_obj.scan_state == "Completed":
                response['aws_status'] = "success"
                response['status'] = True
            elif aws_asset_obj.scan_state in ["Running", "NotInitiated"] and\
                    not aws_asset_obj.scan_status:
                response['aws_status'] = "Loading"
                response['status'] = True
            elif aws_asset_obj.scan_state == "Error" and\
                    aws_asset_obj.scan_status:
                response['aws_status'] = "Error"
                response['status'] = True
            return Response(response, status=status.HTTP_200_OK)
        else:
            return Response(status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, *args, **kwargs):
        """
        ## Note: 
        We are providing custom auth for the api's so add "data-auth-key" in the request header
        ### Response(Error with no key)
        ```
        {
            "detail": "Authentication credentials were not provided."
        }
        ```
        ### Response(Error with invalid key)
        ```
        {
            "detail": "Invalid Authentication key provided"
        }
        ```
        """
        aws_asset_obj = self.get_object()
        aws_asset_obj.delete()
        response = {
            'status': True,
            'status_code': 204,
            'message': 'Aws Assets deleted successfully.'
        }
        return Response(response, status=status.HTTP_200_OK)


class LogPurpleleafUserActivityCreateAPIView(CreateAPIView):
    """
    To log all pages visited by purpleleaf user
    """
    authentication_classes = (CustomAuthentication,)
    permission_classes = (IsAuthenticated,)
    serializer_class = LogPurpleleafUserActivitySerializer

    def post(self, request, *args, **kwargs):
        """
        ## Note: 
        We are providing custom auth for the api's so add "data-auth-key" in the request header
        ### Response(Error with no key)
        ```
        {
            "detail": "Authentication credentials were not provided."
        }
        ```
        ### Response(Error with invalid key)
        ```
        {
            "detail": "Invalid Authentication key provided"
        }
        ```
        ### Body
        ```
        {
            "username": "rajinder.ameo@gmail.com",
            "time_stamp": "2019-04-08 11:40 AM",
            "event_type": "http://localhost:8001/hosts/",
            "ip": "127.0.0.1"
        }

        ```
        ### Response(Success)
        ```
        {
            "status": true,
            "status_code": 201,
            "message": "Activity registered successfully.",
            "data": {
                "event_type": "http://localhost:8001/hosts/",
                "time_stamp": "2019-04-08 11:40 AM",
                "username": "rajinder.ameo@gmail.com",
                "ip": "127.0.0.1"
            }
        }
        ```
        """
        data = request.data.copy()
        serializer = self.serializer_class(data=data)
        if serializer.is_valid():
            serializer.save()
            response = {
                'status': True,
                'message': "Activity registered successfully.",
                'status_code': 201,
                'data': serializer.data
            }
            return Response(
                response,
                status=status.HTTP_201_CREATED
            )
        response = {
            'status': False,
            'message': "Unable to register Activity.",
            'status_code': 400,
            'errors': serializer.errors
        }
        return Response(
            response,
            status=status.HTTP_400_BAD_REQUEST
        )


class ApplicationVulnerabilityAPIView(APIView):
    """
    Get data of a application vulnerability 
    """
    authentication_classes = (CustomAuthentication,)
    permission_classes = (IsAuthenticated, )
    serializer_class = ApplicationVulnerabilitySerializer
    data_serializer_class =ApplicationHostSerializer

    def get_app_object(self):
        app_id = self.kwargs.get('id')
        try:
            app_obj = Applications.objects.get(
                id=app_id
            )
        except:
            app_obj = None
        return app_obj

    def get_object(self):
        app_id = self.kwargs.get('id')
        return ApplicationVulnerability.objects.filter(
                application_id=app_id
                ).annotate(instances=Count('title')
            )

    def get(self, request, *args, **kwargs):
        """
        ## Note:
        We are providing custom auth for the api's so add "data-auth-key" in the request header
        ### Response(Error with no key)
        ```
        {
            "detail": "Authentication credentials were not provided."
        }
        '''
        ### Response(Error with invalid key)
        ```
        {
            "detail": "Invalid Authentication key provided"
        }
        ```
        ### Response(Success)
        ```
        {
            

        }
        ```
        """
        app_vul_obj =  self.get_object()
        app_obj =  self.get_app_object()
        serializer = self.serializer_class(
                app_vul_obj,
                many = True
            )
        app_host_serializer = self.data_serializer_class(
                app_obj
            )
        context = {
            'app_vul_obj': serializer.data,
            'app_obj': app_host_serializer.data
        }
        return Response(context, status=status.HTTP_200_OK)


class ApplicationVulnerabilityDetailAPIView(APIView):
    """
    Get the all details of Applicaton Vulnerability
    """
    authentication_classes = (CustomAuthentication,)
    permission_classes = (IsAuthenticated, )
    app_vul_serializer_class = ApplicationVulnerabilityDetailSerializer

    def get_object(self):
        app_id = self.kwargs.get('id')
        virtue_id = self.kwargs.get('virtue_id')
        return ApplicationVulnerability.objects.filter(
            application_id=app_id,
            virtue_id=virtue_id
        )

    def get(self, request, *args, **kwargs):

        application_vul_obj = self.get_object()
        if application_vul_obj:
            serializer = self.app_vul_serializer_class(
                application_vul_obj,
                many=True
            )
            context = {
                'application_vul_obj': serializer.data[0],
                'application_vul': serializer.data
            }
            return Response(context, status=status.HTTP_200_OK)
        return Response(status=status.HTTP_400_BAD_REQUEST)


class HostVulnerabilitiesAPIView(APIView):
    """
    ## List all the available sorted vulnerabilities corresponding to an host
    """
    authentication_classes = (CustomAuthentication,)
    permission_classes = (IsAuthenticated,)
    serializer_class = HostDetailSerializer

    def get_object(self):
        host_id = self.kwargs.get('host_id')
        try:
            return Host.objects.get(id=host_id)
        except:
            response = {
                'status': False,
                'status_code': 404,
                'message': 'Host not found.'
            }
            raise NotFound(
                response,
                code=status.HTTP_404_NOT_FOUND
            )

    def get(self, request, *args, **kwargs):
        """
        ## Note: 
           We are providing custom auth for the api's so add "data-auth-key" in the request header
        ### Response(Error with invalid key)
        ```
        {
            "detail": "Invalid Authentication key provided"
        }
        ```
        ### Response(Error with no key)
        ```
        {
            "detail": "No Authentication key provided"
        }
        ```
        ### Response(Success)
        ```
        {
            "vulnerabilities": [
                {
                    "risk": "Medium",
                    "title": "Weak Ciphers Supported",
                    "host_ip": "23.94.236.79",
                    "risk_factor": 2,
                    "instances": 1,
                    "host_id": "1393",
                    "virtue_id": 19
                },
                {
                    "risk": "Low",
                    "title": "Web Server Version Disclosed",
                    "host_ip": "165.227.183.108",
                    "risk_factor": 1,
                    "instances": 1,
                    "host_id": "1393",
                    "virtue_id": 1
                }
            ],
            "host_ip": "23.94.236.79"
        }
        ```
        ### Curl 
        ```
        Curl: curl -H "data-auth-key: redtree-auth-key" http://localhost:8000/private/vulnerabilities/host/host_id/
        ```
        """
        host = self.get_object()
        serializer = self.serializer_class(host)
        json_data = {
            'data': serializer.data
        }
        return Response(json_data, status=status.HTTP_200_OK)


class HostVulnerabilitiesDetailAPIView(APIView):
    """
    ## List All the vulnerabilities with a given virtue id and corresponding to one host
    """
    authentication_classes = (CustomAuthentication,)
    permission_classes = (IsAuthenticated,)
    serializer_class = VulnerabilityPartialDetailSerializer
    vuln_serializer_class = VulnerabilityDetailSerailizer

    def get_object(self):
        host_id = self.kwargs.get('host_id')
        virtue_id = self.kwargs.get('virtue_id')
        try:
            host_obj = Host.objects.get(id=int(host_id))
        except:
            response = {
                'status': False,
                'status_code': 404,
                'message': 'Host not found.'
            }
            raise NotFound(
                response,
                code=status.HTTP_404_NOT_FOUND
            )

        return Vulnerability.objects.filter(
            host=host_obj,
            virtue_id=virtue_id
        )

    def get(self, request, *args, **kwargs):
        """
        ### List All the vulnerabilities with a given virtue id corresponding to one host
        ### Note: 
           We are providing custom auth for the api's so add "data-auth-key" in the request header
        ### Response(Error with invalid key)
        ```
        {
            "detail": "Invalid Authentication key provided"
        }
        ```
        ### Response(Error with no key)
        ```
        {
            "detail": "No Authentication key provided"
        }
        ```
        ### Response(Success)
        ```
                {
            "vulnerability": {
                "id": 5480,
                "title": "Weak Ciphers Supported",
                "formatted_description": "Description",
                "formatted_remediation": "Remediation",
                "virtue_id": 19,
                "port": "25",
                "host_ip": "23.94.236.73",
                "banner": "",
                "retest": null,
                "retest_notes": []
            },
            "banner": false,
            "affected_hosts": [
                {
                    "id": 5480,
                    "title": "Weak Ciphers Supported",
                    "virtue_id": 19,
                    "host_ip": "23.94.236.73",
                    "risk": "Medium",
                    "port": "25",
                    "banner": "",
                    "retest": null,
                    "created": "2019-05-28 04:53:AM",
                    "modified": "2019-05-28 04:53:AM",
                    "host_id": 1392
                }
            ]
        }
        ```
        ## Curl
        ```
        curl -H "data-auth-key: redtree-auth-key" http://localhost:8000/private/vulnerabilities/virtue_id/host/host_id/
        ```
        """
        vul_obj = self.get_object()
        if vul_obj:
            vulnerability = vul_obj.first()
        else:
            vulnerability = None
        banner_count = 0
        banner_exist = False
        for banner in vul_obj:
            if banner.banner:
                banner_count = banner_count + 1
        if banner_count > 0:
            banner_exist = True
        else:
            banner_exist = False
        serializer = self.serializer_class(
            vul_obj,
            many=True
        )
        vuln_serializer = self.vuln_serializer_class(
            vulnerability
        )
        context = {
            'affected_hosts': serializer.data,
            'vulnerability': vuln_serializer.data,
            'banner': banner_exist
        }
        return Response(context, status=status.HTTP_200_OK)


def get_aws_pass_count(cloud_storage_data):
    pass_count = 0
    for cloud_storage_obj in cloud_storage_data:
        data_status_list = list()
        data_status_list.append(
            cloud_storage_obj.get('unauthenticated_data_status')
        )
        data_status_list.append(
            cloud_storage_obj.get('authenticated_data_status')
        )
        if not ('fail' in data_status_list or None in data_status_list):
            pass_count = pass_count + 1
    return pass_count


class CloudStorageDetailAPIView(APIView):
    authentication_classes = (CustomAuthentication,)
    permission_classes = (IsAuthenticated, )
    cloud_storage_serializer_class = CloudStorageSerializer
    aws_api_gateway_serializer_class = AwsApiGatewaySerializer
    aws_rds_serializer_class = AwsRdsSerializer
    aws_domains_serializer_class = AwsDomainSerializer

    def get(self, request, *args, **kwargs):
        """
        ### List All the cloudstorage data
        ### Note:
           We are providing custom auth for the api's so add "data-auth-key" in the request header
        ### Response(Error with invalid key)
        ```
        {
            "detail": "Invalid Authentication key provided"
        }
        ```
        ### Response(Error with no key)
        ```
        {
            "detail": "No Authentication key provided"
        }
        ```
        ### Response(Success)
        ```
        {
            "status": true,
            "status_code": 200,
            "message": "data fetech successfully",
            "data": {
                "aws_api_gateway_count": 1,
                "aws_rds_data": [],
                "s3_pass_percentage": 33.33333333333333,
                "aws_token_loaded_status": true,
                "s3_bucket_count": 3,
                "aws_rds_databases_count": 0,
                "aws_api_data": [
                    {
                        "id": 6,
                        "api_url": "https://qkhzxg4ll6.execute-api.us-east-1.amazonaws.com/beta",
                        "region": null,
                        "created": "2019-05-27T06:15:58.330755-05:00"
                    }
                ],
                "cloud_storage_data": [
                    {
                        "id": 97,
                        "bucket": "kjhasdkjhadakjd",
                        "last_scan": "26 07, 2019, 05:26 AM",
                        "unauthenticated_data_status": null,
                        "authenticated_data_status": null
                    },
                    {
                        "id": 99,
                        "bucket": "wallyworld-canada-bucket1",
                        "last_scan": "26 07, 2019, 05:26 AM",
                        "unauthenticated_data_status": "pass",
                        "authenticated_data_status": "pass"
                    },
                    {
                        "id": 98,
                        "bucket": "flaws.cloud",
                        "last_scan": "26 07, 2019, 05:26 AM",
                        "unauthenticated_data_status": "fail",
                        "authenticated_data_status": "fail"
                    }
                ],
                "aws_domains_data": []
            }
        }
        ```
        ## Curl
        ```
        curl -H "data-auth-key: redtree-auth-key" https://acmebankredtree.purpleleafdev.io/private/cloud/
        ```
        """
        if ClientAwsAssets.objects.all().count() > 0:
            aws_token_loaded_status = True
        else:
            aws_token_loaded_status = False


        assetsObj = CloudAssetsData.objects.all()
        cloud_storage_objs = assetsObj.filter(category='S3')
        gcp_obj = assetsObj.filter(category="GCP")
        azure_obj = assetsObj.filter(category="Azure")

        
        gcp_serializer = CloudAssetSerializer(
            gcp_obj,
            many=True
            )

        azure_serializer = CloudAssetSerializer(
            azure_obj,
            many=True
            )

        cloud_storage_serializer = self.cloud_storage_serializer_class(
            cloud_storage_objs,
            many = True
        )
        cloud_storage_data = cloud_storage_serializer.data
        s3_bucket_count = CloudAssetsData.objects.filter(
            category="S3"
        ).count()

        aws_objs = AwsApiGateway.objects.all()
        aws_api_serialiezr = self.aws_api_gateway_serializer_class(
            aws_objs,
            many = True
        )
        aws_api_data = aws_api_serialiezr.data

        aws_rds_objs = AwsRdsEndpoint.objects.all()
        aws_rds_serializer = self.aws_rds_serializer_class(
            aws_rds_objs,
            many = True
        )
        aws_rds_data = aws_rds_serializer.data

        aws_domains_objs = AwsDomains.objects.all()
        aws_domain_serializer = self.aws_domains_serializer_class(
            aws_domains_objs,
            many=True
        )
        aws_domains_data = aws_domain_serializer.data

        pass_count = 0
        s3_pass_percentage = 0
        pass_count = get_aws_pass_count(cloud_storage_data)
        cloud_storage_count =  cloud_storage_objs.count()

        try:
            s3_pass_percentage = float(pass_count)/float(cloud_storage_count)*100
        except ZeroDivisionError:
            s3_pass_percentage = 0



        data = {
            'cloud_storage_data': cloud_storage_data,
            'gcp_serializer_data':gcp_serializer.data,
            'azure_serializer_data':azure_serializer.data,
            'aws_api_data': aws_api_data,
            'aws_rds_data': aws_rds_data,
            'aws_domains_data': aws_domains_data,
            's3_bucket_count': s3_bucket_count,
            's3_pass_percentage': s3_pass_percentage,
            'aws_token_loaded_status': aws_token_loaded_status,
            'aws_api_gateway_count': aws_objs.count(),
            'aws_rds_databases_count': aws_rds_objs.count()
        }

        response = {
            'status': True,
            'status_code': 200,
            'message': 'data fetech successfully',
            'data': data
        }
        return Response(
            response,
            status=status.HTTP_200_OK
        )


class CloudAssetDetailAPIView(APIView):
    authentication_classes = (CustomAuthentication,)
    permission_classes = (IsAuthenticated, )
    serializer_class = CloudStorageScanSerializer

    def get(self, request, *args, **kwargs):
        """
        ### List All the cloudsasset corresponding to particular bucket
        ### Note:
           We are providing custom auth for the api's so add "data-auth-key" in the request header
        ### Response(Error with invalid key)
        ```
        {
            "detail": "Invalid Authentication key provided"
        }
        ```
        ### Response(Error with no key)
        ```
        {
            "detail": "No Authentication key provided"
        }
        ```
        ### Response(Success)
        ```
        {
            "status": true,
            "status_code": 200,
            "message": "data fetech successfully",
            "data": {
                "cloud_asset_data": [
                    {
                        "id": 1730,
                        "cloud_asset_bucket": 98,
                        "bucket_name": null,
                        "unauthenticated_status": false,
                        "authenticated_status": false,
                        "file": "secret-dd02c7c.html",
                        "bucket": "flaws.cloud"
                    },
                    {
                        "id": 1706,
                        "cloud_asset_bucket": 98,
                        "bucket_name": "s3:GetBucketAcl",
                        "unauthenticated_status": true,
                        "authenticated_status": true,
                        "file": null,
                        "bucket": "flaws.cloud"
                    }
                ],
                "cloud_storage_files": [
                    {
                        "id": 1730,
                        "cloud_asset_bucket": 98,
                        "bucket_name": null,
                        "unauthenticated_status": false,
                        "authenticated_status": false,
                        "file": "secret-dd02c7c.html",
                        "bucket": "flaws.cloud"
                    },
                    {
                        "id": 1724,
                        "cloud_asset_bucket": 98,
                        "bucket_name": null,
                        "unauthenticated_status": false,
                        "authenticated_status": false,
                        "file": "hint1.html",
                        "bucket": "flaws.cloud"
                    }
                ]
            }
        }
        ```
        ## Curl
        ```
        curl -H "data-auth-key: redtree-auth-key" https://acmebankredtree.purpleleafdev.io/private/cloud/s3/cloud_asset_id/
        ```
        """

        cloud_asset_id = kwargs.get('cloud_asset_id')
        cloud_storage_bucket_objs = CloudstorageScanData.objects.filter(
            Q(cloud_asset_bucket__id=cloud_asset_id) &
            (Q(bucket_name__isnull=False) | ~Q(bucket_name=""))
        )
        cloud_storage_file_objs = CloudstorageScanData.objects.filter(
            cloud_asset_bucket__id=cloud_asset_id,
            file__isnull=False
        )
        cloud_asset_data_serializer = self.serializer_class(
            cloud_storage_bucket_objs,
            many=True
        )
        cloud_storage_files_serializer = self.serializer_class(
            cloud_storage_file_objs,
            many=True
        )
        data = {
            'cloud_asset_data': cloud_asset_data_serializer.data,
            'cloud_storage_files': cloud_storage_files_serializer.data
        }

        response = {
            'status': True,
            'status_code': 200,
            'message': 'data fetech successfully',
            'data': data
        }
        return Response(
            response,
            status=status.HTTP_200_OK
        )


class UpdateApplicationScanStatusApiView(APIView):
    """
    This is to update scan status of application
    """
    authentication_classes = (CustomAuthentication,)
    permission_classes = (IsAuthenticated,)
    serializer_class = ApplicationScanStatusUpdateSerializer

    def get_app_object(self):
        application_id = self.kwargs.get('application_id')
        try:
            return Applications.objects.get(
                id=application_id
            )
        except:
            response = {
                'status': False,
                'status_code': 404,
                'message': 'Application not found.'
            }
            raise NotFound(
                response,
                code=status.HTTP_404_NOT_FOUND
            )

    def post(self, request, *args, **kwargs):
        """
        ## Note:
        We are providing custom auth for the api's so add "data-auth-key" in the request header
        ### Response(Error with no key)
        ```
        {
            "detail": "Authentication credentials were not provided."
        }
        ```
        ### Response(Error with invalid key)
        ```
        {
            "detail": "Invalid Authentication key provided"
        }
        ```
        ### Response(Success)
        ```
        {
            "status": true,
            "status_code": 200,
            "message": "Application Scanning Status updated successfully.",
            "data": {
                "id": 814,
                "scanning_enabled": true,
                "scan_status": "Active"
            }
        }
        ```
        ### Response(Error)
        ```
        {
            "status": "False",
            "status_code": "404",
            "message": "Application not found."
        }
        ```
        """
        data = request.data.copy()
        scan_status = False
        application = self.get_app_object()
        scan_status_value = data.get('scan_status')
        if scan_status_value == "Active":
            scan_status = True
        elif scan_status_value == "Inactive":
            scan_status = False
        serializer = self.serializer_class(
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

            return Response(
                response,
                status=status.HTTP_200_OK
            )
        response = {
            'status': False,
            'status_code': 400,
            'message': 'Unable to update Application Scanning Status.',
            'errors': serializer.errors
        }
        return Response(
            response,
            status=status.HTTP_400_BAD_REQUEST
        )


class EncryptionCertificateApi(APIView):
    authentication_classes = (CustomAuthentication,)
    permission_classes = (IsAuthenticated,)
    serializer_class = SslyzeCertificatesSerializer

    def get(self, request, *args, **kwargs):
        certificates = SslyzeCertificates.objects.all().order_by('-id')
        serializer = self.serializer_class(
            certificates,
            many = True
        )
        json_data = {
            "certificate_data": serializer.data,
        }
        return Response(json_data, status=status.HTTP_200_OK)


class EncyptionCiphersApi(APIView):
    authentication_classes = (CustomAuthentication,)
    permission_classes = (IsAuthenticated,)

    def get_raw_ciphers(self, *args, **kwargs):
        host_id = self.request.query_params.get('host')
        if host_id:
            try:
                host_obj = Host.objects.get(pk=host_id)
                host = host_obj.host
                ciphers = Ciphers.objects.filter(
                    host=host_obj.host,
                    key_size__isnull=False).values(
                        'key_size','cipher','strength', 'protocol'
                    ).annotate(cipher_count=Count('host','port'))
                return host,ciphers
            except:
                host = None
                ciphers = Ciphers.objects.filter(key_size__isnull=False).values(
                    'key_size','cipher','strength', 'protocol'
                ).annotate(
                    cipher_count=Count('host','port')
                )
                return host,ciphers
        host = None
        ciphers = Ciphers.objects.filter(key_size__isnull=False).values(
            'key_size','cipher','strength', 'protocol'
            ).annotate(
                cipher_count=Count('host','port')
            )
        return host,ciphers


    def get(self, request, *args, **kwargs):
        https_enc_count = Ciphers.objects.filter(
            key_size__isnull=False
        ).distinct('host','port').count()
        ssh_enc_count = SshyzeCiphers.objects.all().distinct('host','port').count()
        host,raw_ciphers = self.get_raw_ciphers()
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
        sorted_by_count_ciphers =  sorted(ciphers, key=lambda x: x['cipher_count'], reverse=True) #sorting on secondary key
        sorted_ciphers = sorted(sorted_by_count_ciphers, key=lambda x: x['key_size'], reverse=True) #sorting on primary key 
        sorted_ciphers = sorted(sorted_ciphers, key=lambda x: x['risk_factor'], reverse=True) #sorting on risk 
        json_data = {
            "ciphers": sorted_ciphers,
        }
        return Response(json_data, status=status.HTTP_200_OK)