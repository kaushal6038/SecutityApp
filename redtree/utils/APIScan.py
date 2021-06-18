# -*- coding: utf-8 -*-
import requests
import time
from datetime import datetime
from urlparse import urlparse
import json

from redtree_app.models import *
from playground.models import *
import base64
from utils.helpers import (
    get_appliance
)
from urlparse import urlparse
import socket
from django.utils import timezone
from IPy import IP
from celery import task
from celery.utils.log import get_task_logger

logger = get_task_logger(__name__)


class ApiGatewayScanner:
    def __init__(self, api, appliance):
        self.api = api
        self.appliance_ip = appliance.appliance_ip
        self.scan_url = "https://{}/curl".format(self.appliance_ip)
        self.auth_username = appliance.appliance_setting.auth_username
        self.auth_password = appliance.appliance_setting.auth_password

        print(self.api.api_url)

    def start_scan(self):
        self.api.last_scan = timezone.now()
        self.api.save()
        request_data = {
            "url": self.api.api_url
        }
        try:
            response = requests.post(
                self.scan_url,
                auth=(self.auth_username, self.auth_password),
                json=request_data,
                timeout=240
            )
            print(response)
            if response and response.status_code == 200:
                self.process_result(response)
            else:
                error_message = "Appliance returned a {} error, check the Appliance".format(response.status_code)
                logger.error('{}'.format(error_message))
                AppNotification.objects.create(
                    issue_type='error',
                    notification_message=error_message
                )

        except requests.Timeout as timeout_exc:
            error_message = "Appliance is taking too long to respond."
            logger.error('{}'.format(error_message))
            AppNotification.objects.create(
                issue_type='error',
                notification_message=error_message
            )
        except requests.ConnectionError as conn_exec:
            error_message = "Appliance is down"
            logger.error('{}'.format(error_message))
            AppNotification.objects.create(
                issue_type='error',
                notification_message=error_message
            )

    def process_result(self, response):
        response = response.json()
        status_code = response.get("status")
        content = response.get("content")
        self.api.status_code = status_code  # Save the Status Code

        try:  # Check if scanner returns a content
            message = json.loads(content).get("message")
            if message:
                self.api.content = message  # Save Message Value
            else:
                self.api.content = content  # Save content if no key/value pair found
        except ValueError:
            self.api.content = content
        self.api.save()


def api_scan():
    api_objs = AwsApiGateway.objects.all()
    appliance = get_appliance("External")
    for api in api_objs:
        api_gateway_scan = ApiGatewayScanner(
            api,
            appliance
        )
        api_gateway_scan.start_scan()
