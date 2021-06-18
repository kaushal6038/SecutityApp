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


class MasscanRestApiDescriptor:
    def __init__(self, app_pk, rds_pk, response=None):
        appliance = Appliances.objects.get(pk=app_pk).appliance_setting
        rds_obj = AwsRdsEndpoint.objects.get(pk=rds_pk)
        host_ip = socket.gethostbyname(rds_obj.host)
        temp_ips = list()
        masscan_ports = list()
        temp_ips.append(host_ip)
        masscan_ports.append(rds_obj.port)

        self.response = response
        self.app_pk = app_pk
        self.rds_pk = rds_pk
        self.temp_ips = temp_ips
        self.masscan_ports = masscan_ports
        self.rds_obj = rds_obj
        self.auth_username = appliance.auth_username
        self.auth_password = appliance.auth_password
        self.parsed_uri = urlparse(appliance.masscan_ip_address)
        self.domain = '{uri.scheme}://{uri.netloc}/{prefix}'.format(
            uri=self.parsed_uri, prefix="masscan"
        )
        self.masscan_url = '{}/scan/new'.format(self.domain)

    def create_masscan(self):
        request_data = {
            "hosts": self.temp_ips,
            "ports": self.masscan_ports
        }
        print
        request_data
        results = {
            "Status": "COMPLETED",
        }
        curl_request = "curl -u {}:{} --header 'Content-Type: application/json' " \
                       "--request POST --data '{}' {}".format(
            self.auth_username,
            self.auth_password,
            json.dumps(request_data),
            self.masscan_url
        )
        print
        curl_request
        try:
            request_header = {
                "Content-Type": "application/json"
            }
            response = requests.post(
                self.masscan_url,
                auth=(self.auth_username, self.auth_password),
                json=request_data,
                headers=request_header,
                timeout=240,
            )
            print
            response
        except requests.Timeout as timeout_exc:
            error_message = "𝗘𝘅𝗰𝗲𝗽𝘁𝗶𝗼𝗻::  {} in masscan." \
                            "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   {}".format(
                timeout_exc,
                curl_request
            )

            AppNotification.objects.create(
                issue_type='error',
                notification_message=error_message
            )

            response = None
            results["Status"] = "FAILED"
            return results
        except Exception as error:
            error_message = "𝗘𝘅𝗰𝗲𝗽𝘁𝗶𝗼𝗻::    {} in masscan." \
                            "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   {}".format(
                error,
                curl_request
            )

            AppNotification.objects.create(
                issue_type='error',
                notification_message=error_message
            )

            response = None
            results["Status"] = "FAILED"
            return results
        print
        'response', response
        try:
            if response and response.status_code == 200:
                response = response.json()
                try:
                    error_message = response.get('exception')
                    print(error_message)
                except:
                    error_message = None
                if error_message:
                    message = "𝗘𝘅𝗰𝗲𝗽𝘁𝗶𝗼𝗻::  {} in masscan." \
                              "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀:: {}".format(
                        error_message,
                        curl_request
                    )

                    results["Status"] = "FAILED"
                    return results
                scan_url = self.domain + response["status_uri"]
                print("scan url" + scan_url)
                scan_id = response.get('scan_id')
                log = "Scan added you can check the status by status_url::\n{}".format(
                    scan_url
                )

                process_scan.delay(scan_url, self.auth_username, self.auth_password, self.app_pk, self.rds_pk)
            elif response.status_code == 400:
                try:
                    json_response = response.json()
                except:
                    json_response = None
                if json_response and json_response.get('error'):
                    error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) + \
                                    "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
                elif json_response and not json_response.get('error'):
                    error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:   " + str(json_response) + \
                                    "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
                elif response:
                    error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) + \
                                    "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
                elif response.text:
                    error_message = "(400 Bad Request).\n𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + \
                                    str(response.text) + "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
                else:
                    error_message = "(400 Bad Request)." + \
                                    "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request

                print
                'error_message', error_message
                results["Status"] = "FAILED"
                return results
            elif response.status_code == 401:
                try:
                    json_response = response.json()
                except:
                    json_response = None
                if json_response and json_response.get('error'):
                    error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) + \
                                    "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
                elif json_response and not json_response.get('error'):
                    error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:   " + str(json_response) + \
                                    "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
                elif response:
                    error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) + \
                                    "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
                elif response.text:
                    error_message = "(401 Unauthorized).\n𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + \
                                    str(response.text) + "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
                else:
                    error_message = "(401 Unauthorized)." + \
                                    "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request

                print
                'error_message', error_message
                results["Status"] = "FAILED"
                return results
            elif response.status_code == 404:
                try:
                    json_response = response.json()
                except:
                    json_response = None
                if json_response and json_response.get('error'):
                    error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) + \
                                    "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
                elif json_response and not json_response.get('error'):
                    error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:   " + str(json_response) + \
                                    "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
                elif response:
                    error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) + \
                                    "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
                elif response.text:
                    error_message = "(404 not found).\n𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + \
                                    str(response.text) + "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
                else:
                    error_message = "(404 not found)." + \
                                    "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request

                print
                'error_message', error_message
                results["Status"] = "FAILED"
                return results
            elif response.status_code == 504:
                try:
                    json_response = response.json()
                except:
                    json_response = None
                if json_response and json_response.get('error'):
                    error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) + \
                                    "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
                elif json_response and not json_response.get('error'):
                    error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:   " + str(json_response) + \
                                    "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
                elif response:
                    error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) + \
                                    "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
                elif response.text:
                    error_message = "(504 Gateway Timeout error).\n𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + \
                                    str(response.text) + "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
                else:
                    error_message = "(504 Gateway Timeout error)." + \
                                    "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request

                print
                'error_message', error_message
                results["Status"] = "FAILED"
                return results
            elif response.status_code == 500:
                try:
                    json_response = response.json()
                except:
                    json_response = None
                if json_response and json_response.get('error'):
                    error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) + \
                                    "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
                elif json_response and not json_response.get('error'):
                    error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:   " + str(json_response) + \
                                    "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
                elif response:
                    error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) + \
                                    "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
                elif response.text:
                    error_message = "(500 Internal Server Error).\n𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + \
                                    str(response.text) + "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
                else:
                    error_message = "(500 Internal Server Error)." + \
                                    "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request

                print
                'error_message', error_message
                results["Status"] = "FAILED"
                return results
            elif response.status_code == 502:
                try:
                    json_response = response.json()
                except:
                    json_response = None
                if json_response and json_response.get('error'):
                    error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) + \
                                    "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
                elif json_response and not json_response.get('error'):
                    error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:   " + str(json_response) + \
                                    "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
                elif response:
                    error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) + \
                                    "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
                elif response.text:
                    error_message = "(502 Bad Gateway).\n𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + \
                                    str(response.text) + "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
                else:
                    error_message = "(502 Bad Gateway)." + \
                                    "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request

                print
                'error_message', error_message
                results["Status"] = "FAILED"
                return results
            else:
                try:
                    json_response = response.json()
                except:
                    json_response = None
                if json_response and json_response.get('error'):
                    error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) + \
                                    "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
                elif json_response and not json_response.get('error'):
                    error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:   " + str(json_response) + \
                                    "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
                elif response:
                    error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) + \
                                    "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
                elif response.text:
                    error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + \
                                    str(response.text) + "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
                else:
                    error_message = "There is either a network connection problem " \
                                    "or the API itself is not returning data." \
                                    "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::  " + curl_request

                print
                'error_message', error_message
                results["Status"] = "FAILED"
                return results
        except Exception as e:
            print
            "Exception::..", e
            try:
                json_response = response.json()
            except:
                json_response = None
            if json_response and json_response.get('error'):
                error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) + \
                                "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
            elif json_response and not json_response.get('error'):
                error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:   " + str(json_response) + \
                                "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
            elif response:
                error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) + \
                                "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
            elif response.text:
                error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + \
                                str(response.text) + "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
            else:
                error_message = "There is either a network connection problem " \
                                "or the API itself is not returning data.." \
                                "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::  " + curl_request

            print
            'error_message', error_message
            results["Status"] = "FAILED"
            return results

    def process_result(self):
        results = {
            "Status": "COMPLETED",
        }

        result_uri = self.response.get("result_uri")
        result_url = self.domain + result_uri
        print
        result_url
        log = "Scan complete you can also check the results by\n{}".format(result_url)
        masscan_response = get_status(result_url, self.auth_username, self.auth_password)
        print
        masscan_response
        response = None
        if masscan_response.get('status'):
            try:
                response = masscan_response.get('response').json()
            except:
                response = None
        if response:
            masscan_data = response.get("results")
            if masscan_data:
                self.rds_obj.last_scan = timezone.now()
                self.rds_obj.scan_status = False  # Update If Port is Open
                self.rds_obj.save()
            else:
                self.rds_obj.last_scan = timezone.now()
                self.rds_obj.scan_status = True  # Port is closed
                self.rds_obj.save()


        elif response and (response.get('status') == "ERROR" or \
                           response.get('status') == "FAILED"):

            results["Status"] = response.get("status")
            try:
                json_response = response
            except:
                json_response = None
            if json_response and json_response.get('error'):
                error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error'))
            elif json_response and not json_response.get('error'):
                error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:   " + str(json_response)
            elif response:
                error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response)
            elif response.text:
                error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response.text)
            else:
                error_message = "There is either a network connection problem " \
                                "or the API itself is not returning data.." + \
                                "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   "
            AppNotification.objects.create(
                issue_type='error',
                notification_message=error_message
            )

            return results


@task(name='process_rds')
def process_scan(url, user, password, app_pk, rds_pk):
    rds_obj = AwsRdsEndpoint.objects.get(pk=rds_pk)
    scan_response = get_status(url, user, password)
    response_data = scan_response.get('response').json()
    print(response_data)
    if response_data.get('status') == 'PENDING':
        print('not ready')
        process_scan.apply_async([url, user, password, app_pk, rds_pk], countdown=10)
    else:
        scan_obj = MasscanRestApiDescriptor(app_pk, rds_pk, response_data)
        scan_obj.process_result()


def get_status(url, auth_username, auth_password):
    context = dict()
    context['status'] = False
    status_curl = "curl -u {}:{} --request GET {}".format(
        auth_username,
        auth_password,
        url
    )
    try:
        response = requests.get(
            url,
            auth=(auth_username, auth_password),
            timeout=240,
        )
    except requests.Timeout as timeout_exc:
        error_message = "𝗘𝘅𝗰𝗲𝗽𝘁𝗶𝗼𝗻::  {} while fetching masscan response due to " \
                        "Maximum connect time limit exceeded." \
                        "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   {}".format(
            timeout_exc,
            status_curl
        )
        response = None

        return context
    except Exception as error:
        error_message = "𝗘𝘅𝗰𝗲𝗽𝘁𝗶𝗼𝗻::    {} while fetching response for masscan." \
                        "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   {}".format(
            error,
            status_curl
        )
        response = None

        return context
    print
    'response::::', response
    try:
        if response and response.status_code == 200:
            status = response.json()
            try:
                error_message = status.get('exception')
            except:
                error_message = None
            if error_message:
                message = "𝗘𝘅𝗰𝗲𝗽𝘁𝗶𝗼𝗻::  {} while fetching response for masscan." \
                          "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀:: {}".format(
                    error_message,
                    status_curl
                )

                return
            context['status'] = True
            context['response'] = response
            return context
        elif response.status_code == 400:
            try:
                json_response = response.json()
            except:
                json_response = None
            if json_response and json_response.get('error'):
                error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) + \
                                "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
            elif json_response and not json_response.get('error'):
                error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:   " + str(json_response) + \
                                "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
            elif response:
                error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) + \
                                "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
            elif response.text:
                error_message = "(400 Bad Request).\n𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + \
                                str(response.text) + "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
            else:
                error_message = "(400 Bad Request)." + \
                                "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl

            print
            'error_message', error_message
            return context
        elif response.status_code == 401:
            try:
                json_response = response.json()
            except:
                json_response = None
            if json_response and json_response.get('error'):
                error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) + \
                                "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
            elif json_response and not json_response.get('error'):
                error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:   " + str(json_response) + \
                                "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
            elif response:
                error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) + \
                                "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
            elif response.text:
                error_message = "(401 Unauthorized).\n𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + \
                                str(response.text) + "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
            else:
                error_message = "(401 Unauthorized)." + \
                                "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl

            print
            'error_message', error_message
            return context
        elif response.status_code == 404:
            try:
                json_response = response.json()
            except:
                json_response = None
            if json_response and json_response.get('error'):
                error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) + \
                                "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
            elif json_response and not json_response.get('error'):
                error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:   " + str(json_response) + \
                                "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
            elif response:
                error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) + \
                                "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
            elif response.text:
                error_message = "(404 not found).\n𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + \
                                str(response.text) + "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
            else:
                error_message = "(404 not found)." + \
                                "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl

            print
            'error_message', error_message
            return context
        elif response.status_code == 504:
            try:
                json_response = response.json()
            except:
                json_response = None
            if json_response and json_response.get('error'):
                error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) + \
                                "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
            elif json_response and not json_response.get('error'):
                error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:   " + str(json_response) + \
                                "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
            elif response:
                error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) + \
                                "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
            elif response.text:
                error_message = "(504 Gateway Timeout error).\n𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + \
                                str(response.text) + "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
            else:
                error_message = "(504 Gateway Timeout error)." + \
                                "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl

            print
            'error_message', error_message
            return context
        elif response.status_code == 500:
            try:
                json_response = response.json()
            except:
                json_response = None
            if json_response and json_response.get('error'):
                error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) + \
                                "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
            elif json_response and not json_response.get('error'):
                error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:   " + str(json_response) + \
                                "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
            elif response:
                error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) + \
                                "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
            elif response.text:
                error_message = "(500 Internal Server Error).\n𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + \
                                str(response.text) + "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
            else:
                error_message = "(500 Internal Server Error)." + \
                                "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl

            print
            'error_message', error_message
            return context
        elif response.status_code == 502:
            try:
                json_response = response.json()
            except:
                json_response = None
            if json_response and json_response.get('error'):
                error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) + \
                                "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
            elif json_response and not json_response.get('error'):
                error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:   " + str(json_response) + \
                                "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
            elif response:
                error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) + \
                                "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
            elif response.text:
                error_message = "(502 Bad Gateway).\n𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + \
                                str(response.text) + "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
            else:
                error_message = "(502 Bad Gateway)." + \
                                "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl

            print
            'error_message', error_message
            return context
        else:
            try:
                json_response = response.json()
            except:
                json_response = None
            if json_response and json_response.get('error'):
                error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) + \
                                "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
            elif json_response and not json_response.get('error'):
                error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:   " + str(json_response) + \
                                "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
            elif response:
                error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) + \
                                "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
            elif response.text:
                error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + \
                                str(response.text) + "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
            else:
                error_message = "There is either a network connection problem " \
                                "or the API itself is not returning data." \
                                "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::  " + status_curl

            print
            'error_message', error_message
            return context
    except Exception as e:
        print
        "Exception::..", e
        try:
            json_response = response.json()
        except:
            json_response = None
        if json_response and json_response.get('error'):
            error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) + \
                            "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
        elif json_response and not json_response.get('error'):
            error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:   " + str(json_response) + \
                            "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
        elif response:
            error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) + \
                            "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
        elif response.text:
            error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + \
                            str(response.text) + "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
        else:
            error_message = "There is either a network connection problem " \
                            "or the API itself is not returning data.." \
                            "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::  " + status_curl

        print
        'error_message', error_message
        return context


def get_host_type(host_name):
    try:
        host_ip = socket.gethostbyname(host_name)
        ip = IP(host_ip)
        return ip.iptype()
    except:
        return []


def rds_scan():
    rds_objs = AwsRdsEndpoint.objects.all()
    for rds_obj in rds_objs:
        if get_host_type(rds_obj.host) is not None:
            if get_host_type(rds_obj.host) == 'PRIVATE':
                rds_obj.last_scan = timezone.now()
                rds_obj.save()
            else:
                appliances = get_appliance("External")
                scan_obj = MasscanRestApiDescriptor(
                    appliances.appliance_setting.pk,
                    rds_obj.pk
                )
                scan_obj.create_masscan()

        else:
            error_message = "No RDS HOST"
            AppNotification.objects.create(
                issue_type='error',
                notification_message=error_message
            )
