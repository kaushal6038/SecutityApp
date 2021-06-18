# -*- coding: utf-8 -*-
import requests
import time
from redtree_app.models import *
from nessus.models import *
from urlparse import urlparse
from redtree_app.ip_validator import *
from django.db.models import Q
import json

def get_request_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


class MasscanRestApiDescriptor:
    def __init__(self, appliance_obj, temp_ips, masscan_ports, 
            masscan_address, host_name_list, task_id):
        ips = ""
        for host in temp_ips:
            ips = ips + str(host) + ", "
        log_obj = LogMicroServiceMasscan.objects.create(
            ips=ips,
            network_type=appliance_obj.network_type,
            status="Queued",
            task_id=task_id,
            appliance=appliance_obj.id
        )
        self.masscan_logging = LogMicroServiceMasscan.objects.filter(id=log_obj.id)
        self.temp_ips = temp_ips
        self.masscan_ports = masscan_ports
        self.masscan_address = masscan_address
        self.appliance_ip = appliance_obj.appliance_ip
        self.appliance_network_type = appliance_obj.network_type
        self.auth_username = appliance_obj.appliance_setting.auth_username
        self.auth_password = appliance_obj.appliance_setting.auth_password
        self.host_name_list = host_name_list
        self.parsed_uri = urlparse(self.masscan_address)
        self.domain = '{uri.scheme}://{uri.netloc}/{prefix}'.format(
            uri=self.parsed_uri, prefix="masscan"
        )
        self.masscan_url = '{}/scan/new'.format(self.domain)

    def get_status(self, url):
        context = dict()
        context['status'] = False
        status_curl = "curl -u {}:{} --request GET {}".format(
            self.auth_username,
            self.auth_password,
            url
        )
        try:
            response = requests.get(
                url,
                auth=(self.auth_username, self.auth_password),
                timeout=240
            )
        except requests.Timeout as timeout_exc:
            error_message = "𝗘𝘅𝗰𝗲𝗽𝘁𝗶𝗼𝗻::  {} while fetching masscan response due to "\
                "Maximum connect time limit exceeded."\
                "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   {}".format(
                    timeout_exc,
                    status_curl
                )
            response = None
            self.masscan_logging.update(
                status="Error",
                message=error_message,
                is_completed=True,
                modified=timezone.now(),
                duration=timezone.now()
            )
            return context
        except Exception as error:
            error_message = "𝗘𝘅𝗰𝗲𝗽𝘁𝗶𝗼𝗻::    {} while fetching response for masscan."\
                "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   {}".format(
                error,
                status_curl
            )
            response = None
            self.masscan_logging.update(
                status="Error",
                message=error_message,
                is_completed=True,
                modified=timezone.now(),
                duration=timezone.now()
            )
            return context
        print 'response::::',response
        try:
            if response and response.status_code == 200:
                try:
                    error_message = status.get('exception')
                except:
                    error_message = None
                if error_message:
                    message = "𝗘𝘅𝗰𝗲𝗽𝘁𝗶𝗼𝗻::  {} while fetching response for masscan."\
                        "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀:: {}".format(
                        error_message,
                        status_curl
                    )
                    self.masscan_logging.update(
                        status="Error",
                        message=message,
                        modified=timezone.now(),
                        is_completed=True,
                        duration=timezone.now()
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
                    error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) +\
                        "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
                elif json_response and not json_response.get('error'):
                    error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:   " + str(json_response) +\
                        "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
                elif response:
                    error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) +\
                        "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
                elif response.text:
                    error_message = "(400 Bad Request).\n𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " +\
                        str(response.text) + "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
                else:
                    error_message = "(400 Bad Request)." +\
                        "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
                self.masscan_logging.update(
                    status="Error",
                    message=error_message,
                    modified=timezone.now(),
                    is_completed=True,
                    duration=timezone.now()
                )
                # logger.error(error_message)
                print 'error_message',error_message
                return context
            elif response.status_code == 401:
                try:
                    json_response = response.json()
                except:
                    json_response = None
                if json_response and json_response.get('error'):
                    error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) +\
                        "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
                elif json_response and not json_response.get('error'):
                    error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:   " + str(json_response) +\
                        "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
                elif response:
                    error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) +\
                        "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
                elif response.text:
                    error_message = "(401 Unauthorized).\n𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " +\
                        str(response.text) + "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
                else:
                    error_message = "(401 Unauthorized)." +\
                        "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
                self.masscan_logging.update(
                    status="Error",
                    message=error_message,
                    modified=timezone.now(),
                    is_completed=True,
                    duration=timezone.now()
                )
                # logger.error(error_message)
                print 'error_message',error_message
                return context
            elif response.status_code == 404:
                try:
                    json_response = response.json()
                except:
                    json_response = None
                if json_response and json_response.get('error'):
                    error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) +\
                        "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
                elif json_response and not json_response.get('error'):
                    error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:   " + str(json_response) +\
                        "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
                elif response:
                    error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) +\
                        "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
                elif response.text:
                    error_message = "(404 not found).\n𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " +\
                        str(response.text) + "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
                else:
                    error_message = "(404 not found)." +\
                        "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
                self.masscan_logging.update(
                    status="Error",
                    message=error_message,
                    modified=timezone.now(),
                    is_completed=True,
                    duration=timezone.now()
                )
                # logger.error(error_message)
                print 'error_message',error_message
                return context
            elif response.status_code == 504:
                try:
                    json_response = response.json()
                except:
                    json_response = None
                if json_response and json_response.get('error'):
                    error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) +\
                        "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
                elif json_response and not json_response.get('error'):
                    error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:   " + str(json_response) +\
                        "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
                elif response:
                    error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) +\
                        "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
                elif response.text:
                    error_message = "(504 Gateway Timeout error).\n𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " +\
                        str(response.text) + "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
                else:
                    error_message = "(504 Gateway Timeout error)." +\
                        "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
                self.masscan_logging.update(
                    status="Error",
                    message=error_message,
                    modified=timezone.now(),
                    is_completed=True,
                    duration=timezone.now()
                )
                # logger.error(error_message)
                print 'error_message',error_message
                return context
            elif response.status_code == 500:
                try:
                    json_response = response.json()
                except:
                    json_response = None
                if json_response and json_response.get('error'):
                    error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) +\
                        "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
                elif json_response and not json_response.get('error'):
                    error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:   " + str(json_response) +\
                        "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
                elif response:
                    error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) +\
                        "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
                elif response.text:
                    error_message = "(500 Internal Server Error).\n𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " +\
                        str(response.text) + "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
                else:
                    error_message = "(500 Internal Server Error)." +\
                        "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
                self.masscan_logging.update(
                    status="Error",
                    message=error_message,
                    modified=timezone.now(),
                    is_completed=True,
                    duration=timezone.now()
                )
                # logger.error(error_message)
                print 'error_message',error_message
                return context
            elif response.status_code == 502:
                try:
                    json_response = response.json()
                except:
                    json_response = None
                if json_response and json_response.get('error'):
                    error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) +\
                        "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
                elif json_response and not json_response.get('error'):
                    error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:   " + str(json_response) +\
                        "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
                elif response:
                    error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) +\
                        "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
                elif response.text:
                    error_message = "(502 Bad Gateway).\n𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " +\
                        str(response.text) + "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
                else:
                    error_message = "(502 Bad Gateway)." +\
                        "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
                self.masscan_logging.update(
                    status="Error",
                    message=error_message,
                    modified=timezone.now(),
                    is_completed=True,
                    duration=timezone.now()
                )
                # logger.error(error_message)
                print 'error_message',error_message
                return context
            else:
                try:
                    json_response = response.json()
                except:
                    json_response = None
                if json_response and json_response.get('error'):
                    error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) +\
                        "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
                elif json_response and not json_response.get('error'):
                    error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:   " + str(json_response) +\
                        "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
                elif response:
                    error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) +\
                        "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
                elif response.text:
                    error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " +\
                        str(response.text) + "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
                else:
                    error_message = "There is either a network connection problem "\
                    "or the API itself is not returning data."\
                    "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::  " + status_curl
                self.masscan_logging.update(
                    status="Error",
                    message=error_message,
                    modified=timezone.now(),
                    is_completed=True,
                    duration=timezone.now()
                )
                # logger.error(error_message)
                print 'error_message',error_message
                return context
        except Exception as e:
            print "Exception::..",e
            try:
                json_response = response.json()
            except:
                json_response = None
            if json_response and json_response.get('error'):
                error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) +\
                    "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
            elif json_response and not json_response.get('error'):
                error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:   " + str(json_response) +\
                    "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
            elif response:
                error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) +\
                    "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
            elif response.text:
                error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " +\
                    str(response.text) + "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
            else:
                error_message = "There is either a network connection problem "\
                "or the API itself is not returning data.."\
                "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::  " + status_curl
            self.masscan_logging.update(
                status="Error",
                message=error_message,
                modified=timezone.now(),
                is_completed=True,
                duration=timezone.now()
            )
            # logger.error(error_message)
            print 'error_message',error_message
            return context

    def create_masscan(self):
        request_data = {
            "hosts": self.temp_ips,
            "ports": self.masscan_ports
        }
        results = {
            "Status": "COMPLETED",
        }
        curl_request = "curl -u {}:{} --header 'Content-Type: application/json' "\
            "--request POST --data '{}' {}".format(
                self.auth_username,
                self.auth_password,
                json.dumps(request_data),
                self.masscan_url
            )
        try:
            request_header = {
                "Content-Type": "application/json"
            }
            response = requests.post(
                self.masscan_url,
                auth=(self.auth_username, self.auth_password),
                json=request_data,
                headers=request_header,
                timeout=240
            )
        except requests.Timeout as timeout_exc:
            error_message = "𝗘𝘅𝗰𝗲𝗽𝘁𝗶𝗼𝗻::  {} in masscan."\
                "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   {}".format(
                    timeout_exc,
                    curl_request
                )
            self.masscan_logging.update(
                status="Error",
                message=error_message,
                is_completed=True,
                modified=timezone.now(),
                duration=timezone.now()
            )
            AppNotification.objects.create(
                issue_type='error',
                notification_message=error_message
            )

            response = None
            results["Status"] = "FAILED"
            return results
        except Exception as error:
            error_message = "𝗘𝘅𝗰𝗲𝗽𝘁𝗶𝗼𝗻::    {} in masscan."\
                "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   {}".format(
                error,
                curl_request
            )
            self.masscan_logging.update(
                status="Error",
                message=error_message,
                is_completed=True,
                modified=timezone.now(),
                duration=timezone.now()
            )
            AppNotification.objects.create(
                issue_type='error',
                notification_message=error_message
            )

            response = None
            results["Status"] = "FAILED"
            return results
        print 'response',response
        try:
            if response and response.status_code == 200:
                response = response.json()
                try:
                    error_message = response.get('exception')
                except:
                    error_message = None
                if error_message:
                    message = "𝗘𝘅𝗰𝗲𝗽𝘁𝗶𝗼𝗻::  {} in masscan."\
                        "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀:: {}".format(
                        error_message,
                        curl_request
                    )
                    self.masscan_logging.update(
                        status="Error",
                        message=message,
                        modified=timezone.now(),
                        is_completed=True,
                        duration=timezone.now()
                    )
                    results["Status"] = "FAILED"
                    return results
                scan_url = self.domain + response["status_uri"]
                scan_id = response.get('scan_id')
                log = "Scan added you can check the status by status_url::\n{}".format(
                    scan_url
                )
                self.masscan_logging.update(
                    status="Running", message=log,
                    scan_id=scan_id, duration=timezone.now()
                )
                response = self.process_masscan(scan_url)
                return response
            elif response.status_code == 400:
                try:
                    json_response = response.json()
                except:
                    json_response = None
                if json_response and json_response.get('error'):
                    error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) +\
                        "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
                elif json_response and not json_response.get('error'):
                    error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:   " + str(json_response) +\
                        "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
                elif response:
                    error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) +\
                        "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
                elif response.text:
                    error_message = "(400 Bad Request).\n𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " +\
                        str(response.text) + "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
                else:
                    error_message = "(400 Bad Request)." +\
                        "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
                self.masscan_logging.update(
                    status="Error",
                    message=error_message,
                    modified=timezone.now(),
                    is_completed=True,
                    duration=timezone.now()
                )
                # logger.error(error_message)
                print 'error_message',error_message
                results["Status"] = "FAILED"
                return results
            elif response.status_code == 401:
                try:
                    json_response = response.json()
                except:
                    json_response = None
                if json_response and json_response.get('error'):
                    error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) +\
                        "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
                elif json_response and not json_response.get('error'):
                    error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:   " + str(json_response) +\
                        "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
                elif response:
                    error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) +\
                        "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
                elif response.text:
                    error_message = "(401 Unauthorized).\n𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " +\
                        str(response.text) + "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
                else:
                    error_message = "(401 Unauthorized)." +\
                        "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
                self.masscan_logging.update(
                    status="Error",
                    message=error_message,
                    modified=timezone.now(),
                    is_completed=True,
                    duration=timezone.now()
                )
                # logger.error(error_message)
                print 'error_message',error_message
                results["Status"] = "FAILED"
                return results
            elif response.status_code == 404:
                try:
                    json_response = response.json()
                except:
                    json_response = None
                if json_response and json_response.get('error'):
                    error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) +\
                        "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
                elif json_response and not json_response.get('error'):
                    error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:   " + str(json_response) +\
                        "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
                elif response:
                    error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) +\
                        "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
                elif response.text:
                    error_message = "(404 not found).\n𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " +\
                        str(response.text) + "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
                else:
                    error_message = "(404 not found)." +\
                        "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
                self.masscan_logging.update(
                    status="Error",
                    message=error_message,
                    modified=timezone.now(),
                    is_completed=True,
                    duration=timezone.now()
                )
                # logger.error(error_message)
                print 'error_message',error_message
                results["Status"] = "FAILED"
                return results
            elif response.status_code == 504:
                try:
                    json_response = response.json()
                except:
                    json_response = None
                if json_response and json_response.get('error'):
                    error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) +\
                        "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
                elif json_response and not json_response.get('error'):
                    error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:   " + str(json_response) +\
                        "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
                elif response:
                    error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) +\
                        "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
                elif response.text:
                    error_message = "(504 Gateway Timeout error).\n𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " +\
                        str(response.text) + "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
                else:
                    error_message = "(504 Gateway Timeout error)." +\
                        "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
                self.masscan_logging.update(
                    status="Error",
                    message=error_message,
                    modified=timezone.now(),
                    is_completed=True,
                    duration=timezone.now()
                )
                # logger.error(error_message)
                print 'error_message',error_message
                results["Status"] = "FAILED"
                return results
            elif response.status_code == 500:
                try:
                    json_response = response.json()
                except:
                    json_response = None
                if json_response and json_response.get('error'):
                    error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) +\
                        "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
                elif json_response and not json_response.get('error'):
                    error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:   " + str(json_response) +\
                        "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
                elif response:
                    error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) +\
                        "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
                elif response.text:
                    error_message = "(500 Internal Server Error).\n𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " +\
                        str(response.text) + "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
                else:
                    error_message = "(500 Internal Server Error)." +\
                        "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
                self.masscan_logging.update(
                    status="Error",
                    message=error_message,
                    modified=timezone.now(),
                    is_completed=True,
                    duration=timezone.now()
                )
                # logger.error(error_message)
                print 'error_message',error_message
                results["Status"] = "FAILED"
                return results
            elif response.status_code == 502:
                try:
                    json_response = response.json()
                except:
                    json_response = None
                if json_response and json_response.get('error'):
                    error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) +\
                        "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
                elif json_response and not json_response.get('error'):
                    error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:   " + str(json_response) +\
                        "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
                elif response:
                    error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) +\
                        "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
                elif response.text:
                    error_message = "(502 Bad Gateway).\n𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " +\
                        str(response.text) + "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
                else:
                    error_message = "(502 Bad Gateway)." +\
                        "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
                self.masscan_logging.update(
                    status="Error",
                    message=error_message,
                    modified=timezone.now(),
                    is_completed=True,
                    duration=timezone.now()
                )
                # logger.error(error_message)
                print 'error_message',error_message
                results["Status"] = "FAILED"
                return results
            else:
                try:
                    json_response = response.json()
                except:
                    json_response = None
                if json_response and json_response.get('error'):
                    error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) +\
                        "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
                elif json_response and not json_response.get('error'):
                    error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:   " + str(json_response) +\
                        "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
                elif response:
                    error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) +\
                        "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
                elif response.text:
                    error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " +\
                        str(response.text) + "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
                else:
                    error_message = "There is either a network connection problem "\
                    "or the API itself is not returning data."\
                    "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::  " + curl_request
                self.masscan_logging.update(
                    status="Error",
                    message=error_message,
                    modified=timezone.now(),
                    is_completed=True,
                    duration=timezone.now()
                )
                # logger.error(error_message)
                print 'error_message',error_message
                results["Status"] = "FAILED"
                return results
        except Exception as e:
            print "Exception::..",e
            try:
                json_response = response.json()
            except:
                json_response = None
            if json_response and json_response.get('error'):
                error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) +\
                    "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
            elif json_response and not json_response.get('error'):
                error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:   " + str(json_response) +\
                    "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
            elif response:
                error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) +\
                    "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
            elif response.text:
                error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " +\
                    str(response.text) + "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
            else:
                error_message = "There is either a network connection problem "\
                "or the API itself is not returning data.."\
                "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::  " + curl_request
            self.masscan_logging.update(
                status="Error",
                message=error_message,
                modified=timezone.now(),
                is_completed=True,
                duration=timezone.now()
            )
            # logger.error(error_message)
            print 'error_message',error_message
            results["Status"] = "FAILED"
            return results




    def process_masscan(self, scan_url):
        results = {
            "Status": "COMPLETED",
        }
        status_curl = "curl -u {}:{} --request GET {}".format(
            self.auth_username,
            self.auth_password,
            scan_url
        )
        masscan_response = self.get_status(scan_url)
        response = None
        if masscan_response.get('status'):
            try:
                response = masscan_response.get('response').json()
            except:
                response = None
        if response and (response.get('status') != "ERROR" or\
                response.get('status') != "FAILED"):
            while response.get('status') == "PENDING":
                event_time = timezone.now() - self.masscan_logging.first().created
                run_time = int(time.strftime('%H', time.gmtime(event_time.seconds)))
                print 'run_time',run_time
                if run_time >= 2:
                    response = None
                    error = "Scan Failed due to maximum scan time exceeded." + \
                        "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
                    self.masscan_logging.update(
                        status="Error",
                        is_completed=True,
                        message=error,
                        result=error,
                        modified=timezone.now(),
                        duration=timezone.now()
                    )
                    break
                time.sleep(5)
                response = self.get_status(scan_url).get('response').json()
                print 'response::>',response
        if response and response.get('status') == "COMPLETED":
            result_uri = response.get("result_uri")
            result_url = self.domain + result_uri
            log = "Scan complete you can aslo check the results by\n{}".format(result_url)
            self.masscan_logging.update(status="Completed", message=log, duration=timezone.now())
            masscan_response = self.get_status(result_url)
            response = None
            if masscan_response.get('status'):
                try:
                    response = masscan_response.get('response').json()
                except:
                    response = None
            if response:
                masscan_data = response.get("results")
                try:
                    api_obj = ApiList.objects.first()
                except:
                    api_obj = None
                try:
                    article_url = "{}/article/open_tcp_port/".format(api_obj.kb_base_url)
                    headers = {'Authorization': 'Token {}'.format(api_obj.kb_auth_token)}
                    article_response = requests.get(article_url, headers=headers)
                except Exception as e:
                    article_response = None

                if article_response and article_response.status_code == 200:
                    article_data = article_response.json()
                else:
                    article_data = None
                if article_data:
                    description = article_data.get('description')
                    remediation = article_data.get('remediation')
                    risk = article_data.get('risk')
                    title = article_data.get('title')
                    virtue_id = article_data.get('virtue_id')
                    plugin_id = article_data.get('plugin_id')
                    modified_date = article_data.get('date')
                    vul_count = []
                    new_vulnerabilities_created = 0

                    for results_data in masscan_data:
                        host = results_data.get('ip')
                        for ports in results_data.get('ports'):
                            port =  ports.get('port')
                            status = ports.get('status')
                        host_type = get_host_type(host)
                        user_host = check_host_exists(host, host_type)
                        if not user_host:
                            host_name_list = self.host_name_list
                            for data in host_name_list:
                                if host in data.get('ip_list'):
                                    try:
                                        user_host = UserHosts.objects.get(
                                            host=data.get('ip')
                                        )
                                    except:
                                        user_host = None
                                if user_host:
                                    break
                        if user_host:
                            network_type = user_host.network.network_type
                            if user_host.host_type == "host_name":
                                host = user_host.host
                            vul_obj = Vulnerability.objects.filter(
                                virtue_id=int(virtue_id),
                                port=str(port), host_ip=host
                            )
                            if not vul_obj.exists():
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
                                vul_obj = Vulnerability.objects.create(
                                    virtue_id=virtue_id,plugin_id=plugin_id,
                                    title=title, description=description,
                                    port=str(port), remediation=remediation,
                                    risk=risk, post_status=True, host_ip=host,
                                    network_type=network_type, host=host_obj,
                                    modified_date=modified_date
                                )
                                vul_count.append(vul_obj)
                            elif vul_obj.exists():
                                vul_obj = vul_obj.first()
                                vul_obj.modified = timezone.now()
                                vul_obj.save()
                    new_vulnerabilities_created = len(vul_count)
                    if new_vulnerabilities_created:
                        if new_vulnerabilities_created == 1:
                            result = "{} port found.".format(
                                new_vulnerabilities_created
                            )
                            log = "Asynchronous port scan complete, {} new port "\
                                "found.".format(new_vulnerabilities_created)
                        else:
                            result = "{} ports found.".format(
                                new_vulnerabilities_created
                            )
                            log = "Asynchronous port scan complete, {} new ports "\
                                "found.".format(new_vulnerabilities_created)
                    else:
                        result = "No ports found."
                        log = "Asynchronous port scan complete, no new ports found."
                    log = "Scan completed successfully::\n{}".format(result_url)
                    self.masscan_logging.update(
                        status="Completed",
                        message=log,
                        result=result,
                        is_completed=True,
                        modified=timezone.now(),
                        duration=timezone.now()
                    )
                    results["new_vulnerabilities_created"] = new_vulnerabilities_created
                    return results
                else:
                    error_message = ""
                    error_message = "masscan failed because of no response from kb"\
                        "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
                    AppNotification.objects.create(
                        issue_type='error',
                        notification_message=error_message
                    )
                    self.masscan_logging.update(
                        status="Error",
                        message=error_message,
                        is_completed=True,
                        modified=timezone.now(),
                        duration=timezone.now()
                    )
                    results["Status"] = "FAILED"
                    return results
        elif response and (response.get('status') == "ERROR" or\
                response.get('status') == "FAILED"):
            
            results["Status"] = response.get("status")
            try:
                json_response = response
            except:
                json_response = None
            if json_response and json_response.get('error'):
                error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) +\
                    "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
            elif json_response and not json_response.get('error'):
                error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:   " + str(json_response) +\
                    "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
            elif response:
                error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) +\
                    "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
            elif response.text:
                error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response.text) +\
                    "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
            else:
                error_message = "There is either a network connection problem "\
                    "or the API itself is not returning data.." +\
                    "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + self.get_status_curl
            AppNotification.objects.create(
                issue_type='error',
                notification_message=error_message
            )
            self.masscan_logging.update(
                status="Error",
                message=error_message,
                is_completed=True,
                modified=timezone.now(),
                duration=timezone.now()
            )
            return results


def get_pending_masscan_status(log_obj, url, auth_username,
        auth_password, curl_req):
    context = dict()
    context['status'] = False
    try:
        response = requests.get(
            url,
            auth=(
                auth_username,
                auth_password
            ),
            timeout=240
        )
    except requests.Timeout as timeout_exc:
        message="𝗘𝘅𝗰𝗲𝗽𝘁𝗶𝗼𝗻::  {} while fetching masscan response due to "\
            "Maximum connect time limit exceeded."\
            "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   {}".format(
                timeout_exc,
                curl_req
            )
        AppNotification.objects.create(
            issue_type='error',
            notification_message=message
        )
        log_obj.status="Error"
        log_obj.message=message
        log_obj.is_completed=True
        log_obj.modified=timezone.now()
        log_obj.duration=timezone.now()
        log_obj.save()
        response = None
        return context
    except Exception as error:
        error_message = "𝗘𝘅𝗰𝗲𝗽𝘁𝗶𝗼𝗻::    {} while fetching response for masscan."\
            "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   {}".format(
            error,
            curl_req
        )
        print 'error_message',error_message
        # logger.error('{}'.format(error_message))
        log_obj.status = "Error"
        log_obj.message = error_message
        log_obj.is_completed = True
        log_obj.modified = timezone.now()
        log_obj.duration = timezone.now()
        log_obj.save()
        AppNotification.objects.create(
            issue_type='error',
            notification_message=error_message
        )
        response = None
        return context
    try:
        if response and response.status_code == 200:
            try:
                response_data = response.json()
            except:
                response_data = None
            try:
                error_message = response_data.get('exception')
            except:
                error_message = None
            if error_message:
                message = "𝗘𝘅𝗰𝗲𝗽𝘁𝗶𝗼𝗻:: {} while fetching response for masscan."\
                    "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   {}".format(
                    error_message,
                    curl_req
                )
                log_obj.status="Error"
                log_obj.message=message
                log_obj.modified=timezone.now()
                log_obj.is_completed=True
                log_obj.duration = timezone.now()
                log_obj.save()
                return context
            context['status'] = True
            context['response'] = response
            return context
        elif response.status_code == 400:
            try:
                json_response = response.json()
            except:
                json_response = None
            if json_response and json_response.get('error'):
                error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) +\
                    "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_req
            elif json_response and not json_response.get('error'):
                error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:   " + str(json_response) +\
                    "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_req
            elif response:
                error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) +\
                    "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_req
            elif response.text:
                error_message = "(400 Bad Request).\n𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " +\
                    str(response.text) + "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_req
            else:
                error_message = "(400 Bad Request)." +\
                    "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_req
            log_obj.status="Error"
            log_obj.message=error_message
            log_obj.is_completed=True
            log_obj.modified=timezone.now()
            log_obj.duration=timezone.now()
            log_obj.save()
            # logger.error(error_message)
            print 'error_message',error_message
            return context
        elif response.status_code == 401:
            try:
                json_response = response.json()
            except:
                json_response = None
            if json_response and json_response.get('error'):
                error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) +\
                    "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_req
            elif json_response and not json_response.get('error'):
                error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:   " + str(json_response) +\
                    "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_req
            elif response:
                error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) +\
                    "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_req
            elif response.text:
                error_message = "(401 Unauthorized).\n𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " +\
                    str(response.text) + "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_req
            else:
                error_message = "(401 Unauthorized)." +\
                    "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_req
            # logger.info("{}".format(error_message))
            print 'error_message',error_message
            log_obj.status="Error"
            log_obj.message=error_message
            log_obj.modified=timezone.now()
            log_obj.is_completed=True
            log_obj.duration=timezone.now()
            log_obj.save()
            AppNotification.objects.create(
                issue_type='error',
                notification_message=error_message
            )
            return context
        elif response.status_code == 404:
            try:
                json_response = response.json()
            except:
                json_response = None
            if json_response and json_response.get('error'):
                error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) +\
                    "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_req
            elif json_response and not json_response.get('error'):
                error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:   " + str(json_response) +\
                    "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_req
            elif response:
                error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) +\
                    "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_req
            elif response.text:
                error_message = "(404 not found).\n𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " +\
                    str(response.text) + "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_req
            else:
                error_message = "(404 not found)." +\
                    "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_req
            log_obj.status="Error"
            log_obj.message=error_message,
            log_obj.modified=timezone.now()
            log_obj.is_completed=True
            log_obj.duration=timezone.now()
            log_obj.save()
            # logger.error(error_message)
            print 'error_message',error_message
            return context
        elif response.status_code == 504:
            try:
                json_response = response.json()
            except:
                json_response = None
            if json_response and json_response.get('error'):
                error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) +\
                    "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_req
            elif json_response and not json_response.get('error'):
                error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:   " + str(json_response) +\
                    "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_req
            elif response:
                error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) +\
                    "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_req
            elif response.text:
                error_message = "(504 Gateway Timeout error).\n𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " +\
                    str(response.text) + "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_req
            else:
                error_message = "(504 Gateway Timeout error)." +\
                    "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_req
            # logger.error(error_message)
            print 'error_message',error_message
            log_obj.status="Error"
            log_obj.message=error_message
            log_obj.is_completed=True
            log_obj.modified=timezone.now()
            log_obj.duration=timezone.now()
            log_obj.save()
            return context
        elif response.status_code == 500:
            try:
                json_response = response.json()
            except:
                json_response = None
            if json_response and json_response.get('error'):
                error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) +\
                    "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_req
            elif json_response and not json_response.get('error'):
                error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:   " + str(json_response) +\
                    "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_req
            elif response:
                error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) +\
                    "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_req
            elif response.text:
                error_message = "(500 Internal Server Error).\n𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " +\
                    str(response.text) + "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_req
            else:
                error_message = "(500 Internal Server Error)." +\
                    "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_req
            log_obj.status="Error"
            log_obj.message=error_message
            log_obj.is_completed=True
            log_obj.modified=timezone.now()
            log_obj.duration=timezone.now()
            log_obj.save()
            # logger.error(error_message)
            print 'error_message',error_message
            return context
        elif response.status_code == 502:
            try:
                json_response = response.json()
            except:
                json_response = None
            if json_response and json_response.get('error'):
                error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) +\
                    "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_req
            elif json_response and not json_response.get('error'):
                error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:   " + str(json_response) +\
                    "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_req
            elif response:
                error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) +\
                    "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_req
            elif response.text:
                error_message = "(502 Bad Gateway).\n𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " +\
                    str(response.text) + "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_req
            else:
                error_message = "(502 Bad Gateway)." +\
                    "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_req
            log_obj.status="Error"
            log_obj.message=error_message
            log_obj.is_completed=True
            log_obj.modified=timezone.now()
            log_obj.duration=timezone.now()
            log_obj.save()
            # logger.error(error_message)
            print 'error_message',error_message
            return context
        else:
            try:
                json_response = response.json()
            except:
                json_response = None
            if json_response and json_response.get('error'):
                error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) +\
                    "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_req
            elif json_response and not json_response.get('error'):
                error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:   " + str(json_response) +\
                    "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_req
            elif response:
                error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) +\
                    "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_req
            elif response.text:
                error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " +\
                    str(response.text) + "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_req
            else:
                error_message = "There is either a network connection problem "\
                    "or the API itself is not returning data."\
                    "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_req
            log_obj.status="Error"
            log_obj.message=error_message
            log_obj.is_completed=True
            log_obj.modified=timezone.now()
            log_obj.duration=timezone.now()
            log_obj.save()
            # logger.error(error_message)
            print 'error_message',error_message
            return context
    except Exception as e:
        print "Exception::..",e
        try:
            json_response = response.json()
        except:
            json_response = None
        if json_response and json_response.get('error'):
            error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) +\
                "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_req
        elif json_response and not json_response.get('error'):
            error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:   " + str(json_response) +\
                "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_req
        elif response:
            error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) +\
                "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_req
        elif response.text:
            error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " +\
                str(response.text) + "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_req
        else:
            error_message = "There is either a network connection problem "\
                "or the API itself is not returning data.."\
                "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_req
        log_obj.status="Error"
        log_obj.message=error_message
        log_obj.modified=timezone.now()
        log_obj.is_completed=True
        log_obj.duration=timezone.now()
        log_obj.save()
        return context


def update_pending_masscan(ips):
    log_objs = LogMicroServiceMasscan.objects.filter(
        status="Running"
    )
    for log_obj in log_objs:
        if log_obj.status == "Running" and log_obj.scan_id and log_obj.appliance:
            try:
                appliance_obj = Appliances.objects.get(id=log_obj.appliance)
            except:
                appliance_obj = None
            if appliance_obj:
                if appliance_obj.network_type == "External":
                    host_name_list = ips.get('external_host_name_list')
                elif appliance_obj.network_type == "Internal":
                    host_name_list = ips.get('internal_host_name_list')
                appliance_setting = appliance_obj.appliance_setting
                auth_username = appliance_setting.auth_username
                auth_password = appliance_setting.auth_password
                scan_url = appliance_setting.masscan_ip_address
                parsed_uri = urlparse(scan_url)
                domain = '{uri.scheme}://{uri.netloc}/{prefix}'.format(
                    uri=parsed_uri,
                    prefix="masscan"
                )
                status_url = "{}/scan/{}/status".format(
                    domain,
                    log_obj.scan_id
                )
                curl_req = "curl -u {}:{} --request GET {}".format(
                    auth_username,
                    auth_password,
                    status_url
                )
                response = get_pending_masscan_status(
                    log_obj,
                    status_url,
                    auth_username,
                    auth_password,
                    curl_req
                )
                try:
                    response_status = response.get('status')
                except:
                    response_status = None
                if response_status:
                    try:
                        response_data = response.get('response').json()
                    except:
                        response_data = None
                    if response_data and response_data.get('status') != "PENDING":
                        if response_data and response_data.get('status') == "COMPLETED":
                            result_uri = response_data.get("result_uri")
                            result_url = domain + result_uri
                            log = "scan complete you can aslo check the results "\
                                "by {}".format(result_url)
                            log_obj.status="Completed"
                            log_obj.message=log
                            log_obj.duration=timezone.now()
                            log_obj.save()
                            response = get_pending_masscan_status(
                                log_obj,
                                result_url,
                                auth_username,
                                auth_password,
                                curl_req
                            )
                            result_data = None
                            if response.get('status'):
                                try:
                                    result_data = response.get('response').json()
                                except:
                                    result_data = None
                            if result_data:
                                masscan_data = result_data.get("results")
                                try:
                                    api_obj = ApiList.objects.first()
                                except:
                                    api_obj = None
                                try:
                                    article_url = "{}/article/open_tcp_port/".format(
                                        api_obj.kb_base_url
                                    )
                                    headers = {
                                        'Authorization': 'Token {}'.format(
                                            api_obj.kb_auth_token
                                        )
                                    }
                                    article_response = requests.get(
                                        article_url,
                                        headers=headers
                                    )
                                except Exception as e:
                                    article_response = None

                                if article_response and article_response.status_code == 200:
                                    article_data = article_response.json()
                                else:
                                    article_data = None
                                if article_data:
                                    description = article_data.get('description')
                                    remediation = article_data.get('remediation')
                                    risk = article_data.get('risk')
                                    title = article_data.get('title')
                                    virtue_id = article_data.get('virtue_id')
                                    plugin_id = article_data.get('plugin_id')
                                    modified_date = article_data.get('date')
                                    vul_count = []
                                    new_vulnerabilities_created = 0

                                    for results_data in masscan_data:
                                        host = results_data.get('ip')
                                        for ports in results_data.get('ports'):
                                            port =  ports.get('port')
                                            status = ports.get('status')
                                        host_type = get_host_type(host)
                                        user_host = check_host_exists(host, host_type)
                                        if not user_host:
                                            for data in host_name_list:
                                                if host in data.get('ip_list'):
                                                    try:
                                                        user_host = UserHosts.objects.get(
                                                            host=data.get('ip')
                                                        )
                                                    except:
                                                        user_host = None
                                                if user_host:
                                                    break
                                        if user_host:
                                            network_type = user_host.network.network_type
                                            if user_host.host_type == "host_name":
                                                host = user_host.host
                                            vul_obj = Vulnerability.objects.filter(
                                                virtue_id=int(virtue_id),
                                                port=str(port), host_ip=host
                                            )
                                            if not vul_obj.exists():
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
                                                vul_obj = Vulnerability.objects.create(
                                                    virtue_id=virtue_id,plugin_id=plugin_id,
                                                    title=title, description=description,
                                                    port=str(port), remediation=remediation,
                                                    risk=risk, post_status=True, host_ip=host,
                                                    network_type=network_type, host=host_obj,
                                                    modified_date=modified_date
                                                )
                                                vul_count.append(vul_obj)
                                            elif vul_obj.exists():
                                                vul_obj = vul_obj.first()
                                                vul_obj.modified = timezone.now()
                                                vul_obj.save()
                                    new_vulnerabilities_created = len(vul_count)
                                    if new_vulnerabilities_created:
                                        if new_vulnerabilities_created == 1:
                                            result = "{} port found.".format(
                                                new_vulnerabilities_created
                                            )
                                            log = "Asynchronous port scan complete, {} new port "\
                                                "found.".format(new_vulnerabilities_created)
                                        else:
                                            result = "{} ports found.".format(
                                                new_vulnerabilities_created
                                            )
                                            log = "Asynchronous port scan complete, {} new ports "\
                                                "found.".format(new_vulnerabilities_created)
                                    else:
                                        result = "No ports found."
                                        log = "Asynchronous port scan complete, no new ports found."
                                    ActivityLog.objects.create(activity=log)
                                    log = "Scan completed successfully.".format(result_url)
                                    log_obj.status="Completed"
                                    log_obj.message=log
                                    log_obj.result=result
                                    log_obj.is_completed=True
                                    log_obj.modified=timezone.now()
                                    log_obj.duration=timezone.now()
                                    log_obj.save()
                                else:
                                    error_message = "masscan failed because of no response from kb"
                                    AppNotification.objects.create(
                                        issue_type='error',
                                        notification_message=error_message
                                    )
                                    log_obj.status="Error"
                                    log_obj.message=error_message
                                    log_obj.is_completed=True
                                    log_obj.modified=timezone.now()
                                    log_obj.duration=timezone.now()
                                    log_obj.save()
                        elif response_data and (response_data.get('status') == "ERROR"\
                                or response_data.get('status') == "FAILED"):
                            try:
                                json_response = response_data
                            except:
                                json_response = None
                            if json_response and json_response.get('error'):
                                error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) +\
                                    "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_req
                            elif json_response and not json_response.get('error'):
                                error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:   " + str(json_response) +\
                                    "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_req
                            elif response:
                                error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) +\
                                    "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_req
                            elif response.text:
                                error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response.text) +\
                                    "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_req
                            else:
                                error_message = "There is either a network connection problem "\
                                    "or the API itself is not returning data.." +\
                                    "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_req
                            AppNotification.objects.create(
                                issue_type='error',
                                notification_message=error_message
                            )
                            log_obj.status="Error"
                            log_obj.message=error_message
                            log_obj.is_completed=True
                            log_obj.modified=timezone.now()
                            log_obj.duration=timezone.now()
                            log_obj.save()
                        else:
                            try:
                                json_response = response_data
                            except:
                                json_response = None
                            if json_response and json_response.get('error'):
                                error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) +\
                                    "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_req
                            elif json_response and not json_response.get('error'):
                                error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:   " + str(json_response) +\
                                    "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_req
                            elif response:
                                error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) +\
                                    "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_req
                            elif response.text:
                                error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response.text) +\
                                    "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_req
                            else:
                                error_message = "There is either a network connection problem "\
                                    "or the API itself is not returning data.." +\
                                    "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_req
                            log_obj.status="Error"
                            log_obj.message=error_message
                            log_obj.is_completed=True
                            log_obj.modified=timezone.now()
                            log_obj.duration=timezone.now()
                            log_obj.save()