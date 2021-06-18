# -*- coding: utf-8 -*-
import requests
import json
from urlparse import urlparse
import time
from redtree_app.models import *
from utils.scans_helpers import (
    get_ip_type,
)
from utils.helpers import (
	get_appliance
)
from django.utils import timezone
from celery import task
from celery.utils.log import get_task_logger
from raven.contrib.django.raven_compat.models import client as sentry_client
from utils.helpers import update_cipher_helper

logger = get_task_logger(__name__)


class RestApiScanDescriptor:

    def __init__(self, task_id, appliance_pk, host, port, response=None):
        appliance_obj = Appliances.objects.get(pk=appliance_pk)
        try:
            log_obj = LogMicroServiceSslyze.objects.get(
            host=host,
            port=int(port),
            status="Queued",
            task_id=task_id,
            appliance=appliance_obj.id
        )
        except LogMicroServiceSslyze.DoesNotExist:
            log_obj = LogMicroServiceSslyze.objects.create(
                host=host,
                port=int(port),
                status="Queued",
                task_id=task_id,
                appliance=appliance_obj.id
            )

        self.response = response
        self.log_obj = log_obj
        self.appliance_pk = appliance_pk
        self.appliance_ip = appliance_obj.appliance_ip
        self.sslyze_logging = LogMicroServiceSslyze.objects.filter(id=log_obj.id)
        self.host = host
        self.port = port
        self.scan_url = appliance_obj.appliance_setting.microservice_scan_url
        self.auth_username = appliance_obj.appliance_setting.auth_username
        self.auth_password = appliance_obj.appliance_setting.auth_password
        self.parsed_uri = urlparse(self.scan_url)
        self.domain = '{uri.scheme}://{uri.netloc}/{prefix}'.format(
            uri=self.parsed_uri,
            prefix="sslyze"
            )
        self.hp = str(self.host) + ":" + str(self.port)
        self.imported_ciphers = 0
        self.total_ciphers = 0


    def create_ciphers(self, protocol, ciphers_list):
        if ciphers_list:
            for cipher in ciphers_list:
                if not cipher.get('key_size'):
                    print 'key_size::',cipher.get('key_size')
                cipher_obj = Ciphers.objects.filter(
                    host=self.host,
                    port=self.port,
                    protocol=protocol,
                    cipher=cipher.get("openssl_name"),
                    key_size=cipher.get('key_size')
                    )
                if not cipher_obj:
                    Ciphers.objects.create(
                        host=self.host,
                        port=self.port,
                        protocol=protocol,
                        cipher=cipher.get("openssl_name"),
                        key_size=cipher.get('key_size')
                    )
                    self.imported_ciphers += 1
                else:
                    cipher_obj.update(modified=timezone.now())

    def process_cipher_scan(self):
        result_uri = self.response.get("result_uri")
        result_url = self.domain + result_uri
        log = "scan complete you can aslo check the results by {}".format(result_url)
        self.sslyze_logging.update(duration=timezone.now(), message=log)
        sslyze = LogMicroServiceSslyze.objects.get(id=self.log_obj.id)
        response = get_status(result_url, self.auth_username, self.auth_password, sslyze)
        if response.get('ok') == True:
            try:
                ciphers_data = response.get("results").get(self.hp)
                if ciphers_data:
                    certinfo = ciphers_data.get('certinfo')
                    if certinfo:
                        verified_certificate_chain = certinfo.get('verified_certificate_chain')
                        if verified_certificate_chain:
                            verified_certificate = True
                        else:
                             verified_certificate = False
                        print 'verified_certificate_chain',verified_certificate
                        has_sha1_in_certificate_chain = certinfo.get('has_sha1_in_certificate_chain')

                        if has_sha1_in_certificate_chain:
                            has_sha1_in_certificate = True
                        else:
                            has_sha1_in_certificate = False
                        print 'has_sha1_in_certificate_chain',has_sha1_in_certificate
                        subject_chain = certinfo.get('certificate_chain')
                        subject = None
                        commonName = None
                        algorithm = None
                        if subject_chain and subject_chain[0]:
                            publicKey=subject_chain[0].get('publicKey')
                            algorithm = publicKey['algorithm'].upper()
                            print 'algorithm',algorithm
                            subject = subject_chain[0].get('subject')
                            for item in subject.split(", "):
                                if item.find('='):
                                    data = item.split("=")
                                    if data[0] == "commonName":
                                        commonName = data[1]
                        print 'commonName',commonName
                    else:
                        verified_certificate = False
                        has_sha1_in_certificate = False
                        subject = None
                    certificate_objs = SslyzeCertificates.objects.filter(
                        subject=subject,
                        host=self.host,
                        port=self.port,
                        common_name=commonName
                    )
                    if subject and not certificate_objs.exists():
                        SslyzeCertificates.objects.create(
                            host=self.host,
                            port=self.port,
                            verified_certificate_chain=verified_certificate,
                            sha1_in_chain=has_sha1_in_certificate,
                            subject=subject,
                            common_name=commonName,
                            algorithm=algorithm
                        )
                    elif certificate_objs.exists():
                        certificate_objs.update(modified=timezone.now())
                    sslv2_ciphers = ciphers_data.get("sslv2")
                    if sslv2_ciphers:
                        ciphers = sslv2_ciphers.get("accepted_cipher_list")
                        if ciphers:
                            self.total_ciphers += len(ciphers)
                            self.create_ciphers("SSLv2", ciphers)
                    sslv3_ciphers = ciphers_data.get("sslv3")
                    if sslv3_ciphers:
                        ciphers = sslv3_ciphers.get("accepted_cipher_list")
                        if ciphers:
                            self.total_ciphers += len(ciphers)
                            self.create_ciphers("SSLv3", ciphers)
                    tlsv1_ciphers = ciphers_data.get("tlsv1")
                    if tlsv1_ciphers:
                        ciphers = tlsv1_ciphers.get("accepted_cipher_list")
                        if ciphers:
                            self.total_ciphers += len(ciphers)
                            self.create_ciphers("TLSv1", ciphers)
                    tlsv1_1_ciphers = ciphers_data.get("tlsv1_1")
                    if tlsv1_1_ciphers:
                        ciphers = tlsv1_1_ciphers.get("accepted_cipher_list")
                        if ciphers:
                            self.total_ciphers += len(ciphers)
                            self.create_ciphers("TLSv1_1", ciphers)
                    tlsv1_2_ciphers = ciphers_data.get("tlsv1_2")
                    if tlsv1_2_ciphers:
                        ciphers = tlsv1_2_ciphers.get("accepted_cipher_list")
                        if ciphers:
                            self.total_ciphers += len(ciphers)
                            self.create_ciphers("TLSv1_2", ciphers)
                    tlsv1_3_ciphers = ciphers_data.get("tlsv1_3")
                    if tlsv1_3_ciphers:
                        ciphers = tlsv1_3_ciphers.get("accepted_cipher_list")
                        if ciphers:
                            self.total_ciphers += len(ciphers)
                            self.create_ciphers("TLSv1_3", ciphers)
                if self.imported_ciphers > 0:
                    log = "Scan completed successfully.Total ciphers found {} and {} ciphers "\
                        "imported.".format(
                        self.total_ciphers,
                        self.imported_ciphers
                    )
                else:
                    log = "Scan completed successfully.Total ciphers found {} and no new ciphers imported.".format(
                        self.total_ciphers
                    )
                self.sslyze_logging.update(
                    status="Completed",
                    message=log,
                    result=log,
                    is_completed=True,
                    modified=timezone.now(),
                    duration=timezone.now()
                )
            except Exception as error:
                error_message = "𝗘𝘅𝗰𝗲𝗽𝘁𝗶𝗼𝗻::  {}  while fetching sslyze "\
                    "response.".format(
                        error
                    )
                self.sslyze_logging.update(
                    status="Error",
                    message=error_message,
                    duration=timezone.now(),
                    modified=timezone.now(),
                    is_completed=True
                )
                print 'error_message',error_message
                sentry_client.captureException()
        else:
            print("check the code")
        

    def create_cipher_scan(self):
        request_data = {
            "targets": [
                [self.host, self.port]
            ]
        }
        create_curl_req = "curl -u {}:{} --header 'Content-Type: application/json' "\
            "--request POST --data '{}' {}".format(
                self.auth_username,
                self.auth_password,
                json.dumps(request_data),
                self.scan_url
            )
        print "create_curl_req", create_curl_req
        try:
            request_header = {
                "Content-Type": "application/json"
                }
            response = requests.post(
                self.scan_url,
                auth=(self.auth_username, self.auth_password),
                json=request_data,
                headers=request_header,
                timeout=180
            )
        except requests.Timeout as timeout_exc:
            error_message = "Maximum connect time exceeded on appliance {} for Sslyze scan. "\
                "Curl request :: ".format(
                self.appliance_ip,
                create_curl_req
            )
            self.sslyze_logging.update(
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
            return
        except Exception as error:
            error_message = "error {} in sslyze scan. Curl request :: {}".format(error, create_curl_req)
            self.sslyze_logging.update(
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
            return
        try:
            if response.status_code == 200:
                response_data = response.json()
                try:
                    error_message = response_data.get('exception')
                except:
                    error_message = None
                if error_message:
                    message="Exception :: {}, Curl request :: {}".format(
                            error_message,
                            create_curl_req
                        )
                    self.sslyze_logging.update(
                        status="Error",
                        message=message,
                        modified=timezone.now(),
                        is_completed=True,
                        duration=timezone.now()
                    )
                    return
                status_url = self.domain + response_data.get("status_uri")
                log = "scan added can check the status by status_url {}".format(status_url)
                self.sslyze_logging.update(
                    status="Running",
                    message=log,
                    scan_id=response_data.get("scan_id")
                )
                print "response_data", response_data


                process_scan.delay(status_url, self.appliance_pk, self.host, self.port, self.log_obj.id)
            elif response.status_code == 400:
                try:
                    json_response = response.json()
                except:
                    json_response = None
                if json_response and json_response.get('error'):
                    error_message = str(json_response.get('error')) + " Curl request is: " + create_curl_req
                elif json_response and not json_response.get('error'):
                    error_message = str(json_response) + " Curl request is: " + create_curl_req
                elif response:
                    error_message = str(response) + " Curl request is: " + create_curl_req
                else:
                    error_message = "(400 Bad Request). Curl request "\
                        "is: " + create_curl_req
                self.sslyze_logging.update(
                    status="Error",
                    message=error_message,
                    modified=timezone.now(),
                    is_completed=True,
                    duration=timezone.now()
                )
                return
            elif response.status_code == 401:
                try:
                    json_response = response.json()
                except:
                    json_response = None
                if json_response and json_response.get('error'):
                    error_message = str(json_response.get('error')) + " Curl request is: " + create_curl_req
                elif json_response and not json_response.get('error'):
                    error_message = str(json_response) + " Curl request is: " + create_curl_req
                elif response:
                    error_message = str(response) + " Curl request is: " + create_curl_req
                else:
                    error_message = "(401 Unauthorized). Curl request "\
                        "is: " + create_curl_req
                self.sslyze_logging.update(
                    status="Error",
                    message=error_message,
                    modified=timezone.now(),
                    is_completed=True,
                    duration=timezone.now()
                )
                AppNotification.objects.create(
                    issue_type='error',
                    notification_message=error_message
                )
                return
            elif response.status_code == 404:
                try:
                    json_response = response.json()
                except:
                    json_response = None
                if json_response and json_response.get('error'):
                    error_message = str(json_response.get('error')) + " Curl request is: " + create_curl_req
                elif json_response and not json_response.get('error'):
                    error_message = str(json_response) + " Curl request is: " + create_curl_req
                elif response:
                    error_message = str(response) + " Curl request is: " + create_curl_req
                else:
                    error_message = "(404 not found). Curl request "\
                        "is: " + create_curl_req
                self.sslyze_logging.update(
                    status="Error",
                    message=error_message,
                    modified=timezone.now(),
                    is_completed=True,
                    duration=timezone.now()
                )
                return
            elif response.status_code == 500:
                try:
                    json_response = response.json()
                except:
                    json_response = None
                if json_response and json_response.get('error'):
                    error_message = str(json_response.get('error')) + " Curl request is: " + create_curl_req
                elif json_response and not json_response.get('error'):
                    error_message = str(json_response) + " Curl request is: " + create_curl_req
                elif response:
                    error_message = str(response) + " Curl request is: " + create_curl_req
                else:
                    error_message = "(500 Internal Server Error). Curl request "\
                        "is: " + create_curl_req
                self.sslyze_logging.update(
                    status="Error",
                    message=error_message,
                    modified=timezone.now(),
                    is_completed=True,
                    duration=timezone.now()
                )
                return
            elif response.status_code == 504:
                try:
                    json_response = response.json()
                except:
                    json_response = None
                if json_response and json_response.get('error'):
                    error_message = str(json_response.get('error')) + " Curl request is: " + create_curl_req
                elif json_response and not json_response.get('error'):
                    error_message = str(json_response) + " Curl request is: " + create_curl_req
                elif response:
                    error_message = str(response) + " Curl request is: " + create_curl_req
                else:
                    error_message = "(504 Gateway Timeout error). Curl request "\
                        "is: " + create_curl_req
                self.sslyze_logging.update(
                    status="Error",
                    message=error_message,
                    is_completed=True,
                    modified=timezone.now(),
                    duration=timezone.now()
                )
                return
            else:
                try:
                    json_response = response.json()
                except:
                    json_response = None
                if json_response and json_response.get('error'):
                    error_message = str(json_response.get('error')) + " Curl request is: " + create_curl_req
                elif json_response and not json_response.get('error'):
                    error_message = str(json_response) + " Curl request is: " + create_curl_req
                elif response:
                    error_message = str(response) + " Curl request is: " + create_curl_req
                else:
                    error_message = "There is either a network connection problem "\
                        "or the API itself is not returning data. Curl request "\
                        "is: " + create_curl_req
                self.sslyze_logging.update(
                    status="Error",
                    message=error_message,
                    modified=timezone.now(),
                    is_completed=True,
                    duration=timezone.now()
                )
                return
        except Exception as e:
            print "Exception::..",e
            try:
                json_response = response.json()
            except:
                json_response = None
            if json_response and json_response.get('error'):
                error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) + \
                    "\nCurl request is: " + create_curl_req
            elif json_response and not json_response.get('error'):
                error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response) + \
                    "\nCurl request is: " + create_curl_req
            elif response:
                error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) + \
                    "\nCurl request is: " + create_curl_req
            elif response.text:
                error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response.text) + \
                    "\nCurl request is: " + create_curl_req
            else:
                error_message = "There is either a network connection problem "\
                    "or the API itself is not returning data.. Curl request "\
                    "is: " + create_curl_req
            self.sslyze_logging.update(
                status="Error",
                message=error_message,
                modified=timezone.now(),
                is_completed=True,
                duration=timezone.now()
            )
            print 'error_message',error_message
            # logger.error(error_message)
            return


def process_ciphers(task_id):
    nessus_obj = NessusData.objects.filter(plugin_id=56984)
    external_appliances = get_appliance("External")
    internal_appliances = get_appliance("Internal")
    for data in nessus_obj:
        host = data.host
        port = data.port
        ip_type = get_ip_type(host)
        if ip_type == "Internal":
            if internal_appliances: # Checks for an Internal appliance before starting scan
                scan_helper = RestApiScanDescriptor(
                    task_id,
                    internal_appliances.pk,
                    host,
                    port
                )
                scan_helper.create_cipher_scan()
        elif ip_type == "External":
            if external_appliances: # Checks for an external appliance before starting scan
                scan_helper = RestApiScanDescriptor(
                    task_id,
                    external_appliances.pk,
                    host,
                    port
                )
                scan_helper.create_cipher_scan()


def external_scan_cipher(task_id):
    nessus_obj = NessusData.objects.filter(plugin_id=56984)
    external_appliances = get_appliance("External")
    for data in nessus_obj:
        host = data.host
        port = data.port
        ip_type = get_ip_type(host)
        if ip_type == "External":
            scan_helper = RestApiScanDescriptor(
                task_id,
                external_appliances.pk,
                host,
                port
            )
            scan_helper.create_cipher_scan()
    


def internal_scan_cipher(task_id):
    nessus_obj = NessusData.objects.filter(plugin_id=56984)
    internal_appliances = get_appliance("Internal")
    for data in nessus_obj:
        host = data.host
        port = data.port
        ip_type = get_ip_type(host)
        if ip_type == "Internal":
            scan_helper = RestApiScanDescriptor(
                task_id,
                internal_appliances.pk,
                host,
                port
            )
            scan_helper.create_cipher_scan()


def get_pending_sslyze_status(log_obj, url, auth_username,
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
        message="𝗘𝘅𝗰𝗲𝗽𝘁𝗶𝗼𝗻::  {} while fetching sslyze response due to "\
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
        error_message = "𝗘𝘅𝗰𝗲𝗽𝘁𝗶𝗼𝗻::    {} while fetching response for sslyze."\
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
                message = "𝗘𝘅𝗰𝗲𝗽𝘁𝗶𝗼𝗻:: {} while fetching response for sslyze."\
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
                json_response = response
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
                json_response = response
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
                json_response = response
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
                json_response = response
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
                json_response = response
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
                json_response = response
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
                json_response = response
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
            json_response = response
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


def create_ciphers(log_obj, protocol, ciphers_list, imported_ciphers):
    imported_ciphers = int(imported_ciphers)
    if ciphers_list:
        for cipher in ciphers_list:
            if not cipher.get('key_size'):
                print 'key_size::>',cipher.get('key_size')
            cipher_obj = Ciphers.objects.filter(
                host=log_obj.host,
                port=log_obj.port,
                protocol=protocol,
                cipher=cipher.get("openssl_name"),
                key_size=cipher.get('key_size')
                )
            if not cipher_obj:
                Ciphers.objects.create(
                    host=log_obj.host,
                    port=log_obj.port,
                    protocol=protocol,
                    cipher=cipher.get("openssl_name"),
                    key_size=cipher.get('key_size')
                )
                imported_ciphers += 1
            else:
                cipher_obj.update(modified=timezone.now())
    return imported_ciphers


def update_pending_sslyze():
    log_objs = LogMicroServiceSslyze.objects.filter(
        status="Running"
    )
    for log_obj in log_objs:
        if log_obj.status == "Running" and log_obj.scan_id and log_obj.appliance:
            try:
                appliance_obj = Appliances.objects.get(id=log_obj.appliance)
            except:
                appliance_obj = None
            if appliance_obj:
                appliance_setting = appliance_obj.appliance_setting
                auth_username = appliance_setting.auth_username
                auth_password = appliance_setting.auth_password
                scan_url = appliance_setting.microservice_scan_url
                parsed_uri = urlparse(scan_url)
                domain = '{uri.scheme}://{uri.netloc}/{prefix}'.format(
                    uri=parsed_uri,
                    prefix="sslyze"
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
                response = get_pending_sslyze_status(
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
                            response = get_pending_sslyze_status(
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
                            if result_data and result_data.get('ok') == True:
                                try:
                                    sslyze_data = result_data.get("results")
                                    hp = str(log_obj.host) + ":" + str(log_obj.port)
                                    ciphers_data = sslyze_data.get(hp)
                                    total_ciphers = 0
                                    imported_ciphers = 0
                                    # old_ciphers = Ciphers.objects.filter(host=self.host, port=self.port)
                                    # if old_ciphers:
                                    #     old_ciphers.delete()
                                    if ciphers_data:
                                        sslv2_ciphers = ciphers_data.get("sslv2")
                                        if sslv2_ciphers:
                                            ciphers = sslv2_ciphers.get(
                                                "accepted_cipher_list"
                                            )
                                            if ciphers:
                                                total_ciphers += len(ciphers)
                                                imported_ciphers = create_ciphers(
                                                    log_obj,
                                                    "SSLv2",
                                                    ciphers,
                                                    imported_ciphers
                                                )
                                        sslv3_ciphers = ciphers_data.get("sslv3")
                                        if sslv3_ciphers:
                                            ciphers = sslv3_ciphers.get(
                                                "accepted_cipher_list"
                                            )
                                            if ciphers:
                                                total_ciphers += len(ciphers)
                                                imported_ciphers = create_ciphers(
                                                    log_obj,
                                                    "SSLv3",
                                                    ciphers,
                                                    imported_ciphers
                                                )
                                        tlsv1_ciphers = ciphers_data.get("tlsv1")
                                        if tlsv1_ciphers:
                                            ciphers = tlsv1_ciphers.get(
                                                "accepted_cipher_list"
                                            )
                                            if ciphers:
                                                total_ciphers += len(ciphers)
                                                imported_ciphers = create_ciphers(
                                                    log_obj,
                                                    "TLSv1",
                                                    ciphers,
                                                    imported_ciphers
                                                )
                                        tlsv1_1_ciphers = ciphers_data.get("tlsv1_1")
                                        if tlsv1_1_ciphers:
                                            ciphers = tlsv1_1_ciphers.get(
                                                "accepted_cipher_list"
                                            )
                                            if ciphers:
                                                total_ciphers += len(ciphers)
                                                imported_ciphers = create_ciphers(
                                                    log_obj,
                                                    "TLSv1_1",
                                                    ciphers,
                                                    imported_ciphers
                                                )
                                        tlsv1_2_ciphers = ciphers_data.get("tlsv1_2")
                                        if tlsv1_2_ciphers:
                                            ciphers = tlsv1_2_ciphers.get(
                                                "accepted_cipher_list"
                                            )
                                            if ciphers:
                                                total_ciphers += len(ciphers)
                                                imported_ciphers = create_ciphers(
                                                    log_obj,
                                                    "TLSv1_2",
                                                    ciphers,
                                                    imported_ciphers
                                                )
                                        tlsv1_3_ciphers = ciphers_data.get("tlsv1_3")
                                        if tlsv1_3_ciphers:
                                            ciphers = tlsv1_3_ciphers.get(
                                                "accepted_cipher_list"
                                            )
                                            if ciphers:
                                                total_ciphers += len(ciphers)
                                                imported_ciphers = create_ciphers(
                                                    log_obj,
                                                    "TLSv1_3",
                                                    ciphers,
                                                    imported_ciphers
                                                )
                                    if imported_ciphers > 0:
                                        log = "Scan completed successfully.Total ciphers "\
                                            "found {} and {} ciphers imported.".format(
                                            total_ciphers,
                                            imported_ciphers
                                        )
                                    else:
                                        log = "Scan completed successfully.Total ciphers "\
                                            "found {} and no new ciphers imported.".format(
                                            total_ciphers
                                        )
                                    log_obj.status="Completed"
                                    log_obj.message=log
                                    log_obj.result=log
                                    log_obj.is_completed=True
                                    log_obj.modified=timezone.now()
                                    log_obj.duration=timezone.now()
                                    log_obj.save()
                                except Exception as error:
                                    error_message = "𝗘𝘅𝗰𝗲𝗽𝘁𝗶𝗼𝗻::  {}  while fetching "\
                                        "sslyze response.".format(
                                            error
                                        )
                                    log_obj.status="Error"
                                    log_obj.message=error_message
                                    log_obj.duration=timezone.now()
                                    log_obj.modified=timezone.now()
                                    log_obj.is_completed=True
                                    log_obj.save()
                                    print 'error_message',error_message
    update_cipher_helper()


@task(name='process_cipher_scan')
def process_scan(url, appliance_pk, host, port, log_pk):
    appliance_obj = Appliances.objects.get(pk=appliance_pk)
    auth_username = appliance_obj.appliance_setting.auth_username
    auth_password = appliance_obj.appliance_setting.auth_password
    sslyze_logging = LogMicroServiceSslyze.objects.get(id=log_pk)
    response = get_status(url, auth_username, auth_password, sslyze_logging)

    print "task id is", sslyze_logging.task_id
    if response and response.get('status') == "PENDING":
        print('pending......')
        process_scan.apply_async([url, appliance_pk, host, port, log_pk], countdown=10)
    if response and response.get('status') == "COMPLETED":
        scan_helper = RestApiScanDescriptor(
            sslyze_logging.task_id,
            appliance_pk,
            host,
            port,
            response
        )
        scan_helper.process_cipher_scan()


def get_status(url, auth_username, auth_password, sslyze_logging):

    status_curl = "curl -u {}:{} --request GET {}".format(
        auth_username,
        auth_password,
        url
    )
    print
    'status_curl', status_curl
    try:
        response = requests.get(
            url,
            auth=(auth_username, auth_password),
            timeout=180
        )
    except requests.Timeout as timeout_exc:
        error_message = "Maximum" \
                        "connect time limit exceeded.Curl request :: {}".format(status_curl)
        sslyze_logging.update(
            status="Error",
            message=error_message,
            is_completed=True,
            modified=timezone.now(),
            duration=timezone.now()
        )
        return
    except Exception as error:
        error_message = "error {} in getting response for sslyze scan.Curl request :: ".format(
            error,
            status_curl
        )
        sslyze_logging.update(
            status="Error",
            message=error_message,
            is_completed=True,
            modified=timezone.now(),
            duration=timezone.now()
        )
        return
    try:
        if response and response.status_code == 200:
            status = response.json()
            try:
                error_message = status.get('exception')
            except:
                error_message = None
            if error_message:
                message = "Exception:: {}, Curl is: {}".format(
                    error_message,
                    status_curl
                )
                sslyze_logging.update(
                    status="Error",
                    message=message,
                    modified=timezone.now(),
                    is_completed=True,
                    duration=timezone.now()
                )
                return
            return status
        elif response.status_code == 400:
            try:
                json_response = response.json()
            except:
                json_response = None
            if json_response and json_response.get('error'):
                error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) + \
                                "\nCurl request is: " + status_curl
            elif json_response and not json_response.get('error'):
                error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response) + \
                                "\nCurl request is: " + status_curl
            elif response:
                error_message = str(response) + " Curl request is: " + status_curl
            else:
                error_message = "(400 Bad Request). Curl request " \
                                "is: " + status_curl
            sslyze_logging.update(
                status="Error",
                message=error_message,
                modified=timezone.now(),
                is_completed=True,
                duration=timezone.now()
            )
            print
            'error_message', error_message
            # logger.error(error_message)
            return
        elif response.status_code == 401:
            try:
                json_response = response.json()
            except:
                json_response = None
            if json_response and json_response.get('error'):
                error_message = str(json_response.get('error')) + " Curl request is: " + status_curl
            elif json_response and not json_response.get('error'):
                error_message = str(json_response) + " Curl request is: " + status_curl
            elif response:
                error_message = str(response) + " Curl request is: " + status_curl
            else:
                error_message = "(401 Unauthorized). Curl request " \
                                "is: " + status_curl
            logger.info("{}".format(error_message))
            sslyze_logging.update(
                status="Error",
                message=error_message,
                modified=timezone.now(),
                is_completed=True,
                duration=timezone.now()
            )
            AppNotification.objects.create(
                issue_type='error',
                notification_message=error_message
            )
            return
        elif response.status_code == 404:
            try:
                json_response = response.json()
            except:
                json_response = None
            if json_response and json_response.get('error'):
                error_message = str(json_response.get('error')) + " Curl request is: " + status_curl
            elif json_response and not json_response.get('error'):
                error_message = str(json_response) + " Curl request is: " + status_curl
            elif response:
                error_message = str(response) + " Curl request is: " + status_curl
            else:
                error_message = "(404 not found). Curl request " \
                                "is: " + status_curl
            sslyze_logging.update(
                status="Error",
                message=error_message,
                modified=timezone.now(),
                is_completed=True,
                duration=timezone.now()
            )
            logger.error(error_message)
            return
        elif response.status_code == 500:
            try:
                json_response = response.json()
            except:
                json_response = None
            if json_response and json_response.get('error'):
                error_message = str(json_response.get('error')) + " Curl request is: " + status_curl
            elif json_response and not json_response.get('error'):
                error_message = str(json_response) + " Curl request is: " + status_curl
            elif response:
                error_message = str(response) + " Curl request is: " + status_curl
            else:
                error_message = "(500 Internal Server Error). Curl request " \
                                "is: " + status_curl
            sslyze_logging.update(
                status="Error",
                message=error_message,
                modified=timezone.now(),
                is_completed=True,
                duration=timezone.now()
            )
            logger.error(error_message)
            return
        elif response.status_code == 504:
            try:
                json_response = response.json()
            except:
                json_response = None
            if json_response and json_response.get('error'):
                error_message = str(json_response.get('error')) + " Curl request is: " + status_curl
            elif json_response and not json_response.get('error'):
                error_message = str(json_response) + " Curl request is: " + status_curl
            elif response:
                error_message = str(response) + " Curl request is: " + status_curl
            else:
                error_message = "(504 Gateway Timeout error). Curl request " \
                                "is: " + status_curl
            logger.error(error_message)
            sslyze_logging.update(
                status="Error",
                message=error_message,
                is_completed=True,
                modified=timezone.now(),
                duration=timezone.now()
            )
            return
        else:
            try:
                json_response = response.json()
            except:
                json_response = None
            if json_response and json_response.get('error'):
                error_message = str(json_response.get('error')) + " Curl request is: " + status_curl
            elif json_response and not json_response.get('error'):
                error_message = str(json_response) + " Curl request is: " + status_curl
            elif response:
                error_message = str(response) + " Curl request is: " + status_curl
            else:
                error_message = "There is either a network connection problem " \
                                "or the API itself is not returning data. Curl request " \
                                "is: " + status_curl
            sslyze_logging.update(
                status="Error",
                message=error_message,
                modified=timezone.now(),
                is_completed=True,
                duration=timezone.now()
            )
            logger.error(error_message)
            return
    except Exception as e:
        print
        "Exception::..", e
        try:
            json_response = response.json()
        except:
            json_response = None
        if json_response and json_response.get('error'):
            error_message = str(json_response.get('error')) + " Curl request is: " + status_curl
        elif json_response and not json_response.get('error'):
            error_message = str(json_response) + " Curl request is: " + status_curl
        elif response:
            error_message = str(response) + " Curl request is: " + status_curl
        else:
            error_message = "There is either a network connection problem " \
                            "or the API itself is not returning data.. Curl request " \
                            "is: " + status_curl
        sslyze_logging.update(
            status="Error",
            message=error_message,
            modified=timezone.now(),
            is_completed=True,
            duration=timezone.now()
        )
        logger.error(error_message)
        return