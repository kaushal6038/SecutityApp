# core imports
import requests
import time
import json
# in house files import
from redtree_app.models import *
from nessus.models import ApiList
from django.utils import timezone
from ipwhois import IPWhois
import traceback
from utils.scans_helpers import get_ip_type
import ipwhois
from redtree_app.alerts import send_mail
import os
from redtree_app.ip_validator import get_host_name_list , get_cidr_list , get_loose_a_list , get_loose_b_list
import logging


class WhoIsScanHelper(object):
    """It will create the whois scans"""

    def __init__(self, host):
        self.host = host
        self.client_obj = ClientConfiguration.objects.first()
        if host.host_type == "ip":
            self.target_ip = host.host
            if get_ip_type(self.target_ip) == "External":
                log_obj = LogMicroServiceWhois.objects.create(
                    host=host,
                    status="Queued"
                )
                self.whois_logging = LogMicroServiceWhois.objects.filter(
                    id=log_obj.id
                )
                self.check_aws_existence()
                self.whois_scan()
        else:
            domain_hosts = get_host_name_list(host.host)
            print "domain_hosts"
            for domainhost in domain_hosts:
                self.target_ip = domainhost
                if get_ip_type(self.target_ip) == "External":
                    log_obj = LogMicroServiceWhois.objects.create(
                        host=host,
                        domain_host="{}/{}".format(host.host, domainhost),
                        status="Queued"
                    )
                    self.whois_logging = LogMicroServiceWhois.objects.filter(
                        id=log_obj.id
                    )
                    self.check_aws_existence()
                    self.whois_scan()

    def update_goeip(self, whois_obj, basic_record):
        api_obj = ApiList.objects.first()
        if api_obj:
            url = "{}/api/geoip/".format(api_obj.kb_base_url)
            headers = {
                'Content-Type': 'application/json',
                'Authorization': 'Token {}'.format(api_obj.kb_auth_token)
            }
        else:
            self.whois_logging.update(
                is_completed=True,
                message="Unable to update lat. and long. Kb api is not set.",
                status="Error",
                modified=timezone.now()
            )
            return
        try:
            kb_response = requests.post(
                url,
                json={'ip': self.target_ip},
                headers=headers
            )
        except Exception as error:
            self.whois_logging.update(
                is_completed=True,
                message="Whois recorded but unable to update lat. and long. due to {}.".format(error),
                status="Error",
                modified=timezone.now()
            )
            return
        if kb_response:
            if kb_response.status_code == 200:
                geoip_data = kb_response.json().get('data')
                if geoip_data:
                    whois_obj.longitude = geoip_data.get('longitude')
                    whois_obj.latitude = geoip_data.get('latitude')
                    whois_obj.city = geoip_data.get('city')
                    basic_record.longitude = geoip_data.get('longitude')
                    basic_record.latitude = geoip_data.get('latitude')
                    basic_record.city = geoip_data.get('city')
                    whois_obj.save()
                    basic_record.save()
                    self.whois_logging.update(
                        is_completed=True,
                        message="Whois scan completed successfully.",
                        status="Completed",
                        modified=timezone.now()
                    )
            elif kb_response.status_code == 400:
                self.whois_logging.update(
                    is_completed=True,
                    message="Whois recorded. Error 400 unable to find lat. and long.",
                    status="Error",
                    modified=timezone.now()
                )
                return
            elif kb_response.status_code == 404:
                self.whois_logging.update(
                    is_completed=True,
                    message="Whois recorded Error 404 unable to update lat. and long.",
                    status="Error",
                    modified=timezone.now()
                )
                return
            elif kb_response.status_code == 500:
                self.whois_logging.update(
                    is_completed=True,
                    message="Whois recorded Error 404 unable to update lat. and long. kb is down.",
                    status="Error",
                    modified=timezone.now()
                )
                return

    def check_aws_existence(self):
        api_obj = ApiList.objects.first()
        if api_obj:
            url = "{}/api/ip-aws-status/".format(api_obj.kb_base_url)
            headers = {
                'Content-Type': 'application/json',
                'Authorization': 'Token {}'.format(api_obj.kb_auth_token)
            }
        try:
            kb_response = requests.post(
                url,
                json={'ip': self.target_ip},
                headers=headers
            )
        except Exception as error:
            kb_response = None
        if kb_response and kb_response.status_code == 200:
            api_response = kb_response.json()
            if api_response['status'] == True:
                existence = api_response['data']['aws_existence']
                if existence == True:
                    services = api_response['data']['service']
                    if len(services) == 1:
                        if services[0] == "AMAZON":
                            self.host.service = "Amazon"
                            self.host.aws_existence = True
                        else:
                            self.host.service = services[0]
                            self.host.aws_existence = True
                        self.host.save()
                    elif len(services) > 1:
                        if "AMAZON" in services:
                            services.remove("AMAZON")
                            sorted_services = services
                        else:
                            sorted_services = services
                        self.host.service = sorted_services[0]
                        self.host.aws_existence = True
                        self.host.save()

    def notify_blocked_ip(self):
        if self.client_obj:
            if os.environ.get('REDTREE_URL'):
                redtree_url = os.environ.get('REDTREE_URL')
                home_url = "{}/host/{}/".format(redtree_url, self.host.id)
                subject = "[{0}] A restricted IP has been added.".format(
                    self.client_obj.client_name
                )
                body = "The IP {0} has been added and appears to be restricted.<br><br> <a href='{1}'>{1}</a>".format(
                    self.target_ip,
                    home_url
                )
                reciever = list(set(NotificationEmails.objects.values_list('email', flat=True)))
                send_mail(reciever, subject, body)
            else:
                logging.error('Environment variable is missing')


    def whois_scan(self):
        ip = self.target_ip
        try:
            obj = IPWhois(self.target_ip)
            results = obj.lookup_rdap(depth=1)
        except ipwhois.exceptions.ASNRegistryError as e:
            self.notify_blocked_ip()
            return 
        except Exception as error:
            print traceback.format_exc()
            error_message = "whois scan failed for {} due to {}".format(
                self.target_ip, error
            )
            self.whois_logging.update(
                is_completed=True,
                message=error_message,
                status="Error",
                modified=timezone.now()
            )
            return 
        ip_whois_record = WhoisRecord.objects.filter(ip=self.host, domain_host=self.target_ip)
        IpWhoisRecord.objects.filter(ip=self.host, target_host=self.target_ip).delete()
        if ip_whois_record:
            ip_whois_record.delete()
        try:
            whois_basic_record = WhoisBasicRecord.objects.filter(
                asn_description=results.get("asn_description"),
                network_name=results.get('network').get('name'),
                asn_id=results.get("asn")
            )
            if whois_basic_record.exists():
                basic_record = whois_basic_record.first()
            else:
                basic_record = WhoisBasicRecord.objects.create(
                    asn_description=results.get("asn_description"),
                    network_name=results.get('network').get('name'),
                    asn_id=results.get("asn"),
                    handle=results.get('network').get('handle')
                )
            self.whois_logging.update(
                status="Running",
                modified=timezone.now()
            )
            ip_whois = IpWhoisRecord.objects.create(
                ip=self.host,
                target_host=self.target_ip,
                whois_record=basic_record
            )
            whois_obj = WhoisRecord.objects.create(
                ip=self.host,
                domain_host=self.target_ip,
                asn = results.get("asn"),
                raw = results.get("raw"),
                asn_registry = results.get("asn_registry"),
                asn_country_code = results.get("asn_country_code"),
                asn_date = results.get("asn_date"),
                asn_cidr = results.get("asn_cidr"),
                nir = results.get("nir"),
                query = results.get("query"), 
                asn_description = results.get("asn_description"),
            )
            net = results.get('network')
            status_data = net.get('status')
            status_response = ''
            if status_data:
                for status in status_data:
                    if status_response:
                        status_response = "{}, {}".format(
                            status_response, status
                            )
                    else:
                        status_response = str(status)
            else:
                status_response = ''
            if net.get('handle'):
                handle = net.get('handle')
            else:
                handle = ''
            if net.get('end_address'):
                end_address = net.get('end_address')
            else:
                end_address = ''
            if net.get('start_address'):
                start_address = net.get('start_address')
            else:
                start_address = ''
            if net.get('cidr'):
                cidr = net.get('cidr')
            else:
                cidr = ''
            if net.get('name'):
                name = net.get('name')
            else:
                name = ''
            if net.get('country'):
                country = net.get('country')
            else:
                country = ''
            if net.get('ip_version'):
                ip_version = net.get('ip_version')
            else:
                ip_version = '' 
            if net.get('parent_handle'):
                parent_handle = net.get('parent_handle')
            else:
                parent_handle = ''
            if net.get('type'):
                w_type = net.get('type')
            else:
                w_type = ''
            if net.get('remarks'):
                remarks = net.get('remarks')
            else:
                remarks = ''
            whois_net_obj = WhoisNetsRecord.objects.create(
                whois_record=whois_obj,
                handle=handle,
                end_address=end_address,
                start_address=start_address,
                cidr=cidr,
                name=name,
                country=country,
                ip_version=ip_version,
                parent_handle=parent_handle,
                net_type=w_type,
                remarks=remarks,
                status=status_response
            )
            for notice_data in net.get('notices'):
                raw_list = notice_data.get('links')
                if raw_list:
                    converted_list = ", ".join(map(str, raw_list))
                else:
                    converted_list = None
                WhoisNetNoticesRecord.objects.create(
                    whois_net=whois_net_obj,
                    description=notice_data.get('description'),
                    links=converted_list,
                    title=notice_data.get('title')
                )
            for event_data in net.get('events'):
                WhoisNetEventsRecord.objects.create(
                    whois_net=whois_net_obj,
                    action=event_data.get('action'),
                    actor=event_data.get('actor'),
                    timestamp=event_data.get('timestamp')
                )
            for links_data in net.get('links'):
                WhoisNetLinksRecord.objects.create(
                    whois_net=whois_net_obj,
                    links=links_data
                )
            self.update_goeip(whois_obj, ip_whois)
        except Exception as error:
            print traceback.format_exc()
            error_message = "whois scan failed for {} due to {}".format(
                self.target_ip, error
            )
            self.whois_logging.update(
                is_completed=True,
                message=error_message,
                status="Error",
                modified=timezone.now()
            )
            return

def ips_whois_scan():
    hosts = UserHosts.objects.all()
    for host in hosts:
        if host.host_type in ['ip', 'host_name']:
            WhoisRecord.objects.filter(ip=host).delete()
            IpWhoisRecord.objects.filter(ip=host).delete()
            WhoIsScanHelper(host)



class WhoIsHostUpdateHelper(object):
    """It will create the whois scans"""

    def __init__(self, host):
        self.host = host
        self.client_obj = ClientConfiguration.objects.first()
        if host.host_type == "ip":
            self.target_ip = host.host
            if get_ip_type(self.target_ip) == "External":
                log_obj = LogMicroServiceWhois.objects.create(
                    host=host,
                    status="Queued"
                )
                self.whois_logging = LogMicroServiceWhois.objects.filter(
                    id=log_obj.id
                )
                self.check_aws_existence()
                self.whois_scan()
        elif host.host_type == "cidr": 
            cidr_ip = get_cidr_list(host.host)
            self.target_ip = cidr_ip[0]
            log_obj = LogMicroServiceWhois.objects.create(
                host=host,
                domain_host="{}/{}".format(host.host, cidr_ip[0]),
                status="Queued"
            )
            self.whois_logging = LogMicroServiceWhois.objects.filter(
                id=log_obj.id
            )
            self.check_aws_existence()
            self.whois_scan()
        elif host.host_type == "loose_a": 
            loose_a = get_loose_a_list(host.host)
            self.target_ip = loose_a[0]
            log_obj = LogMicroServiceWhois.objects.create(
                host=host,
                domain_host="{}/{}".format(host.host, loose_a[0]),
                status="Queued"
            )
            self.whois_logging = LogMicroServiceWhois.objects.filter(
                id=log_obj.id
            )
            self.check_aws_existence()
            self.whois_scan()
        elif host.host_type == "loose_b": 
            loose_b = get_loose_b_list(host.host)
            self.target_ip = loose_b[0]
            log_obj = LogMicroServiceWhois.objects.create(
                host=host,
                domain_host="{}/{}".format(host.host, loose_b[0]),
                status="Queued"
            )
            self.whois_logging = LogMicroServiceWhois.objects.filter(
                id=log_obj.id
            )
            self.check_aws_existence()
            self.whois_scan()
        else:
            domain_hosts = get_host_name_list(host.host)
            print "domain_hosts"
            for domainhost in domain_hosts:
                self.target_ip = domainhost
                if get_ip_type(self.target_ip) == "External":
                    log_obj = LogMicroServiceWhois.objects.create(
                        host=host,
                        domain_host="{}/{}".format(host.host, domainhost),
                        status="Queued"
                    )
                    self.whois_logging = LogMicroServiceWhois.objects.filter(
                        id=log_obj.id
                    )
                    self.check_aws_existence()
                    self.whois_scan()
    def update_goeip(self, whois_obj, basic_record):
        api_obj = ApiList.objects.first()
        if api_obj:
            url = "{}/api/geoip/".format(api_obj.kb_base_url)
            headers = {
                'Content-Type': 'application/json',
                'Authorization': 'Token {}'.format(api_obj.kb_auth_token)
            }
        else:
            self.whois_logging.update(
                is_completed=True,
                message="Unable to update lat. and long. Kb api is not set.",
                status="Error",
                modified=timezone.now()
            )
            return
        try:
            kb_response = requests.post(
                url,
                json={'ip': self.target_ip},
                headers=headers
            )
        except Exception as error:
            self.whois_logging.update(
                is_completed=True,
                message="Whois recorded but unable to update lat. and long. due to {}.".format(error),
                status="Error",
                modified=timezone.now()
            )
            return
        if kb_response.status_code == 200:
            geoip_data = kb_response.json().get('data')
            if geoip_data:
                whois_obj.longitude = geoip_data.get('longitude')
                whois_obj.latitude = geoip_data.get('latitude')
                whois_obj.city = geoip_data.get('city')
                basic_record.longitude = geoip_data.get('longitude')
                basic_record.latitude = geoip_data.get('latitude')
                basic_record.city = geoip_data.get('city')
                whois_obj.save()
                basic_record.save()
                self.whois_logging.update(
                    is_completed=True,
                    message="Whois scan completed successfully.",
                    status="Completed",
                    modified=timezone.now()
                )
        elif kb_response.status_code == 400:
            self.whois_logging.update(
                is_completed=True,
                message="Whois recorded. Error 400 unable to find lat. and long.",
                status="Error",
                modified=timezone.now()
            )
            return
        elif kb_response.status_code == 404:
            self.whois_logging.update(
                is_completed=True,
                message="Whois recorded Error 404 unable to update lat. and long.",
                status="Error",
                modified=timezone.now()
            )
            return
        elif kb_response.status_code == 500:
            self.whois_logging.update(
                is_completed=True,
                message="Whois recorded Error 404 unable to update lat. and long. kb is down.",
                status="Error",
                modified=timezone.now()
            )
            return

    def check_aws_existence(self):
        api_obj = ApiList.objects.first()
        if api_obj:
            url = "{}/api/ip-aws-status/".format(api_obj.kb_base_url)
            headers = {
                'Content-Type': 'application/json',
                'Authorization': 'Token {}'.format(api_obj.kb_auth_token)
            }
        try:
            kb_response = requests.post(
                url,
                json={'ip': self.target_ip},
                headers=headers
            )
        except Exception as error:
            kb_response = None
        if kb_response and kb_response.status_code == 200:
            api_response = kb_response.json()
            if api_response['status'] == True:
                existence = api_response['data']['aws_existence']
                if existence == True:
                    services = api_response['data']['service']
                    if len(services) == 1:
                        if services[0] == "AMAZON":
                            self.host.service = "Amazon"
                            self.host.aws_existence = True
                        else:
                            self.host.service = services[0]
                            self.host.aws_existence = True
                        self.host.save()
                    elif len(services) > 1:
                        if "AMAZON" in services:
                            services.remove("AMAZON")
                            sorted_services = services
                        else:
                            sorted_services = services
                        self.host.service = sorted_services[0]
                        self.host.aws_existence = True
                        self.host.save()

    def notify_blocked_ip(self):
        if self.client_obj:
            if os.environ.get('REDTREE_URL'):
                redtree_url = os.environ.get('REDTREE_URL')
                home_url = "{}/host/{}/".format(redtree_url, self.host.id)
                subject = "[{0}] A restricted IP has been added.".format(
                    self.client_obj.client_name
                )
                body = "The IP {0} has been added and appears to be restricted.<br><br> <a href='{1}'>{1}</a>".format(
                    self.target_ip,
                    home_url
                )
                reciever = list(set(NotificationEmails.objects.values_list('email', flat=True)))
                send_mail(reciever, subject, body)
            else:
                logging.error('Environment variable is missing')


    def whois_scan(self):
        ip = self.target_ip
        try:
            obj = IPWhois(ip)
            results = obj.lookup_rdap(depth=1)
        except ipwhois.exceptions.ASNRegistryError as e:
            self.notify_blocked_ip()
            return 
        except Exception as error:
            print traceback.format_exc()
            error_message = "whois scan failed for {} due to {}".format(
                self.target_ip, error
            )
            self.whois_logging.update(
                is_completed=True,
                message=error_message,
                status="Error",
                modified=timezone.now()
            )
            return
            print("in whoiss")
        ip_whois_record = WhoisRecord.objects.filter(ip=self.host, domain_host=self.target_ip)
        IpWhoisRecord.objects.filter(ip=self.host, target_host=self.target_ip).delete()
        if ip_whois_record:
            ip_whois_record.delete()
        try:
            whois_basic_record = WhoisBasicRecord.objects.filter(
                asn_description=results.get("asn_description"),
                network_name=results.get('network').get('name'),
                asn_id=results.get("asn")
            )
            if whois_basic_record.exists():
                basic_record = whois_basic_record.first()
            else:
                basic_record = WhoisBasicRecord.objects.create(
                    asn_description=results.get("asn_description"),
                    network_name=results.get('network').get('name'),
                    asn_id=results.get("asn"),
                    handle=results.get('network').get('handle')
                )
            self.whois_logging.update(
                status="Running",
                modified=timezone.now()
            )
            ip_whois = IpWhoisRecord.objects.create(
                ip=self.host,
                target_host=self.target_ip,
                whois_record=basic_record
            )
            whois_obj = WhoisRecord.objects.create(
                ip=self.host,
                domain_host=self.target_ip,
                asn = results.get("asn"),
                raw = results.get("raw"),
                asn_registry = results.get("asn_registry"),
                asn_country_code = results.get("asn_country_code"),
                asn_date = results.get("asn_date"),
                asn_cidr = results.get("asn_cidr"),
                nir = results.get("nir"),
                query = results.get("query"), 
                asn_description = results.get("asn_description"),
            )
            net = results.get('network')
            status_data = net.get('status')
            status_response = ''
            if status_data:
                for status in status_data:
                    if status_response:
                        status_response = "{}, {}".format(
                            status_response, status
                            )
                    else:
                        status_response = str(status)
            else:
                status_response = ''
            if net.get('handle'):
                handle = net.get('handle')
            else:
                handle = ''
            if net.get('end_address'):
                end_address = net.get('end_address')
            else:
                end_address = ''
            if net.get('start_address'):
                start_address = net.get('start_address')
            else:
                start_address = ''
            if net.get('cidr'):
                cidr = net.get('cidr')
            else:
                cidr = ''
            if net.get('name'):
                name = net.get('name')
            else:
                name = ''
            if net.get('country'):
                country = net.get('country')
            else:
                country = ''
            if net.get('ip_version'):
                ip_version = net.get('ip_version')
            else:
                ip_version = '' 
            if net.get('parent_handle'):
                parent_handle = net.get('parent_handle')
            else:
                parent_handle = ''
            if net.get('type'):
                w_type = net.get('type')
            else:
                w_type = ''
            if net.get('remarks'):
                remarks = net.get('remarks')
            else:
                remarks = ''
            whois_net_obj = WhoisNetsRecord.objects.create(
                whois_record=whois_obj,
                handle=handle,
                end_address=end_address,
                start_address=start_address,
                cidr=cidr,
                name=name,
                country=country,
                ip_version=ip_version,
                parent_handle=parent_handle,
                net_type=w_type,
                remarks=remarks,
                status=status_response
            )
            for notice_data in net.get('notices'):
                raw_list = notice_data.get('links')
                if raw_list:
                    converted_list = ", ".join(map(str, raw_list))
                else:
                    converted_list = None
                WhoisNetNoticesRecord.objects.create(
                    whois_net=whois_net_obj,
                    description=notice_data.get('description'),
                    links=converted_list,
                    title=notice_data.get('title')
                )
            for event_data in net.get('events'):
                WhoisNetEventsRecord.objects.create(
                    whois_net=whois_net_obj,
                    action=event_data.get('action'),
                    actor=event_data.get('actor'),
                    timestamp=event_data.get('timestamp')
                )
            for links_data in net.get('links'):
                WhoisNetLinksRecord.objects.create(
                    whois_net=whois_net_obj,
                    links=links_data
                )
            self.update_goeip(whois_obj, ip_whois)
        except Exception as error:
            print traceback.format_exc()
            error_message = "whois scan failed for {} due to {}".format(
                self.target_ip, error
            )
            self.whois_logging.update(
                is_completed=True,
                message=error_message,
                status="Error",
                modified=timezone.now()
            )
            return



def ips_whois_host(created_hosts):
    hosts = UserHosts.objects.filter(id__in=created_hosts)
    for host in hosts:
        if host.host_type in ['ip', 'host_name', 'cidr' , 'loose_a' ,'loose_b']:
            WhoisRecord.objects.filter(ip=host).delete()
            IpWhoisRecord.objects.filter(ip=host).delete()
            WhoIsHostUpdateHelper(host)