# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from django.shortcuts import render
from redtree_app.models import *
import socket
from django.db.models import Q
from redtree_app.ip_validator import *
from rest_framework.pagination import PageNumberPagination
from collections import OrderedDict
from datetime import date


# Create your views here.
def get_subdomain_ip_scope(host):
    host_type = get_host_type(host)
    user_host = check_host_exists(host, host_type)
    if user_host:
        return True
    else:
        return False

def get_domain_host(hostname):
    try:
        host = socket.gethostbyname_ex(hostname)[2][0]
    except socket.gaierror:
        host = None
    return host


def get_ciphers_strength():
    secure_ly_v2 = 0
    secure_ly_v3 = 0
    transport_ly_v1 = 0
    transport_ly_v1_1 = 0
    transport_ly_v1_2 = 0
    transport_ly_v1_3 = 0
    ciphers = Ciphers.objects.filter(key_size__isnull=False)
    temp_dict= {}
    
    for cipher in ciphers:
        if cipher.host in temp_dict:
            if cipher.port in temp_dict[cipher.host]:
                if not cipher.protocol in temp_dict[cipher.host][cipher.port]:
                    temp_dict[cipher.host][cipher.port].append(cipher.protocol)
            else:
                temp_dict[cipher.host][cipher.port] = [cipher.protocol]
        else:
            temp_dict[cipher.host] = {
                cipher.port: [cipher.protocol]
            }
    protocol_list = list()
    for ports in temp_dict.values():
        for port_list in ports.values():
            protocol_list.append(port_list)
    for proto in protocol_list:
        status = False
        for protocol in ['SSLv2','SSLv3']:
            if protocol in proto:
                status = True
                break
        if status:
            for protocol in ['SSLv2','SSLv3']:
                if protocol in proto:
                    if protocol == 'SSLv2':  
                        secure_ly_v2+=1
                        break
                    elif protocol == 'SSLv3':
                        secure_ly_v3+=1
        else:
            if 'TLSv1' in proto:
                status = True
                transport_ly_v1+=1
            if not status:
                for protocol in ['TLSv1_1','TLSv1_2','TLSv1_3']:
                    if protocol in proto:
                        status = True
                        break
                if status:
                    for protocol in ['TLSv1_1','TLSv1_2','TLSv1_3']:
                        if protocol in proto:
                            if protocol == 'TLSv1_1':
                                transport_ly_v1_1+=1
                                break
                            elif protocol == 'TLSv1_2':
                                transport_ly_v1_2+=1
                                break
                            elif protocol == 'TLSv1_3':
                                transport_ly_v1_3+=1
    context = {
        'secure_ly_v2': secure_ly_v2,
        'secure_ly_v3': secure_ly_v3,
        'transport_ly_v1': transport_ly_v1,
        'transport_ly_v1_1': transport_ly_v1_1,
        'transport_ly_v1_2': transport_ly_v1_2,
        'transport_ly_v1_3': transport_ly_v1_3
    }
    return context


def get_strength_count():
    low_count = Ciphers.objects.filter(strength="Low").count()
    high_count = Ciphers.objects.filter(strength="High").count()
    medium_count = Ciphers.objects.filter(strength="Medium").count()
    context = {
        'low_count' :low_count,
        'medium_count' :medium_count,
        'high_count' :high_count
    }
    return context


class CustomPagination(PageNumberPagination):
    page_size = 200
    page_size_query_param = 'page_size'
    max_page_size = 1000

    def get_paginated_response_data(self, data):
        page_range = (self.page.paginator.num_pages)  
        has_other_pages = self.page.has_other_pages()
        has_previous = self.page.has_previous()
        page_number = self.page.number
        previous_page_number = page_number - 1
        has_next = self.page.has_next()
        try:
            next_page_number = self.page.next_page_number()
        except:
            next_page_number = None
        return OrderedDict([
            ('page_range', range(1, page_range+1)),
            ('has_other_pages', has_other_pages),
            ('has_previous', has_previous),
            ('previous_page_number', previous_page_number),
            ('page_number', page_number),
            ('has_next', has_next),
            ('next_page_number', next_page_number),
            ('count', self.page.paginator.count),
            ('next', self.get_next_link()),
            ('previous', self.get_previous_link()),
            ('results', data)
        ])



def get_paginated_data(serializer_class, queryset, request,
                        view, pagination_class=CustomPagination):
    paginator = pagination_class()
    page = paginator.paginate_queryset(queryset, request, view)
    if page is not None:
        serializer = serializer_class(
            page,
            many=True,
            context={'request': request}
        )
        return paginator.get_paginated_response_data(serializer.data)
    else:
        return {}


def update_vulnerabilities_chart():
    vul_risks = Vulnerability.objects.values('risk').annotate(
        count=Count('risk')
    )
    vuln_risks = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Note": 0
    }
    for r_risk in vul_risks:
        vuln_risks[r_risk['risk']] += r_risk['count']
    active_ips = Vulnerability.objects.values_list(
        'host_ip', flat=True
    ).distinct().count()
    open_ports = Vulnerability.objects.filter(
        title__icontains="Open TCP Port"
    ).count()
    print active_ips, open_ports
    if HistoricalData.objects.filter(
        created__date=date.today()
    ).exists():
        HistoricalData.objects.filter(
            created__date=date.today()
        ).update(
            active_ips=active_ips,
            open_ports=open_ports
        )
    else:
        HistoricalData.objects.create(
            active_ips=active_ips,
            open_ports=open_ports
        )
    if RiskHistoricalData.objects.filter(
        created__date=date.today()
    ).exists():
        RiskHistoricalData.objects.filter(
            created__date=date.today()
        ).update(
            critical_risk=vuln_risks['Critical'],
            high_risk=vuln_risks['High'],
            medium_risk=vuln_risks['Medium'],
            low_risk=vuln_risks['Low']
        )
    else:
        RiskHistoricalData.objects.create(
            critical_risk=vuln_risks['Critical'],
            high_risk=vuln_risks['High'],
            medium_risk=vuln_risks['Medium'],
            low_risk=vuln_risks['Low']
        )