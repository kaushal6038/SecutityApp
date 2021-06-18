from redtree_app.models import *
from django.db.models import Count, Q
from collections import Counter
import re
from django.template.loader import render_to_string
import os
from datetime import date, datetime, timedelta
from playground.models import ApplicationScanData

def find_markdown_images(markdown_text):
    regex = r"[^(\s]+\.(?:jpeg|jpg|png|gif)(?=\))"
    return re.findall(regex, markdown_text)


def change_media_path(markdown_text):
    regex = r"[^(\s]+(?=\))"
    markdown_images = re.findall(regex, markdown_text)
    for image in markdown_images:
        if image.startswith('http'):
            image_name = image.split('?')[0].split('/')[-1]
            image_key = ''.join(['screenshots/', image_name])
        else:
            image_key = ''.join(['screenshots/', os.path.basename(image)])
        markdown_text = markdown_text.replace(image, image_key)
    return markdown_text


def get_request_header():
    client_conf_obj = ClientConfiguration.objects.first()
    if client_conf_obj:
        header = {
            'data-auth-key': client_conf_obj.authentication_token
        }
    else:
        header = {
            'data-auth-key': None,
        }
    return header


def get_appliance(appliance_type=None):
    try:
        if appliance_type and appliance_type == "Internal":
            return Appliances.objects.get(network_type="Internal")
        elif appliance_type and appliance_type == "External":
            return Appliances.objects.get(network_type="External")
    except Appliances.DoesNotExist:
        return None

def get_sorted_vulnerabilities(*args, **kwargs):
    virtue_id_list = kwargs.get('virtue_ids')
    network_type = kwargs.get('network_type')
    idsbyCount = Counter(virtue_id_list)
    vulnerablityList = []
    vulnerabilities = Vulnerability.objects.filter(
        virtue_id__in=virtue_id_list,
        host__user_host__network__network_type=network_type
    )
    vulnerabilities_dict = dict()
    for vulnerability in vulnerabilities:
        virtue_id = vulnerability.virtue_id
        if virtue_id in vulnerabilities_dict:
            if vulnerabilities_dict[virtue_id].created > vulnerability.created:
                vulnerabilities_dict[virtue_id] = vulnerability
        else:
            vulnerabilities_dict[virtue_id]=vulnerability
    for vul_obj in vulnerabilities_dict.values():
        risk_factor = get_risk_factor(vul_obj.risk)
        if vul_obj.virtue_id in idsbyCount:
            count = idsbyCount[vul_obj.virtue_id]
        vulnerablityList.append({
            'risk': vul_obj.risk,
            'risk_factor': risk_factor,
            'title': vul_obj.title,
            'instances': count,
            'virtue_id': vul_obj.virtue_id,
            'network_type': network_type
        })
    vulnerabilityDetails = sorted(vulnerablityList,
                                  key=lambda x: x['risk_factor'], reverse=True
                                  )
    return vulnerabilityDetails


def get_risk_factor(risk):
    risk_status = dict()
    risk_status["Critical"] = 5
    risk_status["High"] = 4
    risk_status["Medium"] = 3
    risk_status["Low"] = 2
    risk_status["Note"] = 1
    risk_status[None] = 0
    return risk_status[risk]


def get_sorted_cipher(cipher):
    ciphers = Ciphers.objects.filter(
        key_size=cipher.get('key_size'),
        cipher=cipher.get('cipher')).values_list('protocol', flat=True
                                                 )
    sorted_ciphers = {
        'cipher_count': cipher.get('cipher_count'),
        'cipher': cipher.get('cipher'),
        'key_size': cipher.get('key_size'),
        'strength': cipher.get('strength'),
        'risk_factor': get_risk_factor(cipher.get('strength')),
        'protocol': sorted(set(ciphers), reverse=True)
    }
    return sorted_ciphers


def get_sorted_host_vulnerabilities(*args, **kwargs):
    virtue_id_list = kwargs.get('virtue_ids')
    host_obj = kwargs.get('host')
    idsbyCount = Counter(virtue_id_list)
    vulnerablityList = []
    for virtue_id, count in idsbyCount.items():
        vulnerability = Vulnerability.objects.filter(
            virtue_id=virtue_id, host=host_obj
        ).first()
        risk_factor = get_risk_factor(vulnerability.risk)
        vulnerablityList.append({
            'id': vulnerability.id,
            'risk': vulnerability.risk,
            'risk_factor': risk_factor,
            'title': vulnerability.title,
            'instances': count,
            'virtue_id': virtue_id,
            'host_ip': vulnerability.host.id,
            'host_id': vulnerability.host.id
        })
    vulnerabilityDetails = sorted(vulnerablityList,
                                  key=lambda x: x['risk_factor'], reverse=True
                                  )
    return vulnerabilityDetails


def get_sorted_user_host_vulnerabilities(*args, **kwargs):
    virtue_id_list = kwargs.get('virtue_ids')
    user_host_obj = kwargs.get('user_host')
    host_objs = user_host_obj.user_host.all()
    idsbyCount = Counter(virtue_id_list)
    vulnerablityList = []
    for virtue_id, count in idsbyCount.items():
        vulnerability = Vulnerability.objects.filter(
            virtue_id=virtue_id, host__in=host_objs
        ).first()
        risk_factor = get_risk_factor(vulnerability.risk)
        vulnerablityList.append({
            'id': vulnerability.id,
            'risk': vulnerability.risk,
            'risk_factor': risk_factor,
            'title': vulnerability.title,
            'instances': count,
            'virtue_id': virtue_id,
            'host_ip': vulnerability.host_ip,
            'host_id': vulnerability.host.id
        })
    vulnerabilityDetails = sorted(vulnerablityList,
                                  key=lambda x: x['risk_factor'], reverse=True
                                  )
    return vulnerabilityDetails


def update_cipher_helper():
    ciphers = list(Ciphers.objects.filter(
        key_size__isnull=False
    ).distinct('cipher').values_list('cipher', flat=True))
    enc_cache_ciphers = EncryptionCacheCiphers.objects.filter(
        Q(name_iana__in=ciphers) | Q(name_openssl__in=ciphers)
    ).values('name_iana', 'name_openssl', 'strength')
    for data in enc_cache_ciphers:
        name_iana = data.get('name_iana')
        name_openssl = data.get('name_openssl')
        strength = data.get('strength')
        Ciphers.objects.filter(
            Q(cipher=name_iana) | Q(cipher=name_openssl)
        ).update(strength=strength)


def application_vulnerability_count(serialized_data):
    risks_by_count = ApplicationVulnerability.objects.all().values('application_id','risk')
    temp_dict = dict()
    for risks_count in risks_by_count:
        risks = {
            'Critical': 0,
            'High': 0,
            'Medium': 0,
            'Low': 0,
        }
        if risks_count['application_id'] in temp_dict:
            temp_dict[risks_count['application_id']][risks_count['risk']] += 1
        else:
            risks[risks_count['risk']] += 1
            temp_dict[risks_count['application_id']] = risks

    for data in serialized_data:
        if data['last_scan']:
            if data['id'] in temp_dict:
                temp_dict[data['id']]['Total'] = sum(temp_dict[data['id']].values())
                data['vulnerabilities_count'] = temp_dict[data['id']]
            else:
                data['vulnerabilities_count'] = {
                    'Critical': 0,
                    'High': 0,
                    'Medium': 0,
                    'Low': 0,
                    'Total':0
                }
        else:
            data['vulnerabilities_count'] = {
                'Critical': 0,
                'High': 0,
                'Medium': 0,
                'Low': 0,
                'Total':0
                }
    return serialized_data


def unprocessed_burp_count(serialized_data):
    issue_by_count = ApplicationScanData.objects.filter(virtue_id__isnull=True).values('application_fk','severity')
    temp_dict ={}
    for i in issue_by_count:
        issues = {
          'critical': 0,
          'info': 0,
          'high': 0,
          'medium': 0,
          'low': 0,
        } 
        if i['application_fk'] in temp_dict: 
            temp_dict[i['application_fk']][i['severity']] +=1
        else:
            issues[i['severity']] += 1
            temp_dict[i['application_fk']] = issues

    for data in serialized_data:
        if data['id'] in temp_dict:
            temp_dict[data['id']]['Total'] = sum(temp_dict[data['id']].values())
            data['unprocessed_burp_issues_count'] = temp_dict[data['id']]
        else:
            data['unprocessed_burp_issues_count'] = {
                'critical': 0,
                'info': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'Total':0
            }
    return serialized_data
