import ipaddress
from redtree_app.models import Host
from redtree_app.ip_validator import *


def get_ips():
    ips = dict()
    ips['external_ips'] = [host.host_address for host in Host.objects.filter(
        network__network_type="External"
    )]
    ips['internal_ips'] = [host.host_address for host in Host.objects.filter(
        network__network_type="Internal"
    )]
    ips['external_count'] = len(ips['external_ips'])
    ips['internal_count'] = len(ips['internal_ips'])
    return ips


def cipher_host_ip(host_ip):
    ips = dict()
    try:
        internal_ip = ipaddress.ip_address(unicode(host_ip)).is_private
        if not internal_ip:
            ips['external_ip'] = host_ip
            ips['internal_ip'] = None
        else:
            ips['internal_ip'] = host_ip
            ips['external_ip'] = None
    except Exception as e:
        ips['external_ip'] = None
        ips['internal_ip'] = None

    return ips


def get_ip_type(host_ip):
    '''
    This will accept one Ip and check it for internal or external
    '''
    try:
        internal_ip = ipaddress.ip_address(unicode(host_ip)).is_private
        if internal_ip:
            return "Internal"
        else:
            return "External"
    except:
        return "Invalid"


def get_masscan_ips():
    ips = dict()
    ips['external_ips'] = [host.host for host in UserHosts.objects.filter(
        network__network_type="External"
    ).exclude(host_type="host_name")]
    external_host_names = UserHosts.objects.filter(
        network__network_type="External", host_type="host_name"
    ).values_list('host',flat=True)
    external_hosts_list = [str(ip) for ip in external_host_names if ip]
    external_host_name_list, ext_host_name_list_with_hostname = get_hosts_name_list(
        host_list=external_hosts_list
    )
    ips['external_ips'] = ips['external_ips'] + external_host_name_list
    ips['internal_ips'] = [host.host for host in UserHosts.objects.filter(
        network__network_type="Internal"
    ).exclude(host_type="host_name")]
    internal_host_names = UserHosts.objects.filter(
        network__network_type="Internal", host_type="host_name"
    ).values_list('host',flat=True)
    internal_hosts_list = [str(ip) for ip in internal_host_names if ip]
    internal_host_name_list, int_host_name_list_with_hostname = get_hosts_name_list(
        host_list=internal_hosts_list
    )
    ips['internal_ips'] = ips['internal_ips'] + internal_host_name_list
    ips['external_count'] = len(ips['external_ips'])
    ips['internal_count'] = len(ips['internal_ips'])
    ips['internal_host_name_list'] = int_host_name_list_with_hostname
    ips['external_host_name_list'] = ext_host_name_list_with_hostname
    return ips


def get_nessus_ips():
    ips = dict()
    ext_ips = UserHosts.objects.filter(network__network_type="External")
    ext_ip_list = list()
    for ip in ext_ips:
        ext_ip_list.append(ip.host)
    external_ips = ", ".join(map(str,ext_ip_list))
    ips['external_ips'] = external_ips
    int_ips = UserHosts.objects.filter(network__network_type="Internal")
    int_ip_list = list()
    for ip in int_ips:
        int_ip_list.append(ip.host)
    internal_ips = ", ".join(map(str,int_ip_list))
    ips['internal_ips'] = internal_ips
    return ips