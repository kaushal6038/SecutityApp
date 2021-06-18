import ipaddress
import socket
import re
from .models import UserHosts
from django.db.models import Sum
from django.db.models import Q
from netaddr import *
import ipaddr


def get_host_type(line):
    if re.search('[a-zA-Z]', line):
        return 'host_name'

    try:
        socket.inet_aton(line)
        return 'ip'
    except socket.error:
        pass
    if line.find('/') != -1:
        if is_valid_cidr(line):
            return 'cidr'
        else:
            return 'invalid'

    if line.find('-') != -1:
        if is_valid_range_a(line):
            return 'loose_a'
        if is_valid_range_b(line):
            return 'loose_b'

    return 'invalid'


def get_host_network_type(ip, ip_type):
    if ip_type == "cidr":
        cidr = (ip).split('/')[0]
        internal_ip = ipaddress.ip_address(unicode(cidr)).is_private
        if not internal_ip:
            network_type = "External"
        else:
            network_type = "Internal"
    elif ip_type == "loose_a":
        loose_a = (ip).split('-')[0]
        internal_ip = ipaddress.ip_address(unicode(loose_a)).is_private
        if not internal_ip:
            network_type = "External"
        else:
            network_type = "Internal"
    elif ip_type == "loose_b":
        loose_b = (ip).split('-')[0]
        internal_ip = ipaddress.ip_address(unicode(loose_b)).is_private
        if not internal_ip:
            network_type = "External"
        else:
            network_type = "Internal"
    elif ip_type == "ip":
        internal_ip = ipaddress.ip_address(unicode(ip)).is_private
        if not internal_ip:
            network_type = "External"
        else:
            network_type = "Internal"
    elif ip_type == "host_name":
        try:
            ip_list = socket.gethostbyname_ex(ip)[2]
        except socket.gaierror:
            ip_list = None
        if ip_list and ip_list[0]:
            internal_ip = ipaddress.ip_address(unicode(ip_list[0])).is_private
            if not internal_ip:
                network_type = "External"
            else:
                network_type = "Internal"
        else:
            return "Invalid"
    else:
        network_type = "Invalid"
    return network_type


def get_check_host(host, host_type):
    if host_type in ['ip', 'cidr', 'loose_b']:
        for (index, value) in enumerate(host):
            if value == ".":
                last_index = index
        check_host = host[:(last_index-1)]
        last_index = check_host.rfind('.')
        check_host = check_host[:last_index]
    elif host_type == "loose_a":
        for (index, value) in enumerate(host):
            if value == "-":
                last_index = index
        check_host = host[:(last_index)]
        for (index, value) in enumerate(check_host):
            if value == ".":
                last_index = index
        check_host = host[:(last_index)]
        last_index = check_host.rfind('.')
        check_host = check_host[:last_index]
    return check_host


def get_host_count(host, host_type):
    if host_type == "ip":
        return 1
    elif host_type == "host_name":
        return 1
    elif host_type == "cidr":
        ip = IPNetwork(host)
        return ip.size
    elif host_type == "loose_a":
        ip1 = host.split('-')[0]
        ip2 = host.split('-')[1]
        ip = IPRange(ip1, ip2)
        return ip.size

    elif host_type == "loose_b":
        ip1 = host.split('-')[0]
        range_end = host.split('-')[1]
        base = ip1.rsplit('.', 1)[0]
        ip2 = base + '.' + range_end
        ip = IPRange(ip1, ip2)
        return ip.size
    else:
        return 0

def get_loos_a_set(host):
    ip1 = host.split('-')[0]
    ip2 = host.split('-')[1]
    ip = IPRange(ip1, ip2)
    loose_a_set = {str(ip) for ip in list(ip)}
    return loose_a_set

def get_loos_b_set(host):
    ip1 = host.split('-')[0]
    range_end = host.split('-')[1]
    base = ip1.rsplit('.', 1)[0]
    ip2 = base + '.' + range_end
    ip = IPRange(ip1, ip2)
    loose_b_set = {str(ip) for ip in list(ip)}
    return loose_b_set


def check_host_exists(host, host_type):
    if UserHosts.objects.filter(
            host=host
    ).exists():
        return UserHosts.objects.filter(host=host).first()
    if host_type == "host_name":
        if UserHosts.objects.filter(
                host=host
        ).exists():
            return UserHosts.objects.filter(host=host).first()
        else:
            return False
    check_host = get_check_host(host, host_type)
    hosts = UserHosts.objects.filter(
        host__icontains=check_host,
        host_type__in=['cidr', 'loose_a', 'loose_b', 'ip']
    )
    if host_type == "ip":
        for host_obj in hosts:
            if host_obj.host_type == 'cidr':
                if IPAddress(host) in IPNetwork(host_obj.host):
                    return host_obj
            elif host_obj.host_type == "loose_a":
                ch_host = host_obj.host
                ip1 = ch_host.split('-')[0]
                ip2 = ch_host.split('-')[1]
                ip = IPRange(ip1, ip2)
                ips = [str(ip) for ip in list(ip)]
                if host in ips:
                    return host_obj
            elif host_obj.host_type == "loose_b":
                ch_host = host_obj.host
                ip1 = ch_host.split('-')[0]
                range_end = ch_host.split('-')[1]
                base = ip1.rsplit('.', 1)[0]
                ip2 = base + '.' + range_end
                ip = IPRange(ip1, ip2)
                ips = [str(ip) for ip in list(ip)]
                if host in ips:
                    return host_obj

    elif host_type == "cidr":
        cidr_set = {str(ip) for ip in list(IPNetwork(host))}
        for host_obj in hosts:
            if host_obj.host_type == 'cidr':
                n1 = ipaddr.IPNetwork(host_obj.host)
                n2 = ipaddr.IPNetwork(host)
                if n1.overlaps(n2) or n2.overlaps(n1):
                    return host_obj
            elif host_obj.host_type == "loose_a":
                loose_a_set = get_loos_a_set(host_obj.host)
                if check_intersection(loose_a_set, cidr_set):
                    return host_obj

            elif host_obj.host_type == "loose_b":
                loose_b_set = get_loos_b_set(host_obj.host)
                if check_intersection(loose_b_set, cidr_set):
                    return host_obj
    elif host_type == "loose_a":
        check_set = get_loos_a_set(host)
        for host_obj in hosts:
            if host_obj.host_type == 'cidr':
                cidr_set = {str(ip) for ip in list(IPNetwork(host_obj.host))}
                if check_intersection(cidr_set, check_set):
                    return host_obj
            elif host_obj.host_type == "loose_a":
                loose_a_set = get_loos_a_set(host_obj.host)
                if check_intersection(loose_a_set, check_set):
                    return host_obj
            elif host_obj.host_type == "loose_b":
                loose_b_set = get_loos_b_set(host_obj.host)
                if check_intersection(loose_b_set, check_set):
                    return host_obj

    elif host_type == "loose_b":
        check_set = get_loos_b_set(host)
        for host_obj in hosts:
            if host_obj.host_type == 'cidr':
                cidr_set = {str(ip) for ip in list(IPNetwork(host_obj.host))}
                if check_intersection(cidr_set, check_set):
                    return host_obj
            elif host_obj.host_type == "loose_a":
                loose_a_set = get_loos_a_set(host_obj.host)
                if check_intersection(loose_a_set, check_set):
                    return host_obj
            elif host_obj.host_type == "loose_b":
                loose_b_set = get_loos_b_set(host_obj.host)
                if check_intersection(loose_b_set, check_set):
                    return host_obj
    return False

def check_intersection(set_1, set_2):
    if (len(set_2.intersection(set_1)) or len(set_1.intersection(set_2)) ) > 0:
        return True


def is_valid_cidr(range):
    try:
        return ipaddress.ip_network(unicode(range), strict=False)
    except:
        return False


def is_valid_range_a(line):

    ip1 = line.split('-')[0]
    ip2 = line.split('-')[1]

    try:
        ipaddress.IPv4Address(unicode(ip1))
    except:
        return False

    try:
        ipaddress.IPv4Address(unicode(ip2))
    except:
        return False

    return True


def is_valid_range_b(line):
    ip1 = line.split('-')[0]
    ip2 = line.split('-')[1]

    try:
        ipaddress.IPv4Address(unicode(ip1))
    except:
        return False

    if int(ip2) <= int(ip1.split('.')[3]):
        return False

    if int(ip2) > 255:
        return False

    return True


def get_host_name_range(host_name):
    ip_list = list()
    try:
        ip_list = socket.gethostbyname_ex(host_name)[2]
    except socket.gaierror:
        pass
    ipList = [{'ip':str(ip), 'id': ''} for ip in ip_list]
    return ipList


def get_hosts_name_list(**kwargs):
    ip_list = list()
    host_name_list = kwargs.get('host_list')
    host_names_list = list()
    for host_name in host_name_list:
        try:
            ips_List = socket.gethostbyname_ex(host_name)[2]
        except socket.gaierror:
            ips_List = []
            pass
        ip_list = ip_list + ips_List
        host_name_dict = {
            'ip': host_name,
            'ip_list': ips_List
        }
        host_names_list.append(host_name_dict)
    return ip_list, host_names_list


def get_all_host_name_list():
    host_names = Host.objects.filter(host_name__isnull=False)
    print host_names
    ip_list = list()
    for host_name in host_names:
        try:
            ips_list = socket.gethostbyname_ex(host_name.host_name)[2]
        except socket.gaierror:
            pass
        host_name_list = [{'ip':str(ip), 'host_name': host_name.host_name ,\
            'id': host_name.id} for ip in ips_list]
        ip_list = ip_list + host_name_list
    return ip_list


def get_cidr_range(cidr):
    ipRange = ipaddress.ip_network(unicode(cidr), strict=False)
    ipList = [{'ip':str(ip), 'id': ''} for ip in ipRange]
    return ipList


def get_loose_a_range(host):
    ip1 = host.split('-')[0]
    ip2 = host.split('-')[1]
    ips = list()
    ip_obj1 = ipaddress.IPv4Address(unicode(ip1))
    ip_obj2 = ipaddress.IPv4Address(unicode(ip2))

    while ip_obj1 <= ip_obj2:
        ips.append({'ip':str(ip_obj1), 'id': ''})
        ip_obj1 = ip_obj1 + 1
    return ips


def get_loose_b_range(host):
    ips = list()
    ip1 = host.split('-')[0]
    range_end = host.split('-')[1]

    base = ip1.rsplit('.', 1)[0]

    ip2 = base + '.' + range_end

    ip_obj1 = ipaddress.IPv4Address(unicode(ip1))
    ip_obj2 = ipaddress.IPv4Address(unicode(ip2))

    while ip_obj1 <= ip_obj2:
        ips.append({'ip':str(ip_obj1), 'id': ''})
        ip_obj1 = ip_obj1 + 1
    return ips


def get_host_name_length(host_name):
    ip_list = []
    try:
        ip_list = socket.gethostbyname_ex(host_name)[2]
    except socket.gaierror:
        pass
    if ip_list:
        count  = len(ip_list)
    else:
        count = 1
    return count

def get_loose_b_length(loose_b):
    ip_list = []
    ips = list()
    ip1 = loose_b.split('-')[0]
    range_end = loose_b.split('-')[1]
    base = ip1.rsplit('.', 1)[0]
    ip2 = base + '.' + range_end
    ip_obj1 = ipaddress.IPv4Address(unicode(ip1))
    ip_obj2 = ipaddress.IPv4Address(unicode(ip2))
    while ip_obj1 <= ip_obj2:
        ip_list.append(ip_obj1)
        ip_obj1 = ip_obj1 + 1
    if ip_list:
        count  = len(ip_list)
    else:
        count = 1
    return count

def get_loose_a_length(loose_a):
    ip_list = []
    ip1 = loose_a.split('-')[0]
    ip2 = loose_a.split('-')[1]
    ip_obj1 = ipaddress.IPv4Address(unicode(ip1))
    ip_obj2 = ipaddress.IPv4Address(unicode(ip2))
    while ip_obj1 <= ip_obj2:
        ip_list.append(ip_obj1)
        ip_obj1 = ip_obj1 + 1
    if ip_list:
        count  = len(ip_list)
    else:
        count = 1
    return count

def get_cidr_length(cidr):
    ip_list = []
    ipRange = ipaddress.ip_network(unicode(cidr), strict=False)
    ip_list = [ip for ip in ipRange]
    if ip_list:
        count  = len(ip_list)
    else:
        count = 1
    return count


def get_cidr_list(cidr):
    ip_list = list()
    ipRange = ipaddress.ip_network(unicode(cidr), strict=False)
    if ipRange:
        ip_list = [str(ip) for ip in ipRange]
    return ip_list


def get_loose_a_list(loose_a):
    ip_list = list()
    ip1 = loose_a.split('-')[0]
    ip2 = loose_a.split('-')[1]
    ip_obj1 = ipaddress.IPv4Address(unicode(ip1))
    ip_obj2 = ipaddress.IPv4Address(unicode(ip2))
    while ip_obj1 <= ip_obj2:
        ip_list.append(str(ip_obj1))
        ip_obj1 = ip_obj1 + 1
    return ip_list


def get_loose_b_list(loose_b):
    ip_list = []
    ips = list()
    ip1 = loose_b.split('-')[0]
    range_end = loose_b.split('-')[1]
    base = ip1.rsplit('.', 1)[0]
    ip2 = base + '.' + range_end
    ip_obj1 = ipaddress.IPv4Address(unicode(ip1))
    ip_obj2 = ipaddress.IPv4Address(unicode(ip2))
    while ip_obj1 <= ip_obj2:
        ip_list.append(str(ip_obj1))
        ip_obj1 = ip_obj1 + 1
    return ip_list


def get_host_name_list(host_name):
    ip_list = list()
    try:
        ip_list = socket.gethostbyname_ex(host_name)[2]
    except socket.gaierror:
        pass
    return ip_list


def check_ip_existance_in_range(host):
    from .models import Host
    ipType = get_host_type(host)
    status = False
    hosts = Host.objects.all()
    ip_list = list()
    for ips in hosts:
        if ips.type == 'cidr':
            cidr = ips.cidr
            cidr_range = get_cidr_list(cidr)
            if cidr_range:
                ip_list = ip_list + cidr_range
        elif ips.type == 'loose_a':
            loose_a = ips.loose_a
            loose_a_range = get_loose_a_list(loose_a)
            if loose_a_range:
                ip_list = ip_list + loose_a_range
        elif ips.type == 'loose_b':
            loose_b = ips.loose_b
            loose_b_range = get_loose_b_list(loose_b)
            if loose_b_range:
                ip_list = ip_list + loose_b_range
        elif ips.type == 'host_name':
            host_name = ips.host_name
            host_name_range = get_host_name_list(host_name)
            if host_name_range:
                ip_list = ip_list + host_name_range
        elif ips.type == 'ip':
            ip_list = ip_list + [ips]
    if str(host) in set(ip_list):
        status = True
    return status


def get_ip_range(host):
    from .models import Host
    host_obj = Host.objects.filter(
        Q(loose_a__icontains=host) |\
        Q(loose_b__icontains=host) |\
        Q(cidr__icontains=host)
    ).first()
    return host_obj


def get_host_list(host):
    ip_type = host.type
    host_list = list()
    if ip_type == 'cidr':
        host_list = get_cidr_list(host.host_address)
    elif ip_type == 'loose_a':
        host_list = get_loose_a_list(host.host_address)
    elif ip_type == 'loose_b':
        host_list = get_loose_b_list(host.host_address)
    elif ip_type == 'host_name':
        host_list = get_host_name_list(host.host_address)
        host_list.append(host.host_address)
    return host_list


def get_hosts_list(hosts):
    ip_list = list()
    for host in hosts:
        host_list = list()
        ip_type = host.type
        if ip_type == 'cidr':
            host_list = get_cidr_list(host.host_address)
        elif ip_type == 'loose_a':
            host_list = get_loose_a_list(host.host_address)
        elif ip_type == 'loose_b':
            host_list = get_loose_b_list(host.host_address)
        elif ip_type == 'host_name':
            host_list = get_host_name_list(host.host_address)
            host_list.append(host.host_address)
        ip_list = ip_list + host_list
    return ip_list


def get_ips_list(hosts):
    ip_list = list()
    for host in hosts:
        host_list = list()
        ip_type = host.type
        print ip_type
        if ip_type == 'cidr':
            host_list = get_cidr_list(host.host_address)
        elif ip_type == 'loose_a':
            host_list = get_loose_a_list(host.host_address)
        elif ip_type == 'loose_b':
            host_list = get_loose_b_list(host.host_address)
        elif ip_type == 'host_name':
            host_list = get_host_name_list(host.host_address)
            host_list.append(host.host_address)
        elif ip_type == 'ip':
            host_list.append(host.host_address)
        ip_list = ip_list + host_list
    return ip_list


def get_single_host_detail(host):
    host_list = list()
    ip_type = host.type
    if ip_type == 'cidr':
        host_list = get_cidr_list(host.host_address)
    elif ip_type == 'loose_a':
        host_list = get_loose_a_list(host.host_address)
    elif ip_type == 'loose_b':
        host_list = get_loose_b_list(host.host_address)
    elif ip_type == 'host_name':
        host_list = get_host_name_list(host.host_address)
    return host_list


def get_ip_list(ip):
    host_list = list()
    ip_type = ip.type
    if ip_type == 'cidr':
        host_list = get_cidr_list(ip.host_address)
    elif ip_type == 'loose_a':
        host_list = get_loose_a_list(ip.host_address)
    elif ip_type == 'loose_b':
        host_list = get_loose_b_list(ip.host_address)
    elif ip_type == 'host_name':
        host_list = get_host_name_list(ip.host_address)
        host_list.append(ip.host_address)
    elif ip_type == 'ip':
        host_list.append(ip.host_address)
    return host_list


def hosts_count():
    from .models import Host
    host_obj = Host.objects.all()
    host_sum = 0
    total_hosts = 0
    for host in host_obj:
        ip_count = 0
        if not host.ip_count:
            if host.type == "host_name":
                ip_count = get_host_name_length(host.host_name)
            elif host.type == "loose_b":
                ip_count = get_loose_b_length(host.loose_b)
            elif host.type == "loose_a":
                ip_count = get_loose_a_length(host.loose_a)
            elif host.type == "cidr":
                ip_count = get_cidr_length(host.cidr)
            if ip_count:
                host_sum = host_sum + ip_count
            else:
                host_sum = host_sum + 1

    totalHost = Host.objects.aggregate(Sum('ip_count'))
    host_count = totalHost['ip_count__sum']
    if host_count and host_sum:
        total_hosts = host_count + host_sum
    elif host_count and not host_sum:
        total_hosts = host_count
    elif host_sum and not host_count:
        total_hosts = host_sum
    return total_hosts


def get_network_type(ip):
    if re.search("\r\n", ip) or re.search("\r", ip) or re.search("\n", ip):
        if re.search("\r\n", ip):
            ip = ip.replace("\r\n", "")
        if re.search("\n", ip):
            ip = ip.replace("\n", "")
        if re.search("\r", ip):
            ip = ip.replace("\r", "")
    ip = ip.strip()
    ip_list = check_ip_existance_in_range(ip)
    ip_type = get_host_type(ip)
    network_type = None
    if ip_type == "cidr":
        cidr = (ip).split('/')[0]
        internal_ip = ipaddress.ip_address(unicode(cidr)).is_private
        if not internal_ip:
            network_type = "External"
        else:
            network_type = "Internal"
    elif ip_type == "loose_a":
        loose_a = (ip).split('-')[0]
        internal_ip = ipaddress.ip_address(unicode(loose_a)).is_private
        if not internal_ip:
            network_type = "External"
        else:
            network_type = "Internal"
    elif ip_type == "loose_b":
        loose_b = (ip).split('-')[0]
        internal_ip = ipaddress.ip_address(unicode(loose_b)).is_private
        if not internal_ip:
            network_type = "External"
        else:
            network_type = "Internal"
    elif ip_type == "ip":
        internal_ip = ipaddress.ip_address(unicode(ip)).is_private
        if not internal_ip:
            network_type = "External"
        else:
            network_type = "Internal"
    elif ip_type == "host_name":
        try:
            ip_list = socket.gethostbyname_ex(ip)[2]
        except socket.gaierror:
            ip_list = None
        if ip_list and ip_list[0]:
            internal_ip = ipaddress.ip_address(unicode(ip_list[0])).is_private
            if not internal_ip:
                network_type = "External"
            else:
                network_type = "Internal"
    return network_type