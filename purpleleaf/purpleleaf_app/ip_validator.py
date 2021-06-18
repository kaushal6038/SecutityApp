import socket
import time
import re
from whois import *
import ipaddress
from django.db.models import Sum


def get_range_type(line):

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


def get_objects_list(line):
    if re.search(",", line):
        ip_line = line.split(',')
    elif re.search(",", line) and re.search("\n", line):
        ip_line = line.split()
    elif re.search(";", line):
        ip_line = line.split(';')
    elif re.search(";", line) and re.search("\n", line):
        ip_line = line.split()
    elif re.search(r"\s", line):
        ip_line = line.split()
    elif re.search(r"\t", line):
        ip_line = line.split()
    elif re.search(r"\n", line):
        ip_line = line.splitlines()
    else:
        ip_line = line.splitlines()
    return ip_line
