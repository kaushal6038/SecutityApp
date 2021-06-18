import os
import time
import json
import re
from lxml import etree
from redtree_app.constants import *
from redtree_app.models import *


def process_file(data):
    try:
        # xml_content = nessus_file.read()
        root = etree.fromstring(data)
        total_issues = 0
        detected_issues = 0
        undetected_issues = 0
        already_exist_issue = 0
        low_risk_count = 0
        medium_risk_count = 0
        high_risk_count = 0
        critical_risk_count = 0
        vul_history = []
        nessus_data = []
        last_seen = None
        first_identified = None
        for block in root:
            if block.tag == "Report":
                for report_host in block:
                    for report_item in report_host:

                        if report_item.tag == "HostProperties":
                            for host_propeties in report_item:
                                if host_propeties.attrib['name'] == "HOST_START":
                                    first_identified = host_propeties.text
                                elif host_propeties.attrib['name'] == "HOST_END":
                                    last_seen = host_propeties.text
  
                        if 'pluginName' in report_item.attrib:
                            tag_dict = dict()
                            for param in report_item:
                                if param.tag == "risk_factor":
                                    tag_dict['risk_factor'] = param.text
                                elif param.tag == "synopsis":
                                    tag_dict['synopsis'] = param.text
                                elif param.tag == "description":
                                    tag_dict['description'] = param.text
                                elif param.tag == "plugin_output":
                                    tag_dict['plugin_output'] = param.text
                                elif param.tag == "solution":
                                    tag_dict['solution'] = param.text

                            risk = tag_dict.get('risk_factor')
                            synopsis = tag_dict.get('synopsis')
                            solution = tag_dict.get('solution')
                            description = tag_dict.get('description')
                            plugin_output = tag_dict.get('plugin_output')
                            pluginid = report_item.attrib['pluginID']

                            if plugin_output and (pluginid == '10107'):
                                if re.search(BANNER_PATTERN, plugin_output):
                                    banner_pattern = plugin_output.replace("{}".\
                                        format(BANNER_PATTERN), "")
                                    banner = banner_pattern.strip()
                                else:
                                    banner = ''
                            else:
                                banner = ''

                            host = report_host.attrib['name']
                            protocol = report_item.attrib['protocol']
                            port = report_item.attrib['port']
                            pluginname = report_item.attrib['pluginName']
                            svcname = report_item.attrib['svc_name']

                            nessus_dict = {
                                'pluginid': int(pluginid), 'risk': risk,
                                'host':host, 'protocol': protocol,
                                'port': int(port), 'banner': banner,
                                'name': pluginname, 'svc_type': svcname,
                                'description': description, 'solution': solution,
                                'first_identified': first_identified,
                                'last_seen': last_seen,
                                'synopsis': synopsis, 'plugin_output': plugin_output
                            }
                            nessus_data.append(nessus_dict)
        return nessus_data
    except Exception as msg:
        error = "Error {} while processing nessus file.".format(msg)
    	AppNotification.objects.create(issue_type='Error', notification_message=error)
