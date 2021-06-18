from lxml import etree
from redtree_app.ip_validator import *
from redtree_app.models import *
from nessus.models import *
from threading import Thread
from django.db import connection
import logging
import json
import re
from redtree_app.constants import BANNER_PATTERN

logger = logging.getLogger('nessus')


def get_request_ip(request):
    try:
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
    except:
        return request


def postpone(function):
    def decorator(*args, **kwargs):
        t = Thread(target=function, args=args, kwargs=kwargs)
        t.daemon = True
        t.start()

    return decorator


def add_applications(request, application_ip_data, file_obj):
    logging.info('Processing .....')
    logging.info('Generating Applications record.')
    created_applications = list()
    for data in application_ip_data:
        application_url = data.get('application_url')
        nessus_obj = data.get('nessus_obj')
        try:
            user_host = UserHosts.objects.get(id=nessus_obj.user_host.id)
        except:
            user_host = None
        if user_host and application_url and not Applications.objects.filter(
                application_url=application_url
        ).exists():
            Applications.objects.create(
                application_url=application_url,
                host=user_host,
                host_link=nessus_obj.host_link,
                network_type=user_host.network.network_type
            )
            created_applications.append('<br>' + application_url)
    if created_applications:
        from redtree_app.tasks import send_application_add_mail
        logging.info('Added task to notify user for the added applications.')
        send_application_add_mail.delay(application_urls=created_applications)
    if file_obj:
        file_obj.update(
            applications_process_status=True
        )
    logging.info('Applications processed successfully.')


def get_application_data(nessus_obj):
    application_ip_data = list()
    for nessusObj in nessus_obj:
        if re.search("SSL : yes", (nessusObj.plugin_output)):
            if not (nessusObj.port in (80, 443)):
                application_url = "https://" + str(nessusObj.host) + \
                                  ":" + str(nessusObj.port)
            else:
                application_url = "https://" + str(nessusObj.host)
        elif re.search("SSL : no", (nessusObj.plugin_output)):
            if not (nessusObj.port in (80, 443)):
                application_url = "http://" + str(nessusObj.host) + \
                                  ":" + str(nessusObj.port)
            else:
                application_url = "http://" + str(nessusObj.host)
        else:
            application_url = None
        if application_url:
            if nessusObj.user_host:
                data = {
                    "application_url": application_url,
                    "nessus_obj": nessusObj
                }
                application_ip_data.append(data)
    return application_ip_data


@postpone
def reprocess_nessus(*args, **kwargs):
    request = kwargs.get('request')
    process_nessus_data(request=request, nessus_import=False)


def process_nessus_data(*args, **kwargs):
    request = kwargs.get('request')
    nessus_import = kwargs.get('nessus_import')
    process_obj = kwargs.get('process_obj')
    if process_obj:
        file_obj = process_obj.first()
    else:
        file_obj = None
    try:
        if request == 'cron_job':
            username = 'cron_job'
            request_ip = 'cron_job'
        else:
            request = request
            username = request.user.username
            request_ip = get_request_ip(request)
        conf_obj = ClientConfiguration.objects.first()
        nessusModelObj = NessusData.objects
        logger.info('Processing .....')
        if conf_obj:
            nessusObjs = nessusModelObj.all()
            plugin_ids = nessusObjs.values_list('plugin_id', flat=True).distinct()
            plugin_Ids = [int(item) for item in plugin_ids]
            appliances_obj = Appliances.objects.first()
            nessus_app_issues = nessusModelObj.filter(plugin_id=24260)
            logger.info('Processing Applications from nessus issues for plugin 24260.....')
            application_ip_data = get_application_data(nessus_app_issues)
            logger.info('Processing Applications from nessus issues for plugin 24260.....')
            if application_ip_data:
                add_applications(
                    request,
                    application_ip_data,
                    process_obj
                )
            logger.info('Processing vulnerabilities from nessus issues.')
            vul_history = list()
            data = {
                'plugin_list': plugin_Ids
            }
            api_obj = ApiList.objects.first()
            logger.info('Querying kb for the articles....')
            if api_obj:
                url = "{}/kb-plugins/".format(api_obj.kb_base_url)
            else:
                url = None
            headers = {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'Authorization': 'Token {}'.format(api_obj.kb_auth_token)
            }
            try:
                article_response = requests.post(url, json=data, headers=headers)
            except Exception as error:
                error_message = "Unable to create vulnerabilities due to {}".format(str(error))
                logger.error(error_message)
                if process_obj:
                    process_obj.update(
                        error_message=error_message,
                        is_completed=True
                    )
                logger.info('')
                connection.close()
                article_response = None
                return

            if article_response and article_response.status_code == 200:
                logger.info('Processing response from kb.')
                logger.info('Processing vulnerabilities.')
                response_data = article_response.json().get('data').get('article_list')
                vul_count = list()
                kb_plugin_list = list()
                for nesus_obj in response_data:
                    pluginid = nesus_obj.get('pluginId')
                    kb_plugin_list.append(pluginid)
                    virtue_id = nesus_obj.get('virtue_id')
                    triage = nesus_obj.get('triage')
                    title = nesus_obj.get('title')
                    modified_date = nesus_obj.get('date')
                    nessusdata_obj = nessusModelObj.filter(
                        plugin_id=pluginid
                    ).update(virtue_id=virtue_id)
                    if triage == "Auto":
                        nessusdata_obj = nessusModelObj.filter(plugin_id=pluginid)
                        for article in nessusdata_obj:
                            nessus_ids = list()
                            vul_obj = Vulnerability.objects.filter(
                                virtue_id=int(virtue_id),
                                port=article.port, host_ip=article.host
                            )
                            network_type = None
                            host_type = get_host_type(article.host)
                            user_host = check_host_exists(article.host, host_type)
                            if user_host and not vul_obj.exists():
                                network_type = user_host.network.network_type
                                if not Host.objects.filter(
                                        user_host=user_host, host=article.host
                                ).exists():
                                    host_obj = Host.objects.create(
                                        user_host=user_host, host=article.host
                                    )
                                else:
                                    host_obj = Host.objects.filter(
                                        user_host=user_host, host=article.host
                                    ).first()
                                vul_obj = Vulnerability.objects.create(
                                    virtue_id=int(virtue_id), plugin_id=article.plugin_id,
                                    title=title, banner=article.banner, post_status=True,
                                    description=nesus_obj.get('description'),
                                    risk=nesus_obj.get('risk'), port=article.port,
                                    remediation=nesus_obj.get('remediation'),
                                    host_ip=article.host, network_type=network_type,
                                    host=host_obj, modified_date=modified_date
                                )
                                vul_history.append(vul_obj.title)
                                vul_count.append(vul_obj)
                                article.confirmed = True
                                article.date_confirmed = date.today()
                                article.save()
                            elif vul_obj.exists() and nessus_import:
                                vul_obj.update(
                                    modified_date=timezone.now(),
                                    modified=timezone.now()
                                )
                    else:
                        nessus_data = NessusData.objects.filter(
                            plugin_id=pluginid
                        ).exclude(confirmed=True)
                        for article in nessus_data:
                            host_type = get_host_type(article.host)
                            user_host = check_host_exists(article.host, host_type)
                            if user_host and not TestVulnerabilities.objects.filter(
                                    virtue_id=int(virtue_id), port=article.port,
                                    host_ip=article.host
                            ).exists():
                                if not Host.objects.filter(
                                        user_host=user_host, host=article.host
                                ).exists():
                                    host_obj = Host.objects.create(
                                        user_host=user_host, host=article.host
                                    )
                                else:
                                    host_obj = Host.objects.filter(
                                        user_host=user_host, host=article.host
                                    ).first()
                                vul_obj = TestVulnerabilities.objects.create(
                                    virtue_id=int(virtue_id), plugin_id=article.plugin_id,
                                    title=title, banner=article.banner,
                                    description=nesus_obj.get('description'),
                                    risk=nesus_obj.get('risk'), port=article.port,
                                    remediation=nesus_obj.get('remediation'),
                                    host_ip=article.host, host=host_obj,
                                    modified_date=modified_date
                                )
                                vul_history.append(vul_obj.title)
                                article.confirmed = True
                                article.date_confirmed = date.today()
                                article.save()
                            elif TestVulnerabilities.objects.filter(
                                    virtue_id=int(virtue_id), port=article.port,
                                    host_ip=article.host).exists() and nessus_import:
                                TestVulnerabilities.objects.filter(
                                    virtue_id=int(virtue_id), port=article.port,
                                    host_ip=article.host
                                ).update(modified=timezone.now())
                not_kb_plugin_list = list(set(plugin_Ids) ^ set(kb_plugin_list))
                NessusData.objects.filter(
                    plugin_id__in=not_kb_plugin_list
                ).update(virtue_id=None)
                if vul_history:
                    vul_history = set(vul_history)
                    vul_list = ", ".join(vul_history)
                    vul_history_data = "create_vulnerability: {}".format(vul_list)
                    RedtreeEventHistory.objects.create(
                        event_type='create_vulnerability',
                        time_stamp=datetime.now().strftime('%s'),
                        username=username,
                        ip=request_ip,
                        data=vul_history_data
                    )
                new_vulnerabilities_created = 0
                if vul_count:
                    new_vulnerabilities_created = len(vul_count)
                if EventCountHistory.objects.filter(
                        created__date=date.today()
                ).exists():
                    hist_data_obj = EventCountHistory.objects.filter(
                        created__date=date.today()
                    ).first()
                    if hist_data_obj.vulnerability_found > 0:
                        new_count = \
                            hist_data_obj.vulnerability_found \
                            + new_vulnerabilities_created
                    else:
                        new_count = new_vulnerabilities_created
                    hist_data_obj.vulnerability_found = new_count
                    hist_data_obj.save()
                else:
                    EventCountHistory.objects.create(
                        vulnerability_found=new_vulnerabilities_created
                    )
                if new_vulnerabilities_created:
                    if new_vulnerabilities_created == 1:
                        activity_text = "Vulnerability scan complete. {}" \
                                        " issue queued for processing.". \
                            format(new_vulnerabilities_created)
                    else:
                        activity_text = "Vulnerability scan complete. {}" \
                                        " issues queued for processing.". \
                            format(new_vulnerabilities_created)
                else:
                    activity_text = "Vulnerability scan complete." \
                                    " No new issues found."
                logger.info(activity_text)
                ActivityLog.objects.create(activity=activity_text)
                if process_obj:
                    process_obj.update(
                        vulnerabilities_process_status=True,
                        is_completed=True
                    )
                logger.info('Vulnerabilities processing completed.')
            else:
                try:
                    status = article_response.status_code
                except:
                    status = None
                if status:
                    error_message = "Vulnerabilities are not created as unable to fetech" \
                                    "articles from kb. status {}".format(status_code)
                else:
                    error_message = "Vulnerabilities are not created as unable to fetech" \
                                    "articles from kb."
                logger.info(error_message)
                if process_obj:
                    process_obj.update(
                        is_completed=True,
                        error_message=error_message
                    )
        else:
            error_message = "Unable to process Applications and Vulnerabilities" \
                            "as configuration is not set properly."
            logger.info(error_message)
            if process_obj:
                process_obj.update(
                    is_completed=True,
                    error_message=error_message
                )
    except Exception as error:
        logger.info(error)
        if process_obj:
            process_obj.update(
                is_completed=True,
                error_message=str(error),
            )
        sentry_client.captureException()
    if process_obj:
        process_obj.update(
            is_completed=True
        )
    connection.close()


def process_nessus_file(*args, **kwargs):
    process_obj = kwargs.get('file')
    context = kwargs.get('context')
    request = kwargs.get('request')
    file_obj = process_obj.first()
    file_path = file_obj.file.path
    logger.info('Starting: Processing issue from xml_content.')
    context = etree.iterparse(
        file_path,
        events=('end',),
        tag="ReportHost"
    )
    total_issues = 0
    detected_issues = 0
    undetected_issues = 0
    already_exist_issue = 0
    low_risk_count = 0
    medium_risk_count = 0
    high_risk_count = 0
    critical_risk_count = 0
    low_new_issue = 0
    medium_new_issue = 0
    high_new_issue = 0
    critical_new_issue = 0
    vul_history = []
    obj = []
    log_obj = []
    host_obj = []
    for event, elem in context:
        first_identified = None
        last_seen = None
        host = elem.get('name')
        logger.info('Processing issue for host : {}'.format(host))
        for child in elem:
            if child.tag == "HostProperties":
                for host_prop_tags in child:
                    if host_prop_tags.attrib['name'] == "HOST_START":
                        first_identified = host_prop_tags.text
                    elif host_prop_tags.attrib['name'] == "HOST_END":
                        last_seen = host_prop_tags.text
            if child.tag == "ReportItem":
                main_tags = child.attrib
                child_tags = dict()
                for ch_tags in child:
                    if ch_tags.text:
                        tag_text = ch_tags.text.strip()
                    else:
                        tag_text = ch_tags.text
                    child_tags[ch_tags.tag] = tag_text
                if child_tags.get('solution') and \
                        child_tags.get('solution') in ['n/a', 'N/A']:
                    child_tags['solution'] = ''
                plugin_output = child_tags.get('plugin_output')
                pluginid = int(main_tags.get('pluginID'))
                if plugin_output and (pluginid == 10107):
                    if re.search(BANNER_PATTERN, plugin_output):
                        banner_pattern = plugin_output.replace("{}". \
                                                               format(BANNER_PATTERN), "")
                        banner = banner_pattern.strip()
                    else:
                        banner = ''
                else:
                    banner = ''
                risk = child_tags.get('risk_factor')
                synopsis = child_tags.get('synopsis')
                description = child_tags.get('description')
                solution = child_tags.get('solution')
                protocol = main_tags.get('protocol')
                port = main_tags.get('port')
                pluginname = main_tags.get('pluginName')
                svcname = main_tags.get('svc_type')
                try:
                    host_type = get_host_type(host)
                    user_host = check_host_exists(host, host_type)
                    logger.info(user_host)
                    if user_host and not NessusData.objects.filter(
                            plugin_id=int(pluginid), host=host,
                            port=int(port), name=pluginname
                    ).exists():
                        try:
                            host_link_obj = Host.objects.get(
                                host=host
                            )
                        except Host.MultipleObjectsReturned:
                            host_link_obj = Host.objects.filter(
                                host=host
                            ).first()
                        except Host.DoesNotExist:
                            host_link_obj = Host.objects.create(
                                host=host,
                                user_host=user_host
                            )
                        nessus_obj = NessusData(
                            user_host=user_host,
                            host_link=host_link_obj,
                            linked_file=file_obj,
                            plugin_id=int(pluginid),
                            risk=risk, host=host,
                            protocol=protocol, port=int(port),
                            banner=banner, name=pluginname,
                            svc_type=svcname,
                            description=description,
                            first_identified=first_identified,
                            last_seen=last_seen,
                            synopsis=synopsis,
                            plugin_output=plugin_output,
                            solution=solution
                        )
                        obj.append(nessus_obj)
                        issue = "Issue with host {}, port {} and" \
                                " pluginID {} is added.". \
                            format(
                            host, port,
                            pluginid
                        )
                        nessus_log = NessusFileLog(
                            linked_file=file_obj,
                            issue_type="new",
                            issue=issue
                        )
                        log_obj.append(nessus_log)
                        detected_issues = detected_issues + 1
                        if risk == 'Medium':
                            medium_new_issue = medium_new_issue + 1
                        elif risk == 'Low':
                            low_new_issue = low_new_issue + 1
                        elif risk == 'High':
                            high_new_issue = high_new_issue + 1
                        elif risk == 'Critical':
                            critical_new_issue = critical_new_issue + 1
                    else:
                        nessus_obj = NessusData.objects.filter(
                            plugin_id=int(pluginid), host=host,
                            port=int(port), name=pluginname
                        ).first()
                        if nessus_obj and not nessus_obj.last_seen:
                            nessus_obj.last_seen = last_seen
                            nessus_obj.save()
                        issue = "Issue with host {}, port {} and" \
                                " pluginID {} is already exists.". \
                            format(host, port, pluginid)
                        nessus_log = NessusFileLog(
                            linked_file=file_obj,
                            issue_type="duplicate",
                            issue=issue
                        )
                        log_obj.append(nessus_log)
                        already_exist_issue = already_exist_issue + 1
                except Exception as e:
                    issue = "Issue with host {}, port {} and" \
                            " pluginID {} is not created due to error {}.". \
                        format(host, port, pluginid, e)
                    nessus_log = NessusFileLog(
                        linked_file=file_obj,
                        issue_type="undetected",
                        issue=issue
                    )
                    log_obj.append(nessus_log)
                    undetected_issues = undetected_issues + 1
                    logger.error(issue)
                if risk == 'Medium':
                    medium_risk_count = medium_risk_count + 1
                elif risk == 'Low':
                    low_risk_count = low_risk_count + 1
                elif risk == 'High':
                    high_risk_count = high_risk_count + 1
                elif risk == 'Critical':
                    critical_risk_count = critical_risk_count + 1
                total_issues = total_issues + 1
        elem.clear()
        while elem.getprevious() is not None:
            del elem.getparent()[0]
    NessusData.objects.bulk_create(obj)
    NessusFileLog.objects.bulk_create(log_obj)
    # Host.objects.bulk_create(host_obj)
    del context
    logger.info('Complete: Processing issue from xml_content.')
    process_obj.update(
        low_risk_count=low_risk_count,
        medium_risk_count=medium_risk_count,
        high_risk_count=high_risk_count,
        critical_risk_count=critical_risk_count,
        low_new_issue=low_new_issue,
        medium_new_issue=medium_new_issue,
        high_new_issue=high_new_issue,
        critical_new_issue=critical_new_issue
    )
    NessusFileRecord.objects.create(
        file=file_obj, issues_read=total_issues,
        issues_detected=detected_issues,
        issues_undetected=undetected_issues,
        duplicate_issues=already_exist_issue
    )
    issue_count = "Issues: total {}, detected {}, undetected {}," \
                  " duplicate {}.". \
        format(total_issues, detected_issues,
               undetected_issues, already_exist_issue
               )
    logger.info(issue_count)
    process_obj.update(
        xml_process_status=True
    )
    logger.info('XML processed successfully.')
    logger.info('Processing Applications and Vulnerabilities.')
    process_nessus_data(
        request=request,
        nessus_import=False,
        process_obj=process_obj
    )


def check_file_hosts(context):
    logger.info('Starting: Checking hosts in db.')
    not_found_hosts = list()
    for event, elem in context:
        host = elem.get('name')
        logger.info('Checking host:{} in db.'.format(host))
        host_type = get_host_type(host)
        if not check_host_exists(host, host_type):
            logger.info('Host:{} not found in db.'.format(host))
            not_found_hosts.append(host)
        elem.clear()
        while elem.getprevious() is not None:
            del elem.getparent()[0]
    del context
    logger.info('Complete: Checking hosts in db.')
    return not_found_hosts


@postpone
def process_nessus(input_file, request):
    nessus_file = input_file.first()
    file_path = nessus_file.file.path
    logger.info('Starting: etree.iterparse(xml_content)')
    context = etree.iterparse(
        file_path,
        events=('end',),
        tag="ReportHost"
    )
    logger.info('Complete: etree.iterparse(xml_content)')
    logger.info('Checking file hosts..')
    hosts = check_file_hosts(context)
    if hosts:
        message = "Hosts {} not found in db. File rejected.".format(hosts)
        logger.error(message)
        hosts_list = json.dumps(hosts)
        input_file.update(
            is_completed=True,
            hosts_list=hosts_list
        )
    else:
        logger.info('File accepted. Processing xml of file')
        input_file.update(is_accepted=True)
        process_nessus_file(
            file=input_file,
            request=request
        )


def upload_file(scan_id, nessus_data):
    if not NessusFile.objects.filter(file_code=scan_id).exists():
        file_obj = NessusFile.objects.create(file_code=scan_id)
    else:
        file_obj = None
    if file_obj:
        total_issues = 0
        detected_issues = 0
        undetected_issues = 0
        already_exist_issue = 0
        low_risk_count = 0
        medium_risk_count = 0
        high_risk_count = 0
        critical_risk_count = 0
        low_new_issue = 0
        medium_new_issue = 0
        high_new_issue = 0
        critical_new_issue = 0
        application_ip_data = []

        for nessus_issue in nessus_data:
            pluginid = nessus_issue.get('pluginid')
            risk = nessus_issue.get('risk')
            host = nessus_issue.get('host')
            protocol = nessus_issue.get('protocol')
            port = nessus_issue.get('port')
            banner = nessus_issue.get('banner')
            pluginname = nessus_issue.get('name')
            svcname = nessus_issue.get('svc_type')
            description = nessus_issue.get('description')
            first_identified = nessus_issue.get('first_identified')
            last_seen = nessus_issue.get('last_seen')
            synopsis = nessus_issue.get('synopsis')
            plugin_output = nessus_issue.get('plugin_output')
            solution = nessus_issue.get('solution')
            if solution and solution in ['n/a', 'N/A']:
                solution = ''
            host_type = get_host_type(host)
            user_host = check_host_exists(host, host_type)
            if user_host and not NessusData.objects.filter(plugin_id=int(pluginid),
                                                           host=host, port=int(port), name=pluginname
                                                           ).exists():
                try:
                    host_link_obj = Host.objects.get(
                        host=host
                    )
                except Host.MultipleObjectsReturned:
                    host_link_obj = Host.objects.filter(
                        host=host
                    ).first()
                except Host.DoesNotExist:
                    host_link_obj = Host.objects.create(
                        host=host,
                        user_host=user_host
                    )
                nessus_obj = NessusData.objects.create(
                    linked_file=file_obj,
                    plugin_id=int(pluginid),
                    risk=risk,
                    host=host,
                    host_link=host_link_obj,
                    protocol=protocol,
                    port=int(port),
                    banner=banner,
                    name=pluginname,
                    svc_type=svcname,
                    description=description,
                    solution=solution,
                    first_identified=first_identified,
                    synopsis=synopsis,
                    plugin_output=plugin_output,
                    user_host=user_host,
                    last_seen=last_seen
                )
                issue = "Issue with host {}, port {} and pluginID {} is added.".format(
                    nessus_obj.host, nessus_obj.port, nessus_obj.plugin_id
                )
                NessusFileLog.objects.create(
                    linked_file=file_obj, issue_type="new", issue=issue
                )
                detected_issues = detected_issues + 1
                if risk == 'Medium':
                    medium_new_issue = medium_new_issue + 1
                elif risk == 'Low':
                    low_new_issue = low_new_issue + 1
                elif risk == 'High':
                    high_new_issue = high_new_issue + 1
                elif risk == 'Critical':
                    critical_new_issue = critical_new_issue + 1
            else:
                nessus_obj = NessusData.objects.filter(
                    plugin_id=int(pluginid), host=host,
                    port=int(port), name=pluginname
                ).first()
                if nessus_obj and not nessus_obj.last_seen:
                    nessus_obj.last_seen = last_seen
                    nessus_obj.save()
                issue = "Issue with host {}, port {} and pluginID {} is already " \
                        "exists.".format(host, port, pluginid)
                NessusFileLog.objects.create(
                    linked_file=file_obj, issue_type="duplicate", issue=issue
                )
                already_exist_issue = already_exist_issue + 1
            if risk == 'Medium':
                medium_risk_count = medium_risk_count + 1
            elif risk == 'Low':
                low_risk_count = low_risk_count + 1
            elif risk == 'High':
                high_risk_count = high_risk_count + 1
            elif risk == 'Critical':
                critical_risk_count = critical_risk_count + 1
            total_issues = total_issues + 1
        process_obj = NessusFile.objects.filter(id=file_obj.id)
        process_obj.update(
            low_risk_count=low_risk_count,
            medium_risk_count=medium_risk_count,
            high_risk_count=high_risk_count,
            critical_risk_count=critical_risk_count,
            low_new_issue=low_new_issue,
            medium_new_issue=medium_new_issue,
            high_new_issue=high_new_issue,
            critical_new_issue=critical_new_issue,
            xml_process_status=True,
            is_accepted=True
        )
        NessusFileRecord.objects.create(
            file=file_obj, issues_read=total_issues, issues_detected=detected_issues,
            issues_undetected=undetected_issues, duplicate_issues=already_exist_issue
        )
        issue_count = "Issues: total {}, detected {}, undetected {}, duplicate " \
                      "{}.".format(
            total_issues, detected_issues,
            undetected_issues, already_exist_issue
        )
        logger.info(issue_count)
        # nessus_file.close()
        process_nessus_data(
            request='cron_job',
            nessus_import=True,
            process_obj=process_obj
        )
