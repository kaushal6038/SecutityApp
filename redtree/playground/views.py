# -*- coding: utf-8 -*-
from __future__ import unicode_literals
# import from django
from django.contrib import messages
from django.db.models import Count
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse
from django.core.urlresolvers import reverse, reverse_lazy
from django.db import connection
from django.db.models import Q

# celery module
from redtree.celery import app
from django_celery_beat.models import CrontabSchedule, PeriodicTask
from celery.task.control import inspect
from .forms import *
from croniter import croniter

# # core imports
import json
import uuid
import requests
import time
from .models import *
from datetime import date, datetime, timedelta
#
# # import from in house apps
from redtree_app.models import *
from utils.appliances import external_appliances, internal_appliances
from utils.scans_helpers import (
    get_ips,
    cipher_host_ip,
    get_ip_type,
    get_masscan_ips,
)
from utils.request_ip import get_request_ip
from utils.process_nessus_file import process_file
from utils.calculate_time_ago import calculate_time_ago
from utils.MasscanRestApiDescriptor import (
    MasscanRestApiDescriptor
)
from utils.RestApiScanDescriptor import (
    RestApiScanDescriptor,
    process_ciphers,
)
from utils.ApplicationScansHelper import ApplicationScanHelper
from utils.MediaUploader import MediaUploader
from utils.SshyzeScanDescriptor import SshyzeScanDescriptor
from utils.NessusScanUpdate import NessusScanUpdator
from redtree_app.tasks import (
    sslyze_cipher,
    sshyze_cipher,
    generate_application_scan,
    domain_enum,
    application_screenshot_generator,
    cloudstorage_s3_bucket_scan,
    whois_scan,
    run_scan,
    run_masscan,
    aws_rds_scan,
    refresh_aws_asset_status,
    api_gateway_scan
)
from cron_descriptor import get_description, ExpressionDescriptor


# Create your views here.


#################################
#           Playground          #
#################################
@login_required
def playground(request):


    nessus_form = NessusCronForm()
    masscan_form = MassScanCronForm()
    sslyze_form = SslyzeCronForm()
    sshyze_form = SshyzeCronForm()
    burp_form = BurpCronForm()
    dns_form = DnsCronForm()
    screenshot_form = ScreenshotCronForm()
    cloudstorage_form = CloudStorageCronForm()
    whois_form = WhoisCronForm()
    rds_form = RDSCronForm()
    asset_refresh_form = AssetRefreshCronForm()
    apigateway_form = ApiGatewayCronForm()

    client_conf_obj = ClientConfiguration.objects.first()
    all_cron_jobs = PeriodicTask.objects.all().order_by('name')

    try:
        for job in all_cron_jobs:
            if job.crontab is not None:
                cron_expression = '{} {} {} {} {}'.format(
                job.crontab.minute,
                job.crontab.hour,
                job.crontab.day_of_month,
                job.crontab.month_of_year,
                job.crontab.day_of_week
                )

                next_run = croniter(cron_expression, job.last_run_at)
                next_run_date = next_run.get_next(datetime) # Get task next run date
                job.next_run_date = next_run_date
    except PeriodicTask.DoesNotExist:
        pass

    conf_obj = Configuration.objects.first()
    external_appliance_obj = Appliances.objects.filter(
        network_type="External"
    ).first()
    internal_appliance_obj = Appliances.objects.filter(
        network_type="Internal"
    ).first()

    try:
        nessus_periodic_add_scan_task = PeriodicTask.objects.get(
            name='run-scan'
        )
    except PeriodicTask.DoesNotExist:
        nessus_periodic_add_scan_task = None

    try:
        masscan_periodic_task = PeriodicTask.objects.get(
            name='run-masscan'
        )
    except PeriodicTask.DoesNotExist:
        masscan_periodic_task = None

    try:
        sslyze_periodic_task = PeriodicTask.objects.get(
            name='sslyze-cipher'
        )
    except PeriodicTask.DoesNotExist:
        sslyze_periodic_task = None

    try:
        sshyze_periodic_task = PeriodicTask.objects.get(
            name='sshyze-cipher'
        )
    except PeriodicTask.DoesNotExist:
        sshyze_periodic_task = None

    try:
        burp_periodic_task = PeriodicTask.objects.get(
            name='burp'
        )
    except PeriodicTask.DoesNotExist:
        burp_periodic_task = None

    try:
        dnsenum_periodic_task = PeriodicTask.objects.get(
            name='domain-enum'
        )
    except PeriodicTask.DoesNotExist:
        dnsenum_periodic_task = None

    try:
        screenshot_periodic_task = PeriodicTask.objects.get(
            name='screenshot'
        )
    except PeriodicTask.DoesNotExist:
        screenshot_periodic_task = None
    try:
        cloudstorage_periodic_task = PeriodicTask.objects.get(
            name='cloudstorage'
        )
    except PeriodicTask.DoesNotExist:
        cloudstorage_periodic_task = None
    try:
        whois_periodic_task = PeriodicTask.objects.get(
            name='whois'
        )
    except PeriodicTask.DoesNotExist:
        whois_periodic_task = None
    try:
        rds_periodic_task = PeriodicTask.objects.get(
            name='rds-scan'
        )
    except PeriodicTask.DoesNotExist:
        rds_periodic_task = None
    try:
        awsasset_periodic_task = PeriodicTask.objects.get(
            name='assetrefresh'
        )
    except PeriodicTask.DoesNotExist:
        awsasset_periodic_task = None
    try:
        apigateway_periodic_task = PeriodicTask.objects.get(
            name='api-gateway'
        )
    except PeriodicTask.DoesNotExist:
        apigateway_periodic_task = None

    if nessus_periodic_add_scan_task:
        nessus_add_scan_crontab_obj = CrontabSchedule.objects.get(
            id=nessus_periodic_add_scan_task.crontab_id
        )
        nessus_cron = get_job(nessus_add_scan_crontab_obj)
        nessus_description = get_description(nessus_cron)
    else:
        nessus_description = None
        nessus_cron = None

    if masscan_periodic_task:
        masscan_crontab_obj = CrontabSchedule.objects.get(
            id=masscan_periodic_task.crontab_id
        )
        masscan_cron = get_job(masscan_crontab_obj)
        masscan_description = get_description(masscan_cron)
    else:
        masscan_description = None
        masscan_cron = None

    if sslyze_periodic_task:
        sslyze_crontab_obj = CrontabSchedule.objects.get(
            id=sslyze_periodic_task.crontab_id
        )
        sslyze_cron = get_job(sslyze_crontab_obj)
        sslyze_description = get_description(sslyze_cron)
    else:
        sslyze_description = None
        sslyze_cron = None

    if sshyze_periodic_task:
        sshyze_crontab_obj = CrontabSchedule.objects.get(
            id=sshyze_periodic_task.crontab_id
        )
        sshyze_cron = get_job(sshyze_crontab_obj)
        sshyze_description = get_description(sshyze_cron)
    else:
        sshyze_description = None
        sshyze_cron = None

    if burp_periodic_task:
        burp_crontab_obj = CrontabSchedule.objects.get(
            id=burp_periodic_task.crontab_id
        )
        burp_cron = get_job(burp_crontab_obj)
        burp_description = get_description(burp_cron)
    else:
        burp_description = None
        burp_cron = None

    if dnsenum_periodic_task:
        dnsenum_crontab_obj = CrontabSchedule.objects.get(
            id=dnsenum_periodic_task.crontab_id
        )

        dnsenum_cron = get_job(dnsenum_crontab_obj)
        dnsenum_description = get_description(dnsenum_cron)
    else:
        dnsenum_description = None
        dnsenum_cron = None

    if screenshot_periodic_task:
        screenshot_crontab_obj = CrontabSchedule.objects.get(
            id=screenshot_periodic_task.crontab_id
        )
        screenshot_cron = get_job(screenshot_crontab_obj)
        screenshot_description = get_description(screenshot_cron)
    else:
        screenshot_description = None
        screenshot_cron = None

    if cloudstorage_periodic_task:
        cloudstorage_crontab_obj = CrontabSchedule.objects.get(
            id=cloudstorage_periodic_task.crontab.id
        )

        cloudstorage_cron = get_job(cloudstorage_crontab_obj)
        cloudstorage_description = get_description(cloudstorage_cron)
    else:
        cloudstorage_description = None
        cloudstorage_cron = None

    if rds_periodic_task:
        rds_crontab_obj = CrontabSchedule.objects.get(
            id=rds_periodic_task.crontab.id
        )

        rds_cron = get_job(rds_crontab_obj)
        rds_description = get_description(rds_cron)
    else:
        rds_description = None
        rds_cron = None

    if whois_periodic_task:
        whois_crontab_obj = CrontabSchedule.objects.get(
            id=whois_periodic_task.crontab.id
        )
        whois_cron = get_job(whois_crontab_obj)
        whois_description = get_description(whois_cron)
    else:
        whois_description = None
        whois_cron = None

    if awsasset_periodic_task:
        awsasset_crontab_obj = CrontabSchedule.objects.get(
            id=awsasset_periodic_task.crontab.id
        )

        awsasset_cron = get_job(awsasset_crontab_obj)
        awsasset_description = get_description(awsasset_cron)
    else:
        awsasset_description = None
        awsasset_cron = None
    if apigateway_periodic_task:
        apigateway_crontab_obj = CrontabSchedule.objects.get(
            id=apigateway_periodic_task.crontab.id
        )

        apigateway_cron = get_job(apigateway_crontab_obj)
        apigateway_description = get_description(apigateway_cron)
    else:
        apigateway_description = None
        apigateway_cron = None

    try:
        inspect_task = app.control.inspect()
    except Exception as e:
        inspect_task = None

    register_task = inspect_task.registered()
    active_task = inspect_task.active()
    task_stats = inspect_task.stats()

    if register_task:
        messages.success(request, 'Celery is Working')
    else:
        messages.error(request, 'Celery is Not Working')

    if request.method == "POST":
        form_type = request.POST.get('form-type')
        if form_type == "nessus_form":
            nessus_form = NessusCronForm(request.POST)

            if nessus_form.is_valid():
                details = nessus_form.cleaned_data
                cron_details = details.get('nes_job')
                if croniter.is_valid(cron_details):
                    cron_list = cron_details.split()
                    if len(cron_list) == 5:
                        nessus_add_scan_crontab_obj = CrontabSchedule.objects.get(
                            id=nessus_periodic_add_scan_task.crontab_id
                        )
                        save_job(nessus_add_scan_crontab_obj, cron_list)

                        messages.add_message(request, messages.SUCCESS, 'Schedule updated successfully')
                    else:
                        messages.add_message(request, messages.ERROR, 'Invalid Cron Syntax')
                else:
                    messages.add_message(request, messages.ERROR, 'Invalid Cron Syntax')

        elif form_type == "masscan_form":
            masscan_form = MassScanCronForm(request.POST)
            if masscan_form.is_valid():
                details = masscan_form.cleaned_data
                cron_details = details.get('masscan_job')
                if croniter.is_valid(cron_details):
                    cron_list = cron_details.split()
                    if len(cron_list) == 5:
                        masscan_crontab_obj = CrontabSchedule.objects.get(
                            id=masscan_periodic_task.crontab_id
                        )
                        save_job(masscan_crontab_obj, cron_list)

                        messages.add_message(request, messages.SUCCESS, 'Schedule updated successfully')
                    else:
                        messages.add_message(request, messages.ERROR, 'Invalid Cron Syntax')
                else:
                    messages.add_message(request, messages.ERROR, 'Invalid Cron Syntax')

        elif form_type == "sslyze_form":
            sslyze_form = SslyzeCronForm(request.POST)
            if sslyze_form.is_valid():
                details = sslyze_form.cleaned_data
                cron_details = details.get('sslyze_job')
                if croniter.is_valid(cron_details):
                    cron_list = cron_details.split()
                    if len(cron_list) == 5:
                        sslyze_crontab_obj = CrontabSchedule.objects.get(
                            id=sslyze_periodic_task.crontab_id
                        )
                        save_job(sslyze_crontab_obj, cron_list)

                        messages.add_message(request, messages.SUCCESS, 'Schedule updated successfully')
                    else:
                        messages.add_message(request, messages.ERROR, 'Invalid Cron Syntax')
                else:
                    messages.add_message(request, messages.ERROR, 'Invalid Cron Syntax')

        elif form_type == "sshyze_form":
            sshyze_form = SshyzeCronForm(request.POST)
            if sshyze_form.is_valid():
                details = sshyze_form.cleaned_data
                cron_details = details.get('sshyze_job')
                if croniter.is_valid(cron_details):
                    cron_list = cron_details.split()
                    if len(cron_list) == 5:
                        sshyze_crontab_obj = CrontabSchedule.objects.get(
                            id=sshyze_periodic_task.crontab_id
                        )
                        save_job(sshyze_crontab_obj, cron_list)

                        messages.add_message(request, messages.SUCCESS, 'Schedule updated successfully')
                    else:
                        messages.add_message(request, messages.ERROR, 'Invalid Cron Syntax')
                else:
                    messages.add_message(request, messages.ERROR, 'Invalid Cron Syntax')

        elif form_type == "burp_form":
            burp_form = BurpCronForm(request.POST)
            if burp_form.is_valid():
                details = burp_form.cleaned_data
                cron_details = details.get('burp_job')
                if croniter.is_valid(cron_details):
                    cron_list = cron_details.split()
                    if len(cron_list) == 5:
                        burp_crontab_obj = CrontabSchedule.objects.get(
                            id=burp_periodic_task.crontab_id
                        )
                        save_job(burp_crontab_obj, cron_list)

                        messages.add_message(request, messages.SUCCESS, 'Schedule updated successfully')
                    else:
                        messages.add_message(request, messages.ERROR, 'Invalid Cron Syntax')
                else:
                    messages.add_message(request, messages.ERROR, 'Invalid Cron Syntax')

        elif form_type == "dns_form":
            dns_form = DnsCronForm(request.POST)
            if dns_form.is_valid():
                details = dns_form.cleaned_data
                cron_details = details.get('dnsenum_job')
                if croniter.is_valid(cron_details):
                    cron_list = cron_details.split()
                    if len(cron_list) == 5:
                        dnsenum_crontab_obj = CrontabSchedule.objects.get(
                            id=dnsenum_periodic_task.crontab_id
                        )
                        save_job(dnsenum_crontab_obj, cron_list)

                        messages.add_message(request, messages.SUCCESS, 'Schedule updated successfully')
                    else:
                        messages.add_message(request, messages.ERROR, 'Invalid Cron Syntax')
                else:
                    messages.add_message(request, messages.ERROR, 'Invalid Cron Syntax')

        elif form_type == "screenshot_form":
            screenshot_form = ScreenshotCronForm(request.POST)
            if screenshot_form.is_valid():
                details = screenshot_form.cleaned_data
                cron_details = details.get('screenshot_job')
                if croniter.is_valid(cron_details):
                    cron_list = cron_details.split()
                    if len(cron_list) == 5:
                        screenshot_crontab_obj = CrontabSchedule.objects.get(
                            id=screenshot_periodic_task.crontab_id
                        )
                        save_job(screenshot_crontab_obj, cron_list)

                        messages.add_message(request, messages.SUCCESS, 'Schedule updated successfully')
                    else:
                        messages.add_message(request, messages.ERROR, 'Invalid Cron Syntax')
                else:
                    messages.add_message(request, messages.ERROR, 'Invalid Cron Syntax')

        elif form_type == "cloudstorage_form":
            cloudstorage_form = CloudStorageCronForm(request.POST)
            if cloudstorage_form.is_valid():
                details = cloudstorage_form.cleaned_data
                cron_details = details.get('cloudstorage_job')
                if croniter.is_valid(cron_details):
                    cron_list = cron_details.split()
                    if len(cron_list) == 5:
                        cloudstorage_crontab_obj = CrontabSchedule.objects.get(
                            id=cloudstorage_periodic_task.crontab.id
                        )
                        save_job(cloudstorage_crontab_obj, cron_list)

                        messages.add_message(request, messages.SUCCESS, 'Schedule updated successfully')
                    else:
                        messages.add_message(request, messages.ERROR, 'Invalid Cron Syntax')
                else:
                    messages.add_message(request, messages.ERROR, 'Invalid Cron Syntax')

        elif form_type == "whois_form":
            whois_form = WhoisCronForm(request.POST)
            if whois_form.is_valid():
                details = whois_form.cleaned_data
                cron_details = details.get('whois_job')
                if croniter.is_valid(cron_details):
                    cron_list = cron_details.split()
                    if len(cron_list) == 5:
                        whois_crontab_obj = CrontabSchedule.objects.get(
                            id=whois_periodic_task.crontab.id
                        )
                        save_job(whois_crontab_obj, cron_list)

                        messages.add_message(request, messages.SUCCESS, 'Schedule updated successfully')
                    else:
                        messages.add_message(request, messages.ERROR, 'Invalid Cron Syntax')
                else:
                    messages.add_message(request, messages.ERROR, 'Invalid Cron Syntax')



        elif form_type == "rds_form":
            rds_form = RDSCronForm(request.POST)
            if rds_form.is_valid():
                details = rds_form.cleaned_data
                cron_details = details.get('rds_job')
                if croniter.is_valid(cron_details):
                    cron_list = cron_details.split()
                    if len(cron_list) == 5:
                        rds_crontab_obj = CrontabSchedule.objects.get(
                            id=rds_periodic_task.crontab.id
                        )
                        save_job(rds_crontab_obj, cron_list)

                        messages.add_message(request, messages.SUCCESS, 'Schedule updated successfully')
                    else:
                        messages.add_message(request, messages.ERROR, 'Invalid Cron Syntax')
                else:
                    messages.add_message(request, messages.ERROR, 'Invalid Cron Syntax')


        elif form_type == "asset_refresh_form":
            asset_refresh_form = AssetRefreshCronForm(request.POST)
            if asset_refresh_form.is_valid():
                details = asset_refresh_form.cleaned_data
                cron_details = details.get('asset_refresh_job')
                if croniter.is_valid(cron_details):
                    cron_list = cron_details.split()
                    if len(cron_list) == 5:
                        awsasset_crontab_obj = CrontabSchedule.objects.get(
                            id=awsasset_periodic_task.crontab.id
                        )
                        save_job(awsasset_crontab_obj, cron_list)

                        messages.add_message(request, messages.SUCCESS, 'Schedule updated successfully')
                    else:
                        messages.add_message(request, messages.ERROR, 'Invalid Cron Syntax')
                else:
                    messages.add_message(request, messages.ERROR, 'Invalid Cron Syntax')


        elif form_type == "apigateway_form":
            apigateway_form = ApiGatewayCronForm(request.POST)
            if apigateway_form.is_valid():
                details = apigateway_form.cleaned_data
                cron_details = details.get('apigateway_job')
                if croniter.is_valid(cron_details):
                    cron_list = cron_details.split()
                    if len(cron_list) == 5:
                        apigateway_crontab_obj = CrontabSchedule.objects.get(
                            id=awsasset_periodic_task.crontab.id
                        )
                        save_job(apigateway_crontab_obj, cron_list)

                        messages.add_message(request, messages.SUCCESS, 'Schedule updated successfully')
                    else:
                        messages.add_message(request, messages.ERROR, 'Invalid Cron Syntax')
                else:
                    messages.add_message(request, messages.ERROR, 'Invalid Cron Syntax')



        nessus_add_external_scan = request.POST.get(
            "nessus_add_external_scan"
        )
        nessus_add_internal_scan = request.POST.get(
            "nessus_add_internal_scan"
        )

        masscan_external_scan = request.POST.get("masscan_external_scan")
        masscan_internal_scan = request.POST.get("masscan_internal_scan")

        sslyze_external_scan = request.POST.get("sslyze_external_scan")
        sslyze_internal_scan = request.POST.get("sslyze_internal_scan")

        sshyze_external_scan = request.POST.get("sshyze_external_scan")
        sshyze_internal_scan = request.POST.get("sshyze_internal_scan")

        burp_external_scan = request.POST.get("burp_external_scan")
        burp_internal_scan = request.POST.get("burp_internal_scan")

        dnsenum_external_scan = request.POST.get("dnsenum_external_scan")
        dnsenum_internal_scan = request.POST.get("dnsenum_internal_scan")

        screenshot_external_scan = request.POST.get("screenshot_external_scan")
        screenshot_internal_scan = request.POST.get("screenshot_internal_scan")

        cloudstorage_external_scan = request.POST.get("cloudstorage_external_scan")

        ip_whois_scan = request.POST.get("whois_scan")

        rds_scan = request.POST.get("rds_scan")

        aws_asset_scan = request.POST.get("aws_asset_scan")

        api_scan = request.POST.get("api_scan")  # Check if APIGateway Button is Clicked

        if conf_obj and conf_obj.scanning_status:
            if nessus_add_external_scan:
                if external_appliance_obj:
                    run_scan.delay(scan_type='External')
                    messages.success(request, 'External Scan Registered for Nessus.')
                else:
                    messages.error(request, 'Appliance is not setup for external scan.')

            elif nessus_add_internal_scan:
                if internal_appliance_obj:
                    run_scan.delay(scan_type='Internal')
                    messages.success(request, 'Internal Scan Registered for Nessus.')
                else:
                    messages.error(request, 'Appliance is not setup for internal scan.')

            elif masscan_external_scan:
                if external_appliance_obj:
                    run_masscan.delay(scan_type='External')
                    messages.success(request, 'External Scan Registered for Masscan.')
                else:
                    messages.error(request, 'Appliance is not setup for external scan.')

            elif masscan_internal_scan:
                if internal_appliance_obj:
                    run_masscan.delay(scan_type='Internal')
                    messages.success(request, 'Internal Scan Registered for Masscan.')
                else:
                    messages.error(request, 'Appliance is not setup for internal scan.')

            elif sslyze_external_scan:
                if external_appliance_obj:
                    sslyze_cipher.delay(scan_type='External')
                    messages.success(request, 'External Scan Registered for Sslyze.')
                else:
                    messages.error(request, 'Appliance is not setup for external scan.')

            elif sslyze_internal_scan:
                if internal_appliance_obj:
                    sslyze_cipher.delay(scan_type='Internal')
                    messages.success(request, 'Internal Scan Registered for Sslyze.')
                else:
                    messages.error(request, 'Appliance is not setup for internal scan.')

            elif sshyze_external_scan:
                if external_appliance_obj:
                    sshyze_cipher.delay(scan_type='External')
                    messages.success(request, 'External Scan Registered for Sshyze.')
                else:
                    messages.error(request, 'Appliance is not setup for external scan.')

            elif sshyze_internal_scan:
                if internal_appliance_obj:
                    sshyze_cipher.delay(scan_type='Internal')
                    messages.success(request, 'Internal Scan Registered for Sshyze.')
                else:
                    messages.error(request, 'Appliance is not setup for internal scan.')

            elif burp_external_scan:
                if external_appliance_obj:
                    generate_application_scan.delay(scan_type='External')
                    messages.success(request, 'External Scan Registered for Burp.')
                else:
                    messages.error(request, 'Appliance is not setup for external scan.')

            elif burp_internal_scan:
                if internal_appliance_obj:
                    generate_application_scan.delay(scan_type='Internal')
                    messages.success(request, 'Internal Scan Registered for Burp.')
                else:
                    messages.error(request, 'Appliance is not setup for internal scan.')

            elif dnsenum_external_scan:
                if external_appliance_obj:
                    domain_enum.delay(scan_type='External')
                    messages.success(request, 'External Scan Registered for DnsEnum.')
                else:
                    messages.error(request, 'Appliance is not setup for external scan.')

            elif dnsenum_internal_scan:
                if internal_appliance_obj:
                    domain_enum.delay(scan_type='Internal')
                    messages.success(request, 'Internal Scan Registered for DnsEnum.')
                else:
                    messages.error(request, 'Appliance is not setup for internal scan.')

            elif screenshot_external_scan:
                if external_appliance_obj:
                    application_screenshot_generator.delay(scan_type='External')
                    messages.success(request, 'External Scan Registered for Screenshot.')
                else:
                    messages.error(request, 'Appliance is not setup for external scan.')

            elif screenshot_internal_scan:
                if internal_appliance_obj:
                    application_screenshot_generator.delay(scan_type='Internal')
                    messages.success(request, 'Internal Scan Registered for Screenshot.')
                else:
                    messages.error(request, 'Appliance is not setup for internal scan.')

            elif cloudstorage_external_scan:
                if external_appliance_obj:
                    cloudstorage_s3_bucket_scan.delay()
                    messages.success(request, 'Scan Registered for Cloudstorage.')
                else:
                    messages.error(request, 'Appliance is not setup.')

            elif ip_whois_scan:
                whois_scan.delay()
                messages.success(request, 'Whois scan registered successfully.')

            elif rds_scan:
                if external_appliance_obj:
                    aws_rds_scan.delay()
                    messages.success(request, 'Assets Refresh Started.')
                else:
                    messages.error(request, 'No AWS Assets.')

            elif aws_asset_scan:
                if external_appliance_obj:
                    refresh_aws_asset_status.delay()
                    messages.success(request, 'Assets Refresh Started.')
                else:
                    messages.error(request, 'No AWS Assets.')

            elif api_scan:
                if external_appliance_obj:
                    api_gateway_scan.delay()
                    messages.success(request, 'Assets Refresh Started.')
                else:
                    messages.error(request, 'No AWS Assets.')


        else:
            messages.error(
                request,
                "Scan can't be initiated, because scanning is disabled.."
            )
        return HttpResponseRedirect(request.path_info)

    context = {

        'nessus_description': nessus_description,
        'nessus_cron': nessus_cron,
        'nessus_form': nessus_form,
        'masscan_description': masscan_description,
        'masscan_cron': masscan_cron,
        'masscan_form': masscan_form,
        'sslyze_description': sslyze_description,
        'sslyze_cron': sslyze_cron,
        'sslyze_form': sslyze_form,
        'sshyze_description': sshyze_description,
        'sshyze_cron': sshyze_cron,
        'sshyze_form': sshyze_form,
        'burp_description': burp_description,
        'burp_cron': burp_cron,
        'burp_form': burp_form,
        'dnsenum_description': dnsenum_description,
        'dnsenum_cron': dnsenum_cron,
        'dns_form': dns_form,
        'screenshot_description': screenshot_description,
        'screenshot_cron': screenshot_cron,
        'screenshot_form': screenshot_form,
        'cloudstorage_description': cloudstorage_description,
        'cloudstorage_cron': cloudstorage_cron,
        'cloudstorage_form': cloudstorage_form,
        'whois_description': whois_description,
        'whois_cron': whois_cron,
        'whois_form': whois_form,
        'rds_description': rds_description,
        'rds_cron': rds_cron,
        'rds_form': rds_form,
        'awsasset_description': awsasset_description,
        'awsasset_cron': awsasset_cron,
        'apigateway_description': apigateway_description,
        'apigateway_cron': apigateway_cron,
        'apigateway_form': apigateway_form,
        'asset_refresh_form': asset_refresh_form,
        'all_cron': all_cron_jobs

    }
    return render(
        request,
        "redtree_app/playground.html",
        context
    )


def save_job(cron_obj, expression):
    """

    :param cron_obj: DB Object
    :param expression: Crontab Expression
    :return:
    """
    cron_obj.minute = expression[0]
    cron_obj.hour = expression[1]
    cron_obj.day_of_month = expression[2]
    cron_obj.month_of_year = expression[3]
    cron_obj.day_of_week = expression[4]

    cron_obj.save()


def get_job(crontab_obj):
    """

    :param crontab_obj: DB Object
    :return: Crontab Expression
    """
    cron_job = '{} {} {} {} {}'.format(
        crontab_obj.minute,
        crontab_obj.hour,
        crontab_obj.day_of_month,
        crontab_obj.month_of_year,
        crontab_obj.day_of_week
    )
    return cron_job
