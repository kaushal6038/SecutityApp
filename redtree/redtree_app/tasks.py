# -*- coding: utf-8 -*-
from __future__ import absolute_import, unicode_literals
import pytz
import ipaddress
import requests
import datetime
import logging
import shutil
import pdfkit
from celery import task
import time
from redtree_app.models import *
from playground.models import *
from django.db.models.functions import Cast
from django.db.models import FloatField, IntegerField
from django.utils import timezone
from datetime import date, datetime as dt, timedelta
from redtree_app.alerts import send_host_mail, send_mail
from django.core.mail import EmailMessage
from django.db.models import Count, Q, Sum

from redtree_app.ip_validator import *

# Local imports from playground
from playground.views import process_ciphers

# Local imports from utils
from utils.NessusScanAddDescriptor import (
	nessus_scan,
	internal_nessus_scan,
	external_nessus_scan,
)
from utils.MasscanRestApiDescriptor import (
    MasscanRestApiDescriptor,
    update_pending_masscan
)
from utils.RestApiScanDescriptor import (
    RestApiScanDescriptor,
    process_ciphers,
    internal_scan_cipher,
    external_scan_cipher,
    update_pending_sslyze
)

from utils.SshyzeScanDescriptor import (
	SshyzeScanDescriptor,
	process_sshyze_ciphers,
	external_sshyze_cipher,
	internal_sshyze_cipher
)

from utils.AwsDescriptor import (
	generate_aws_scan,
	check_aws_asset_token_status,
)

from utils.AwsAssetRefresh import (
	refresh_aws_asset,
)

from utils.AwsRdsScan import (
	rds_scan,
)

from utils.scans_helpers import cipher_host_ip, get_ips, get_masscan_ips
from utils.appliances import external_appliances, internal_appliances
from utils.process_nessus_file import process_file
from utils.ApplicationScansHelper import (
	application_scan,
	internal_application_scan,
	external_application_scan,
	update_pending_application_scans,
)
from utils.NessusScanUpdate import NessusScanUpdator
from utils.helpers import (
    get_appliance
)
from utils.DnsEnumHelper import (
	process_domains,
	process_external_domains,
	process_internal_domains,
	prior_domain_scan
)
from utils.ApplicationScreenshotScansHelper import (
	application_screenshot_generator_scan,
	internal_application_screenshot_generator_scan,
	external_application_screenshot_generator_scan,
)
from utils.CloudstorageScanDescriptor import (
	cloudstorage_bucket_scan,
)
from utils.WhoisScanHelper import (
	ips_whois_scan
)

from utils.APIScan import api_scan
from django.template.loader import render_to_string
from django_celery_beat.models import PeriodicTask


from redtree_app.views import get_report_data
from django.conf import settings
from PyPDF2 import PdfFileWriter, PdfFileReader
from django.template.loader import get_template
from django.http import HttpResponse




def update_next_scan(client_conf_obj):
	last_run = client_conf_obj.last_scan
	today_date = timezone.now()
	scan_frequency = client_conf_obj.scan_frequency
	last_run_date = last_run + timedelta(days=scan_frequency)
	next_run_date = client_conf_obj.next_scan_date
	if last_run_date == today_date or next_run_date <= today_date:
		date = timezone.now() + timedelta(days=scan_frequency)
		day = date.day
		client_conf_obj.next_scan = day
		client_conf_obj.next_scan_date = date
		client_conf_obj.last_scan = timezone.now()
		client_conf_obj.save()


@task(bind=True, priority=5)
def run_scan(self, *args, **kwargs):
	task_id = self.request.id
	conf_obj = Configuration.objects.first()
	client_conf_obj = ClientConfiguration.objects.first()
	if conf_obj and client_conf_obj:
		update_next_scan(client_conf_obj)
		if conf_obj.scanning_status:
			if kwargs.get('scan_type') and kwargs.get('scan_type') == 'External':
				external_nessus_scan(task_id)
			elif kwargs.get('scan_type') and kwargs.get('scan_type') == 'Internal':
				internal_nessus_scan(task_id)
			else:
				nessus_scan(task_id)
	else:
		error_message = "Nessus Scan can't be initiated, because scanning is disabled.."
		AppNotification.objects.create(
			issue_type='cron_error', 
			notification_message=error_message
		)


@task(priority=5)
def update_nessus_status():
	nessus_scan_update = NessusScanUpdator()
	nessus_scan_update.update_nessus_scan_status()


@task(bind=True, priority=5)
def run_masscan(self, *args, **kwargs):
	task_id = self.request.id
	conf_obj = Configuration.objects.first()
	client_conf_obj = ClientConfiguration.objects.first()
	if conf_obj and client_conf_obj:
	 	update_next_scan(client_conf_obj)
	 	if conf_obj.scanning_status:
			ips = get_masscan_ips()
			if kwargs.get('scan_type') and kwargs.get('scan_type') == 'External':
				appliance_objs = Appliances.objects.filter(
					network_type="External"
				)
				if not ips['external_ips']:
					ips = None
			elif kwargs.get('scan_type') and kwargs.get('scan_type') == 'Internal':
				appliance_objs = Appliances.objects.filter(
					network_type="Internal"
				)
				if not ips['internal_ips']:
					ips = None
			else:
				appliance_objs = Appliances.objects.all()
				if not (ips.get('internal_ips') or ips.get('external_ips')):
					ips = None
			if client_conf_obj and appliance_objs and ips:
					scan_masscan_cron(
						client_conf_obj,
						appliance_objs,
						ips,
						task_id
					)
	ips = get_masscan_ips()
	update_pending_masscan(ips)


def scan_masscan_cron(client_conf_obj, appliance_objs, ips, task_id):
	new_vulnerabilities_created = 0
	for appliance_obj in appliance_objs:
		try:
			appliance_settings = appliance_obj.appliance_setting
		except Exception as e:
			appliance_settings = None
		if appliance_settings and appliance_settings.\
				masscan_maximum_hosts_per_scan and appliance_settings.masscan_ports:
			masscan_address = appliance_settings.masscan_ip_address
			max_host_per_scan = appliance_settings.masscan_maximum_hosts_per_scan
			masscan_ports = [appliance_settings.masscan_ports]
			if appliance_obj.network_type == "Internal":
				ip_list = ips.get('internal_ips')
				host_name_list = ips.get('internal_host_name_list')
			elif appliance_obj.network_type == "External":
				ip_list = ips.get('external_ips')
				host_name_list = ips.get('external_host_name_list')
			if ip_list:
				ip_sec = 1
				temp_ips = list()
				for ip_sec1 in range(0, len(ip_list), int(max_host_per_scan)):
					for ip_sec2 in range(ip_sec1, int(max_host_per_scan) * ip_sec):
						if ip_sec2 + 1 <= len(ip_list):
							temp_ips.append(ip_list[ip_sec2])
					masscan_descriptor = MasscanRestApiDescriptor(
						appliance_obj,
						temp_ips,
						masscan_ports,
						masscan_address,
						host_name_list,
						task_id
					)
					name_request = masscan_descriptor.create_masscan()
					if name_request:
						new_vulnerabilities = name_request.\
							get('new_vulnerabilities_created')
					else:
						new_vulnerabilities = None
					if new_vulnerabilities:
						new_vulnerabilities_created = new_vulnerabilities_created\
							+ new_vulnerabilities
					temp_ips = []
					ip_sec += 1
	if new_vulnerabilities_created:
		if new_vulnerabilities_created == 1:
			activity_text = "Asynchronous port scan complete, {} new port "\
				"found.".format(new_vulnerabilities_created)
		else:
			activity_text = "Asynchronous port scan complete, {} new ports "\
				"found.".format(new_vulnerabilities_created)
	else:
		activity_text = "Asynchronous port scan complete, no new ports found."
	ActivityLog.objects.create(activity=activity_text)


@task(bind=True, priority=5)
def sslyze_cipher(self, *args, **kwargs):
	task_id = self.request.id
	conf_obj = Configuration.objects.first()
	client_conf_obj = ClientConfiguration.objects.first()
	if conf_obj and client_conf_obj:
		update_next_scan(client_conf_obj)
		if not NessusData.objects.filter(plugin_id=56984).exists():
			LogMicroServiceSslyze.objects.create(
				status="Completed",
				message="No data for scanning",
				is_completed=True,
				modified=timezone.now(),
				task_id=task_id
			)
		else:
			if conf_obj.scanning_status:
				if kwargs.get('scan_type') and kwargs.get('scan_type') == 'External':
					external_scan_cipher(task_id)
				elif kwargs.get('scan_type') and kwargs.get('scan_type') == 'Internal':
					internal_scan_cipher(task_id)
				else:
					process_ciphers(task_id)
			else:
				error_message = "Sslyze Scan can't be initiated, because scanning is disabled.."
				AppNotification.objects.create(
					issue_type='cron_error', 
					notification_message=error_message
				)
	else:
		error_message = "Sslyze Scan can't be initiated, because configuration is not setup properly.."
		AppNotification.objects.create(
			issue_type='cron_error', 
			notification_message=error_message
		)
	update_pending_sslyze()


@task(bind=True, priority=5)
def sshyze_cipher(self, *args, **kwargs):
	task_id = self.request.id
	conf_obj = Configuration.objects.first()
	client_conf_obj = ClientConfiguration.objects.first()
	if conf_obj and client_conf_obj:
		update_next_scan(client_conf_obj)
		if not NessusData.objects.filter(plugin_id=10881).exists():
			LogMicroServiceSshyze.objects.create(
				status="Completed",
				message="No data for scanning",
				is_completed=True,
				modified=timezone.now(),
				task_id=task_id
			)
			return
		else:
			if conf_obj.scanning_status:
				if kwargs.get('scan_type') and kwargs.get('scan_type') == 'External':
					external_sshyze_cipher(task_id)
				elif kwargs.get('scan_type') and kwargs.get('scan_type') == 'Internal':
					internal_sshyze_cipher(task_id)
				else:
					process_sshyze_ciphers(task_id)
			else:
				error_message = "Sshyze Scan can't be initiated, because scanning is disabled.."
				AppNotification.objects.create(
					issue_type='cron_error', 
					notification_message=error_message
				)
	else:
		error_message = "Sshyze Scan can't be initiated, because configuration is not setup properly.."
		AppNotification.objects.create(
			issue_type='cron_error', 
			notification_message=error_message
		)


@task(bind=True, priority=5)
def domain_enum(self, *args, **kwargs):
	task_id = self.request.id
	conf_obj = Configuration.objects.first()
	client_conf_obj = ClientConfiguration.objects.first()
	if conf_obj and client_conf_obj:
		update_next_scan(client_conf_obj)
		if conf_obj.scanning_status:
			if kwargs.get('scan_type') and kwargs.get('scan_type') == 'External':
				process_external_domains(task_id)
			elif kwargs.get('scan_type') and kwargs.get('scan_type') == 'Internal':
				process_internal_domains(task_id)
			elif kwargs.get('scan_type') and kwargs.get('scan_type') == 'Prior':
				domain_id = kwargs.get('target_id')
				prior_domain_scan(task_id, domain_id)
			else:
				process_domains(task_id)
		else:
			error_message = "Domain enum can't be initiated, because scanning is disabled.."
			AppNotification.objects.create(
				issue_type='cron_error', 
				notification_message=error_message
			)
	else:
		error_message = "Domain enum can't be initiated, because configuration is not setup properly.."
		AppNotification.objects.create(
			issue_type='cron_error', 
			notification_message=error_message
		)


@task(bind=True, priority=1)
def generate_application_scan(self, *args, **kwargs):
	task_id = self.request.id
	conf_obj = Configuration.objects.first()
	client_conf_obj = ClientConfiguration.objects.first()
	if conf_obj and client_conf_obj:
		update_next_scan(client_conf_obj)
		if conf_obj.scanning_status:
			if kwargs.get('scan_type') and kwargs.get('scan_type') == 'External':
				Applications.objects.filter(
					network_type="External",
					scanning_enabled=True
				).update(burp_scanning=False) # Reset Burp Status for Internal Applications
				external_application_scan(task_id)
			elif kwargs.get('scan_type') and kwargs.get('scan_type') == 'Internal':
				Applications.objects.filter(
					network_type="Internal",
					scanning_enabled=True
				).update(burp_scanning=False) # Reset Burp Status for Internal Applications
				internal_application_scan(task_id)
			else:
				Applications.objects.filter(
					scanning_enabled=True
				).update(burp_scanning=False) # Reset Burp Status for all Applications
				application_scan(task_id) # Triggered by Crontab
		else:
			error_message = "Application Scan can't be initiated, because scanning is disabled.."
			AppNotification.objects.create(
				issue_type='cron_error', 
				notification_message=error_message
			)
	else:
		error_message = "Application Scan can't be initiated, because configuration is not setup properly.."
		AppNotification.objects.create(
			issue_type='cron_error', 
			notification_message=error_message
		)
	update_pending_application_scans()


@task(priority=10)
def pl_historical_data():
	'''
		Calculating record for storing active_ips and open_ports for
		graphical data on dashboard in PL
	'''
	print "*** chart data task started ***"
	vulnerability_obj = Vulnerability.objects.all()
	active_ips = vulnerability_obj.values_list(
		'host_ip', flat=True
	).distinct().count()
	open_ports = vulnerability_obj.filter(
		title__icontains="Open TCP Port"
	).count()
	if HistoricalData.objects.filter(
			created__date=date.today()
			).exists():
		hist_data_obj = HistoricalData.objects.filter(
			created__date=date.today()
		).first()
		hist_data_obj.active_ips = active_ips
		hist_data_obj.open_ports = open_ports
		hist_data_obj.save()
	else:
		HistoricalData.objects.create(
			active_ips=active_ips,
			open_ports=open_ports
		)

	'''
		Calculating record for storing vulnerabilities for graphical
		data on dashboard in PL
	'''
	vulnerability_obj = Vulnerability.objects.all()
	critical_risk = vulnerability_obj.filter(risk="Critical").count()
	high_risk = vulnerability_obj.filter(risk="High").count()
	medium_risk = vulnerability_obj.filter(risk="Medium").count()
	low_risk = vulnerability_obj.filter(risk="Low").count()
	if RiskHistoricalData.objects.filter(
			created__date=date.today()).exists():
		risk_factor_obj = RiskHistoricalData.objects.filter(
			created__date=date.today()
		).first()
		risk_factor_obj.critical_risk = critical_risk
		risk_factor_obj.high_risk = high_risk
		risk_factor_obj.medium_risk = medium_risk
		risk_factor_obj.low_risk = low_risk
		risk_factor_obj.save()
	else:
		RiskHistoricalData.objects.create(
			critical_risk=critical_risk,
			high_risk=high_risk,
			medium_risk=medium_risk,
			low_risk=low_risk
		)
	risks_by_count = ApplicationVulnerability.objects.all().values('risk').annotate(
		counts=Count('risk')
	)
	risks = {
		'Critical': 0,
		'High': 0,
		'Medium': 0,
		'Low': 0,
	}
	for risks_count in risks_by_count:
		risks[risks_count['risk']] += risks_count['counts']
	application_hist_record = ApplicationVulnerabilityChart.objects.filter(
		created__date=date.today()
	)
	if application_hist_record:
		application_hist_record.update(
			high_risk=risks['High'],
			medium_risk=risks['Medium'],
			low_risk=risks['Low'],
			critical_risk=risks['Critical'],
		)
	else:
		ApplicationVulnerabilityChart.objects.create(
			high_risk=risks['High'],
			medium_risk=risks['Medium'],
			low_risk=risks['Low'],
			critical_risk=risks['Critical'],
		)

	cipher_data = Ciphers.objects.distinct('host','port')
	high_strength = 0
	medium_strength = 0
	low_strength = 0
	for cipher in cipher_data:
		proto = list(set(Ciphers.objects.filter(
			host=cipher.host,
			port=cipher.port,
			key_size__isnull=False
		).distinct('protocol').values_list('protocol', flat=True)))
		status = False
		for protocol in ['SSLv2','SSLv3']:
			if protocol in proto:
				low_strength+=1
				status = True
				break
		if not status:
			if 'TLSv1' in proto:
				medium_strength+=1
				status = True
			if not status:
				for protocol in ['TLSv1_1','TLSv1_2','TLSv1_3']:
					if protocol in proto:
						high_strength+=1
						status = True
						break

	encryption_record = EncryptionChart.objects.filter(
		created__date=date.today()
	)
	if encryption_record:
		encryption_record.update(
			services=cipher_data.count(),
			medium_strength=medium_strength,
			low_strength=low_strength,
			high_strength=high_strength,
		)
	else:
		EncryptionChart.objects.create(
			services=cipher_data.count(),
			medium_strength=medium_strength,
			low_strength=low_strength,
			high_strength=high_strength,
		)

	print "*****chart data feteched successfully******"


@task(priority=10)
def get_aws_assets(*args, **kwargs):
	conf_obj = Configuration.objects.first()
	if conf_obj and conf_obj.scanning_status:
		generate_aws_scan()


@task(priority=10)
def app_screenshot_generator(*args, **kwargs):
	app_id = kwargs.get("id")
	app_obj = Applications.objects.get(id=app_id)
	network_type = app_obj.network_type
	application_url = app_obj.application_url
	client_obj = ClientConfiguration.objects.first()
	appliances_obj = get_appliance(network_type)
	if client_obj:
		update_next_scan(client_obj)
		if not app_obj.screenshot_filename:
			appliance_settings_obj = appliances_obj.appliance_setting
			if appliances_obj and appliances_obj.appliance_ip:
				data = {'url': application_url}
				headers = {'Content-Type': 'application/json'}
				try:
					webscreenshot_url = appliance_settings_obj.webscreenshot_app_url
					auth_username = appliance_settings_obj.auth_username
					auth_password = appliance_settings_obj.auth_password
					request = requests.post(
						webscreenshot_url,
						json=data,
						auth=(auth_username, auth_password),
						headers=headers
					)
					result = request.json()
					if result.get("success") and result.get("image"):
						# To check if screenshot title overwrite is allowed
						if not app_obj.screenshot_title:
							filename = result.get("filename")
							image = result.get("image")
							url_title = result.get("url_title")
							download_dir = os.path.join(
								settings.MEDIA_ROOT,
								'screenshots'
							)
							if not os.path.exists(download_dir):
								os.mkdir(download_dir)
							path = os.path.join(download_dir, filename)
							fh = open(path, "wb")
							fh.write(image.decode('base64'))
							fh.close()
							app_obj.screenshot_filename = filename
							
							app_obj.application_title = url_title
							app_obj.screenshot_path = os.path.join(
								"/media/screenshots/",
								filename
							)
							base_path = str(settings.BASE_DIR)
							image_path = base_path + app_obj.screenshot_path
							image_file = File(open(image_path, 'rb'))
							if client_obj and client_obj.storage_type=="S3":
								image_key = ''.join(['screenshots/', filename])
								media_uploader = MediaUploader(
									client_obj,
									image_key,
									image_file
								)
								result = media_uploader.upload()
								if result == "success" and not \
										S3Uploads.objects.filter(key=image_key).exists():
									S3Uploads.objects.create(
										key=image_key,
										filename=filename
									)
					app_obj.last_seen = timezone.now()
					app_obj.save()
				except Exception as e:
					pass


@task(priority=10)
def send_mail_everyweek():
	print 'send_mail_everyweek_task::'
	if os.environ.get('REDTREE_URL'):
		if not EmailRecord.objects.filter(created__date=date.today()).exists():
			print '<<<  sending first mail today  >>>'
			clint_conf_obj = ClientConfiguration.objects.first()
			notification_list = list()
			vulnerabilities_discovered = 0
			high_sum = 0
			medium_sum = 0
			emails = NotificationEmails.objects.all()
			one_w_ago =(date.today() - timedelta(days=7)).strftime('%Y-%m-%d')
			critical_unmapped_issues = NessusData.objects.filter(
				Q(virtue_id__isnull=True) & Q(risk = 'Critical')
			).values_list('name',flat=True).annotate(instances=Count('name'))
			high_unmapped_issues = NessusData.objects.filter(
				Q(virtue_id__isnull=True) & Q(risk = 'High')
			).values_list('name',flat=True).annotate(instances=Count('name'))
			low_unmapped_issues = NessusData.objects.filter(
				Q(virtue_id__isnull=True) & Q(risk = 'Low')
			).values_list('name',flat=True).annotate(instances=Count('name'))
			medium_unmapped_issues = NessusData.objects.filter(
				Q(virtue_id__isnull=True) & Q(risk = 'Medium')
			).values_list('name',flat=True).annotate(instances=Count('name'))
			files = NessusFile.objects.filter(uploaded_at__gte=one_w_ago)
			critical_count = files.values_list('critical_new_issue',flat=True).\
					annotate(critical_issue=Cast('critical_new_issue', IntegerField())).\
					aggregate(Sum('critical_issue'))
			high_count = files.values_list('high_new_issue',flat=True).\
					annotate(high_issue=Cast('high_new_issue', IntegerField())).\
					aggregate(Sum('high_issue'))
			medium_count = files.values_list('medium_new_issue',flat=True).\
					annotate(medium_issue=Cast('medium_new_issue', IntegerField())).\
					aggregate(Sum('medium_issue'))
			low_count = files.values_list('low_new_issue',flat=True ).\
					annotate(low_issue=Cast('low_new_issue', IntegerField())).\
					aggregate(Sum('low_issue'))
			if critical_count['critical_issue__sum']:
				critical_sum = critical_count['critical_issue__sum']
			else:
				critical_sum = 0
			if high_count['high_issue__sum']:
				high_sum = high_count['high_issue__sum']
			else:
				high_sum = 0
			if medium_count['medium_issue__sum']:
				medium_sum = medium_count['medium_issue__sum']
			else:
				medium_sum = 0
			if low_count['low_issue__sum']:
				low_sum = low_count['low_issue__sum']
			else:
				low_sum = 0
			vulnerabilities_discovered = critical_sum + high_sum + medium_sum + low_sum
			vulnerability_completed = files.count()
			if high_sum + medium_sum == 0 :
				subject_in = "[{0}] Weekly Scanning Summary".\
					format(clint_conf_obj.client_name)
			else:
				subject_in = "[{0}] Weekly Scanning Summary (Action Required)".\
					format(clint_conf_obj.client_name)
			context = {
				'vulnerability_completed': vulnerability_completed,
				'vulnerabilities_discovered': vulnerabilities_discovered,
				'medium_unmapped_issues': medium_unmapped_issues.count(),
				'low_unmapped_issues': low_unmapped_issues.count(),
				'high_unmapped_issues': high_unmapped_issues.count(),
				'critical_unmapped_issues': critical_unmapped_issues.count(),
				'redtree_url': os.environ.get('REDTREE_URL')
				}
			send_weekly_mail_template = render_to_string(
				'email-templates/send_weekly_mail.html',
				context
			)
			try:
				print 'inside try'
				notification_email_objs = NotificationEmails.objects.values_list(
					'email', flat=True
				)
				notification_list = [str(email) for email in notification_email_objs]
				print 'notification_list',notification_list
				subject = subject_in
				reciever = notification_list
				send_mail(reciever, subject, send_weekly_mail_template)
				message = "vulnerability_scan_completed={},\n"\
					"vulnerabilities_discovered={},\nunmapped_issues>>\n"\
					"medium={},\nlow={},\nhigh={},\ncritical={}".\
					format(
						vulnerability_completed,vulnerabilities_discovered,
						medium_unmapped_issues.count(),low_unmapped_issues.count(),
						high_unmapped_issues.count(),critical_unmapped_issues.count()
					)
				EmailRecord.objects.create(
					email_type="weekly_email",
					receivers=notification_list,
					message=message
				)
			except Exception as e:
				print 'Exception:: ',e
				pass
	else:
		logging.error('Environment variable is missing')
  

@task(priority=10)
def send_host_add_mail(*args, **kwargs):
	host_data = kwargs.get('host_data')
	host_list = host_data.get('created_host_id')
	excluded_ips = host_data.get('excluded_hosts')
	hosts = list()
	for host in host_list:
		try:
			host_obj = UserHosts.objects.get(id=host)
			hosts.append('<br>' + host_obj.host)
		except:
			pass
	notification_list = list()
	emails = NotificationEmails.objects.all()
	client_obj = ClientConfiguration.objects.first()
	for email in emails:
		notification_list.append(email)
	html_content = ''
	subject = ''
	if hosts:
		html_content = "The following hosts have been added:"
		for host in hosts:
			html_content = html_content + str(host)
		subject = "[{0}] Hosts have been added".format(client_obj.client_name)
	if excluded_ips:
		rejected_ips = ""
		for host in excluded_ips:
			rejected_ips = rejected_ips + str(host) + ",  "
		RedtreeEventHistory.objects.create(
			event_type  =   'Host not added',
			time_stamp  =   datetime.datetime.now().strftime('%s'),
			data        =   rejected_ips
		)
	html_content = html_content
	if html_content:
		subject = subject
		reciever = notification_list
		send_host_mail(reciever, subject, html_content)


@task(priority=10)
def check_aws_asset_status(*args, **kwargs):
	aws_asset_id = kwargs.get('aws_asset_id')
	try:
		aws_asset_obj = ClientAwsAssets.objects.get(id=aws_asset_id)
	except:
		aws_asset_obj = None
	if aws_asset_obj:
		check_aws_asset_token_status(aws_asset_obj)

@task(bind=True, priority=5)
def refresh_aws_asset_status(*args, **kwargs):
	aws_asset_id = kwargs.get('aws_asset_id')
	try:
		all_asset = ClientAwsAssets.objects.all()
		aws_asset_obj = all_asset.filter(scan_state="Completed")
	except:
		aws_asset_obj = None
	if aws_asset_obj:
		for aws_obj in aws_asset_obj:
			refresh_aws_asset(aws_obj)


@task(bind=True, priority=5)
def application_screenshot_generator(self, *args, **kwargs):
	print self.request.id
	conf_obj = Configuration.objects.first()
	client_conf_obj = ClientConfiguration.objects.first()
	if conf_obj and client_conf_obj:
		update_next_scan(client_conf_obj)
		if conf_obj.scanning_status:
			if kwargs.get('scan_type') and kwargs.get('scan_type') == 'External':
				appliances = get_appliance("External")
				if appliances:
					external_application_screenshot_generator_scan(self.request.id)
				else:
					error_message = "External Screenshot Scan can't be initiated, because appliance is not set."
					AppNotification.objects.create(
						issue_type='cron_error',
						notification_message=error_message
					)
			elif kwargs.get('scan_type') and kwargs.get('scan_type') == 'Internal':
				appliances = get_appliance("Internal")
				if appliances:
					internal_application_screenshot_generator_scan(self.request.id)
			else:
				appliances = get_appliance("External") or get_appliance("Internal")
				if appliances:
					application_screenshot_generator_scan(self.request.id)
				else:
					error_message = "Screenshot Scan can't be initiated, because appliance is not set."
					AppNotification.objects.create(
						issue_type='cron_error',
						notification_message=error_message
					)
		else:
			error_message = "Screenshot Scan can't be initiated, because scanning is disabled.."
			AppNotification.objects.create(
				issue_type='cron_error',
				notification_message=error_message
			)
	else:
		error_message = "Screenshot Scan can't be initiated, because configuration is not setup properly.."
		AppNotification.objects.create(
			issue_type='cron_error',
			notification_message=error_message
		)


@task(bind=True, priority=5)
def cloudstorage_s3_bucket_scan(self, *args, **kwargs):
	conf_obj = Configuration.objects.first()
	client_conf_obj = ClientConfiguration.objects.first()
	if conf_obj and client_conf_obj:
		update_next_scan(client_conf_obj)
		if conf_obj.scanning_status:
			cloudstorage_bucket_scan()
		else:
			error_message = "cloudstorage scan can't be initiated, "\
				"because scanning is disabled.."
			AppNotification.objects.create(
				issue_type='cron_error',
				notification_message=error_message
			)
	else:
		error_message = "cloudstorage scan can't be initiated, "\
			"because configuration is not setup properly.."
		AppNotification.objects.create(
			issue_type='cron_error',
			notification_message=error_message
		)

@task(bind=True, priority=5)
def aws_rds_scan(self, *args, **kwargs):
	conf_obj = Configuration.objects.first()
	client_conf_obj = ClientConfiguration.objects.first()
	rds_obj = AwsRdsEndpoint.objects.first()
	if conf_obj and client_conf_obj and rds_obj:
		rds_scan()
	else:
		error_message = "rds scan can't be initiated, " \
						"No RDS found.."
		AppNotification.objects.create(
			issue_type='cron_error',
			notification_message=error_message
		)

@task(bind=True, priority=5)
def api_gateway_scan(self, *args, **kwargs):
	conf_obj = Configuration.objects.first()
	client_conf_obj = ClientConfiguration.objects.first()
	if conf_obj and client_conf_obj:
		api_scan()
	else:
		error_message = "API Gateway scan can't be initiated, " \
						"because configuration is not setup properly.."
		AppNotification.objects.create(
			issue_type='cron_error',
			notification_message=error_message
		)


@task(bind=True, priority=5)
def whois_scan(self, *args, **kwargs):
	conf_obj = Configuration.objects.first()
	client_conf_obj = ClientConfiguration.objects.first()
	if conf_obj and client_conf_obj:
		update_next_scan(client_conf_obj)
		if conf_obj.scanning_status:
			ips_whois_scan()
		else:
			error_message = "whois scan can't be initiated, "\
				"because scanning is disabled.."
			AppNotification.objects.create(
				issue_type='cron_error',
				notification_message=error_message
			)
	else:
		error_message = "whois scan can't be initiated, "\
			"because configuration is not setup properly.."
		AppNotification.objects.create(
			issue_type='cron_error',
			notification_message=error_message
		)


@task(priority=10)
def send_loopback_ip_add_mail(*args, **kwargs):
	loopback_ip_data = kwargs.get('loopback_ip_data')
	loopback_ip_list = loopback_ip_data.get('loopback_ips')
	hosts = list()
	for host in loopback_ip_list:
		hosts.append('<br>' + host)
	notification_list = list()
	emails = NotificationEmails.objects.all()
	client_obj = ClientConfiguration.objects.first()
	for email in emails:
		notification_list.append(email)
	html_content = ''
	subject = ''
	if hosts:
		if len(hosts) == 1:
			html_content = "A loopback address was added::"
		elif len(hosts) > 1:
			html_content = "The following loopback addresses were added::"
		for host in hosts:
			html_content = html_content + str(host)
		subject = "[{}] Security Alert".format(client_obj.client_name)
	html_content = html_content
	if html_content:
		subject = subject
		reciever = notification_list
		send_host_mail(reciever, subject, html_content)


@task(priority=10)
def generate_line_chart_record(*args, **kwargs):
	yesterday_date = date.today() - timedelta(days=1)
	pl_events = PurpleleafUserEventHistory.objects.filter(
		created__date=yesterday_date
	).count()
	dns_error_count = LogMicroServiceDnsEnum.objects.filter(
		created__date=yesterday_date,
		status="Error"
	).count()
	sslyze_error_count = LogMicroServiceSslyze.objects.filter(
		created__date=yesterday_date,
		status="Error"
	).count()
	sshyze_error_count = LogMicroServiceSshyze.objects.filter(
		created__date=yesterday_date,
		status="Error"
	).count()
	sshyze_error_count = LogMicroServiceSshyze.objects.filter(
		created__date=yesterday_date,
		status="Error"
	).count()
	burp_error_count = LogMicroServiceBurp.objects.filter(
		created__date=yesterday_date,
		status="Error"
	).count()
	nessus_count = LogMicroServiceNessus.objects.filter(
		status="Error",
		created__date=yesterday_date
	).count()
	masscan_count = LogMicroServiceMasscan.objects.filter(
		created__date=yesterday_date,
		status="Error"
	).count()
	total_count = dns_error_count + sslyze_error_count + sshyze_error_count + burp_error_count + nessus_count
	if EventCountHistory.objects.filter(
			created__date=date.today()
			).exists():
		hist_data_obj = EventCountHistory.objects.filter(
			created__date=date.today()
		).first()
		hist_data_obj.pl_activity = pl_events
		hist_data_obj.microservice_error = total_count
		hist_data_obj.burp_error = burp_error_count
		hist_data_obj.nessus_error = nessus_count
		hist_data_obj.masscan_error = masscan_count
		hist_data_obj.save()
	else:
		EventCountHistory.objects.create(
			pl_activity=pl_events,
			microservice_error=total_count,
			burp_error = burp_error_count,
			nessus_error = nessus_count,
			masscan_error = masscan_count,
		)


@task(bind=True, priority=10)
def get_source_ip(self, *args, **kwargs):
	print 'source_ip task started'
	appliance_id = kwargs.get('appliance_id')
	if appliance_id:
		try:
			appliance = Appliances.objects.get(id=appliance_id)
		except:
			appliance = Appliances.objects.filter(
				network_type="Internal"
			).first()
	else:
		appliance = Appliances.objects.filter(
			network_type="Internal"
		).first()
	conf_obj = Configuration.objects.first()
	if conf_obj and conf_obj.scanning_status and appliance and \
			appliance.appliance_setting:
		appliance_settings_obj = appliance.appliance_setting
		url = "http://{}/sourceip/".format(
			appliance.appliance_ip
		)
		auth_username = appliance_settings_obj.auth_username
		auth_password = appliance_settings_obj.auth_password
		curl_request = "curl -u {}:{} {}".format(
			auth_username, auth_password, url
		)
		request_header = {
			"Content-Type": "application/json"
		}
		try:
			response = requests.get(
				url,
				auth=(auth_username, auth_password),
				headers = request_header
			)
		except requests.exceptions.ConnectionError:
			error_message = "Connection error due to maximum retries exceeded "\
				"for sourceip on appliance {}".format(
					appliance.appliance_ip
				)
			AppNotification.objects.create(
				issue_type='error',
				notification_message=error_message
			)
			response = None
			return
		except requests.Timeout as timeout_exc:
			error_message = "Exception while fetching detail for internal "\
				"appliance due to Maximum connect time limit exceeded."
			AppNotification.objects.create(
				issue_type='error',
				notification_message=error_message
			)
			response = None
			return
		except Exception as error:
			error_message = "Exception while fetching detail for internal "\
				"appliance::\n{}. Curl is {}".format(
				error, curl_request
			)
			AppNotification.objects.create(
				issue_type='error',
				notification_message=error_message
			)
			response = None
			return
		print 'response',response
		try:
			json_response = response.json()
			ip = json_response.get('ip')
		except:
			json_response = None
			ip = None
		error_message = None
		if json_response and ip:
			try:
				ip_address = ipaddress.ip_address(ip)
			except Exception as error:
				print 'Exception while fetching detail for internal appliance::',error
				error_message = "Exception while fetching detail for internal "\
					"appliance::\n{}".format(
					error
				)
				AppNotification.objects.create(
					issue_type='error',
					notification_message=error_message
				)
				ip_address = None
				return
			if ip_address:
				appliance.source_ip = ip_address
			else:
				appliance.source_ip = ""
			appliance.save()
			return
		elif json_response and json_response.get('error'):
			error_message = "Error {} while fetching source_ip(Internal appliance).\n Curl is {}".format(
				str(json_response.get('error')), curl_request
			)
		elif json_response and not json_response.get('error'):
			error_message = "Error {} while fetching source_ip(Internal appliance).\n Curl is {}".format(
				str(json_response), curl_request
			)
		elif json_response and not ip:
			error_message = "Error in get_source_ip(Internal appliance) "\
				"appliance is not returning sourceip.{}. \n Curl is {}".format(str(response.text), curl_request)
		elif response:
			error_message = "Error in get_source_ip(Internal appliance) while fetching detail for internal "\
				"appliance::  \n.Curl is {}".format(curl_request) + str(response)
		elif response.text:
			error_message = "Error in get_source_ip(Internal appliance) while fetching detail for internal "\
				"appliance::  \n. Curl is {}".format(curl_request) + str(response.text)
		else:
			error_message = "Error in get_source_ip(Internal appliance) while fetching detail for internal "\
				"appliance:: \n There is either a network connection problem "\
				"or the API itself is not returning data..\nCurl is {}".format(curl_request)
		if error_message:
			AppNotification.objects.create(
				issue_type='error',
				notification_message=error_message
			)


@task(priority=10)
def send_application_add_mail(*args, **kwargs):
	application_urls = kwargs.get('application_urls')
	client_obj = ClientConfiguration.objects.first()
	notification_list = list()
	emails = NotificationEmails.objects.all()
	for email in emails:
		notification_list.append(email)
	if application_urls and len(application_urls) > 1:
		html_content = "The following applications has been added:"
		for application in application_urls:
			html_content = html_content + str(application)
		subject = "[{0}] New applications added".format(client_obj.client_name)
		reciever = notification_list
		send_host_mail(reciever, subject, html_content)
	elif application_urls and len(application_urls) == 1:
		html_content = "The following application has been added:"
		for application in application_urls:
			html_content = html_content + str(application)
		subject = "[{0}] New application added".format(client_obj.client_name)
		reciever = notification_list
		send_host_mail(reciever, subject, html_content)

def append_pdf(pdf, output):
	[output.addPage(pdf.getPage(page_num)) for page_num in range(pdf.numPages)]

def create_report(monthly_report=False, request=None):

	template = get_template("redtree_app/context_pdf.html")
	front_page_template = get_template("redtree_app/pdf_first_page.html")
	last_page_template = get_template("redtree_app/pdf_last_page.html")
	response = None
	message = None
	for network_type in ['External', 'Internal']:
		try:
			context = get_report_data(
				request=request,
				network_type=network_type
			)
			context['base_path'] = settings.BASE_DIR
		except:
			context = None
		front_page_html = front_page_template.render(context)
		context_html = template.render(context)
		last_page_html = last_page_template.render(context)
		conf_obj = ClientConfiguration.objects.first()
		if conf_obj:
			file_name = '{}-Network Penetration Test-{} Report.pdf'.\
				format(conf_obj.client_name,date.today().strftime("%B %Y")
			)
			front_page_file = "front_page.pdf"
			context_file = "context.pdf"
			last_page_file = "conclusion.pdf"
		else:
			file_name = 'Network Penetration Test - {} Report.pdf'.\
				format(date.today().strftime("%B %Y"))
			front_page_file = "front_page.pdf"
			context_file = "context.pdf"
			last_page_file = "conclusion.pdf"

		dir_path = './media/Reports/api/{}'.format(date.today())
		if not os.path.exists(dir_path):
			os.makedirs(dir_path)
		file_path = dir_path + "/{}".format(file_name)
		front_page_file_path = dir_path + "/{}".format(front_page_file)
		context_file_path = dir_path + "/{}".format(context_file)
		last_page_file_path = dir_path + "/{}".format(last_page_file)

		front_page_options = {
			'page-size': 'Letter',
			'margin-top': '0in',
			'margin-right': '0in',
			'margin-bottom': '0in',
			'margin-left': '0in',
		}
		context_options = {
			'page-size': 'Letter',
			'margin-top': '0.20in',
			'margin-right': '0in',
			'margin-bottom': '0.20in',
			'margin-left': '0in',
		}
		last_page_options = {
			'page-size': 'Letter',
			'margin-top': '0in',
			'margin-right': '0in',
			'margin-bottom': '0in',
			'margin-left': '0in',
		}

		pdfkit.from_string(
							last_page_html,
							last_page_file_path,
							options=last_page_options
						)
		pdfkit.from_string(
							context_html,
							context_file_path,
							options=context_options
						)
		pdfkit.from_string(
							front_page_html,
							front_page_file_path,
							options=front_page_options
						)

		output = PdfFileWriter()
		append_pdf(PdfFileReader(open(front_page_file_path, "rb")), output)
		append_pdf(PdfFileReader(open(context_file_path, "rb")), output)
		append_pdf(PdfFileReader(open(last_page_file_path, "rb")), output)
		output.write(open(file_path, "wb"))
		bufsize = 0
		pdf = open(file_path, "rb" , bufsize)
		if network_type == "External":
			response = HttpResponse(pdf.read(), content_type='application/pdf')
		pdf.close()
		pdf_file = open(file_path)
		file_obj = File(pdf_file)
		try:
			report_obj = Reports()
			report_obj.file.save(file_name, file_obj, save=True)
			report_obj.network_type = network_type
			report_obj.save()
			shutil.rmtree(dir_path, ignore_errors=True)
		except:
			report_obj = None
		if conf_obj and conf_obj.storage_type == "S3" and report_obj:
			try:
				base_path = str(settings.BASE_DIR)
				file_key =  ''.join(['media/', str(report_obj.file)])
				pdf_file_path = base_path + '/' + file_key
				open_pdf_file = open(pdf_file_path, 'rb')
				media_uploader = MediaUploader(conf_obj, file_key, open_pdf_file)
				result = media_uploader.upload()
				if result == "success" and not\
						S3Uploads.objects.filter(key=file_key).exists():
					S3Uploads.objects.create(key=file_key, filename=file_name)
				open_pdf_file.close()
			except Exception as e:
				message = e
				response = None
		elif conf_obj and not report_obj and not monthly_report:
			message = "Unable to generate pdf"
			response = None
	if not monthly_report:
		return response, message

@task(priority=10)
def generate_monthly_pdf(*args, **kwargs):	
		
	create_report(monthly_report=True)

	# To send emails to users
	
	notification_list = list()
	emails = NotificationEmails.objects.all()
	for email in emails:
		notification_list.append(email)
	html_content = "The monthly report has been generated."
	subject = "Monthly report generated"
	reciever = notification_list
	send_host_mail(reciever, subject, html_content)
