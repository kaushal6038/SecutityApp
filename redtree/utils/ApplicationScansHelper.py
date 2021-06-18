# -*- coding: utf-8 -*-
# core imports
import requests
import time

# in house files import
from redtree_app.models import *
from playground.models import *
import base64
from utils.helpers import (
	get_appliance
)
import json
from urlparse import urlparse
from celery import task
from django.utils import timezone
from redtree_app.views import processBurpData
from celery.utils.log import get_task_logger
from raven.contrib.django.raven_compat.models import client as sentry_client

logger = get_task_logger(__name__)


class ApplicationScanHelper(object):
	"""It will create the application scans"""

	def __init__(self, appliance_pk, application_pk, task_id, network_type, response=None):
		appliance = Appliances.objects.get(pk=appliance_pk).appliance_setting
		application = Applications.objects.get(pk=application_pk)
		if response:
			log_obj = LogMicroServiceBurp.objects.get(
				application=application,
				network_type=network_type,
				appliance=appliance.appliance.id,
				task_id=task_id,
				status="Running")
		else:
			log_obj = LogMicroServiceBurp.objects.create(
				application=application,
				network_type=network_type,
				appliance=appliance.appliance.id,
				task_id=task_id,
				status="Queued"
			)


		self.response = response
		self.appliance_pk = appliance_pk
		self.application_pk = application_pk
		self.network = network_type
		self.log_obj = log_obj
		self.dns_logging = LogMicroServiceBurp.objects.filter(pk=log_obj.pk)
		self.scan_url = appliance.burp_url
		self.task_id = task_id
		self.auth_username = appliance.auth_username
		self.auth_password = appliance.auth_password
		self.parsed_uri = urlparse(self.scan_url)
		self.domain = '{uri.scheme}://{uri.netloc}/{prefix}'.format(uri=self.parsed_uri, prefix="burp")
		self.application = application.application_url
		self.app_obj = application
		self.context = dict()

	def create_application_scan(self):
		post_data = {
			'url': self.application
		}
		create_curl_req = "curl -u {}:{} --header 'Content-Type: application/json' "\
			"--request POST --data '{}' {}".format(
				self.auth_username,
				self.auth_password,
				json.dumps(post_data),
				self.scan_url
			)
		headers = {
			'Content-Type': 'application/json',
		}
		try:
			response = requests.post(
				self.scan_url,
				json = post_data,
				auth=(self.auth_username, self.auth_password),
				headers = headers,
				timeout=240
			)
			print "application scan generated successfully"
		except requests.Timeout as timeout_exc:
			message="Unable to add application scan due to Maximum"\
				"connect time limit exceeded."
			AppNotification.objects.create(
				issue_type='error',
				notification_message=message
			)
			self.dns_logging.update(
				status="Error",
				message=message,
				is_completed=True,
				modified=timezone.now()
			)
			response = None

		except Exception as error:
			error_message = "error {} in Application scan.Curl request is {}.".format(
				error,
				create_curl_req
			)
			AppNotification.objects.create(
				issue_type='error',
				notification_message=error_message
			)
			self.dns_logging.update(
				status="Error",
				message=error_message,
				is_completed=True,
				modified=timezone.now()
			)
			response = None
		self.context['status'] = False
		self.context['scan_obj'] = None
		try:
			if response.status_code == 200:
				data = response.json()
				try:
					error_message = data.get('exception')
				except:
					error_message = None
				if error_message:
					message = "𝗘𝘅𝗰𝗲𝗽𝘁𝗶𝗼𝗻 :: {}.\n𝗖𝘂𝗿𝗹 𝗥𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀:: {}.".format(
						error_message,
						create_curl_req
					)
					self.dns_logging.update(
						status="Error",
						message=message,
						modified=timezone.now(),
						is_completed=True
					)
					return
				scan_obj = ApplicationScans.objects.create(
					application=self.app_obj,
					scan_id=data.get('scan_id'),
					status_uri=data.get('status_uri'),
					scan_status=True
				)
				status_url = "{}{}".format(
					self.domain,
					data.get("status_uri")
				)
				self.get_status_curl = "curl -u {}:{} --request GET {}".format(
					self.auth_username,
					self.auth_password,
					status_url
				)
				log = "scan added you can check the status by status_url\n{}".format(status_url)
				self.dns_logging.update(
					status="Running",
					message=log,
					scan_id=data.get('scan_id'),
					modified=timezone.now()
				)
				self.scan_obj = scan_obj
				self.context['status'] = True
				self.context['scan_obj'] = scan_obj
				process_burp.delay(status_url, self.appliance_pk, self.application_pk, self.network, self.log_obj.pk, self.task_id)
				return self.context
			elif response.status_code == 400:
				try:
					json_response = response.json()
				except:
					json_response = None
				try:
					response_text = response.text
				except:
					response_text = None
				if json_response and json_response.get('error'):
					error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) +\
						"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + create_curl_req
				elif json_response and not json_response.get('error'):
					error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:   " + str(json_response) +\
						"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + create_curl_req
				elif response:
					error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) +\
						"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + create_curl_req
				elif response_text:
					error_message = "(400 Bad Request).\n𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " +\
						str(response_text) + "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + create_curl_req
				else:
					error_message = "(400 Bad Request)." +\
						"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + create_curl_req
				self.dns_logging.update(
					status="Error",
					message=error_message,
					modified=timezone.now(),
					is_completed=True
				)
				return self.context
			elif response.status_code == 404:
				try:
					json_response = response.json()
				except:
					json_response = None
				try:
					response_text = response.text
				except:
					response_text = None
				if json_response and json_response.get('error'):
					error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) +\
						"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + create_curl_req
				elif json_response and not json_response.get('error'):
					error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:   " + str(json_response) +\
						"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + create_curl_req
				elif response:
					error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) +\
						"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + create_curl_req
				elif response_text:
					error_message = "(404 not found).\n𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " +\
						str(response_text) + "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + create_curl_req
				else:
					error_message = "(404 not found)." +\
						"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + create_curl_req
				self.dns_logging.update(
					status="Error",
					message=error_message,
					is_completed=True,
					modified=timezone.now()
				)
				return self.context
			elif response.status_code == 504:
				try:
					json_response = response.json()
				except:
					json_response = None
				try:
					response_text = response.text
				except:
					response_text = None
				if json_response and json_response.get('error'):
					error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) +\
						"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + create_curl_req
				elif json_response and not json_response.get('error'):
					error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:   " + str(json_response) +\
						"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + create_curl_req
				elif response:
					error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) +\
						"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + create_curl_req
				elif response_text:
					error_message = "(504 Gateway Timeout error).\n𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " +\
						str(response_text) + "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + create_curl_req
				else:
					error_message = "(504 Gateway Timeout error)." +\
						"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + create_curl_req
				self.dns_logging.update(
					status="Error",
					message=error_message,
					is_completed=True,
					modified=timezone.now()
				)
				AppNotification.objects.create(
					issue_type='error',
					notification_message="Unable to add application scan for {} {}".format(
						self.application,
						error_message
						)
				)
				return self.context
			elif response.status_code == 401:
				try:
					json_response = response.json()
				except:
					json_response = None
				try:
					response_text = response.text
				except:
					response_text = None
				if json_response and json_response.get('error'):
					error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) +\
						"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + create_curl_req
				elif json_response and not json_response.get('error'):
					error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:   " + str(json_response) +\
						"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + create_curl_req
				elif response:
					error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) +\
						"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + create_curl_req
				elif response_text:
					error_message = "(401 Unauthorized).\n𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " +\
						str(response_text) + "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + create_curl_req
				else:
					error_message = "(401 Unauthorized)." +\
						"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + create_curl_req
				self.dns_logging.update(
					status="Error",
					message=error_message,
					is_completed=True,
					modified=timezone.now()
				)
				AppNotification.objects.create(
					issue_type='error',
					notification_message="Unable to add application scan for {} {}".format(
						self.application,
						error_message
						)
				)
				return self.context
			elif response.status_code == 500:
				try:
					json_response = response.json()
				except:
					json_response = None
				try:
					response_text = response.text
				except:
					response_text = None
				if json_response and json_response.get('error'):
					error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) +\
						"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + create_curl_req
				elif json_response and not json_response.get('error'):
					error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:   " + str(json_response) +\
						"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + create_curl_req
				elif response:
					error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) +\
						"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + create_curl_req
				elif response_text:
					error_message = "(500 Internal Server Error).\n𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " +\
						str(response_text) + "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + create_curl_req
				else:
					error_message = "(500 Internal Server Error)." +\
						"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + create_curl_req
				self.dns_logging.update(
					status="Error",
					message=error_message,
					is_completed=True,
					modified=timezone.now()
				)
				return self.context
			elif response.status_code == 502:
				try:
					json_response = response.json()
				except:
					json_response = None
				try:
					response_text = response.text
				except:
					response_text = None
				if json_response and json_response.get('error'):
					error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) +\
						"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + create_curl_req
				elif json_response and not json_response.get('error'):
					error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:   " + str(json_response) +\
						"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + create_curl_req
				elif response:
					error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) +\
						"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + create_curl_req
				elif response_text:
					error_message = "(502 Bad Gateway).\n𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " +\
						str(response_text) + "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + create_curl_req
				else:
					error_message = "(502 Bad Gateway)." +\
						"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + create_curl_req
				self.dns_logging.update(
					status="Error",
					message=error_message,
					is_completed=True,
					modified=timezone.now()
				)
				return self.context
			else:
				try:
					json_response = response.json()
				except:
					json_response = None
				try:
					response_text = response.text
				except:
					response_text = None
				if json_response and json_response.get('error'):
					error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) +\
						"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + create_curl_req
				elif json_response and not json_response.get('error'):
					error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:   " + str(json_response) +\
						"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + create_curl_req
				elif response:
					error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) +\
						"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + create_curl_req
				elif response_text:
					error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response_text) +\
						"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + create_curl_req
				else:
					error_message = "There is either a network connection problem "\
						"or the API itself is not returning data."\
						"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + create_curl_req
				self.dns_logging.update(
					status="Error",
					message=error_message,
					is_completed=True,
					modified=timezone.now()
				)
				AppNotification.objects.create(
					issue_type='error',
					notification_message=error_message
				)
				return self.context
		except Exception as e:
			try:
				json_response = response.json()
			except:
				json_response = None
			try:
				response_text = response.text
			except:
				response_text = None
			if json_response and json_response.get('error'):
				error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) +\
					"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + create_curl_req
			elif json_response and not json_response.get('error'):
				error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:   " + str(json_response) +\
					"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + create_curl_req
			elif response:
				error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) +\
					"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + create_curl_req
			elif response_text:
				error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response_text) +\
					"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + create_curl_req
			else:
				error_message = "There is either a network connection problem "\
					"or the API itself is not returning data.."\
					"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + create_curl_req
			self.dns_logging.update(
				status="Error",
				message=error_message,
				is_completed=True,
				modified=timezone.now()
			)
			AppNotification.objects.create(
				issue_type='error',
				notification_message=error_message
			)
			# logger.error(error_message)
			return self.context

	def process_encoded_response(self, response_json):
		response_str = ""
		if response_json:
			for res in response_json:
				encode_str = res.get('data')
				if encode_str:
					raw_str = base64.b64decode(encode_str)
					try:
						raw_str.decode('utf-8')
						response_str = "{}{}".format(response_str, raw_str)
					except UnicodeDecodeError, UnicodeError:
						response_str = "{}\n{}".format(response_str, encode_str)
					except:
						sentry_client.captureException()
		return response_str.replace('\x00', '')

	def process_encoded_request(self, request_json):
		request_str = ""
		if request_json:
			for req in request_json:
				encode_str = req.get('data')
				if encode_str:
					raw_str = base64.b64decode(encode_str)
					try:
						raw_str.decode('utf-8')
						request_str = "{}{}".format(request_str, raw_str)
					except UnicodeDecodeError, UnicodeError:
						response_str = "{}\n{}".format(response_str, encode_str)
					except:
						sentry_client.captureException()
		return request_str.replace('\x00', '')

	def process_evidence(self, scan_obj, evidence_list):
		for evidence in evidence_list:
			request_response = evidence.get("request_response")
			if request_response:
				url = request_response.get("url")
				if url:
					encoded_request = request_response.get("request")
					encoded_response = request_response.get("response")
					request_str = self.process_encoded_request(encoded_request)
					response_str = self.process_encoded_response(encoded_response)
					BurpEvidence.objects.create(
						issue = scan_obj,
						url = url,
						request = request_str,
						response = response_str
						)

	def update_application_scan_status(self):
		print "updating scan result"
		response = self.response
		result =  response.get("result_uri")
		scan_id = result.split("/")[2] #Get Scan ID
		scan_obj = ApplicationScans.objects.get(
			scan_id=scan_id,
		)
		if response and response.get('status') != "FAILED":
			if response and response.get('status') == "COMPLETED":
				application_obj = self.app_obj
				result_uri = response.get("result_uri")
				result_url = self.domain + result_uri
				log = "scan completed can check the result by url\n{}".format(result_url)
				self.dns_logging.update(
					status="Completed",
					message=log,
					modified=timezone.now()
				)
				result = get_status(result_url, self.auth_username, self.auth_password, self.dns_logging)
				issues = result.get('results').get('issue_events')
				issues_len = 0
				for issue_list in issues:
					issue = issue_list.get('issue')
					origin = issue.get('origin')
					confidence = issue.get('confidence')
					name = issue.get('name')
					description = issue.get('description')
					caption = issue.get('caption')
					type_index = issue.get('type_index')
					internal_data = issue.get('internal_data')
					path = issue.get('path')
					serial_number = issue.get('serial_number')
					severity = issue.get('severity')
					evidence_list = issue.get('evidence')
					if not ApplicationScanData.objects.filter(
							origin=origin,
							confidence=confidence,
							name=name,
							description=description,
							caption=caption,
							type_index=type_index,
							internal_data=internal_data,
							path=path,
							severity=severity
						) and ApplicationScanData.objects.filter(
							origin=origin,
							application_fk=application_obj,
							name=name
						).count() <= 25:
						app_scan_obj = ApplicationScanData.objects.create(
							application=scan_obj,
							application_fk=application_obj,
							origin=origin,
							confidence=confidence,
							name=name,
							description=description,
							caption=caption,
							type_index=type_index,
							internal_data=internal_data,
							path=path,
							serial_number=serial_number,
							severity=severity,
						)
						issues_len += 1
						if evidence_list:
							self.process_evidence(
								app_scan_obj,
								evidence_list
							)
					scan_obj.scan_status = False
					scan_obj.save()
				if issues_len > 0:
					result = "{} issues discovered.".format(issues_len)
					log = "scan completed and {} subdomains discovered.".format(issues_len)
				else:
					result = "No issues discovered."
					log = "scan completed and no new issues discovered."
				self.dns_logging.update(
					status="Completed",
					message=log,
					is_completed=True,
					result=result,
					modified=timezone.now()
				)
				application_obj.last_scan = timezone.now()
				application_obj.save()
				processBurpData('cron_job')
			elif response and response.get('status') == "FAILED":
				try:
					json_response = response
				except:
					json_response = None
				try:
					response_text = response.text
				except:
					response_text = None
				if json_response and json_response.get('error'):
					error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error'))
				elif json_response and not json_response.get('error'):
					error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:   " + str(json_response)
				elif response:
					error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response)
				elif response_text:
					error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response_text)
				else:
					error_message = "There is either a network connection problem "\
						"or the API itself is not returning data.."
				self.dns_logging.update(
					status="Completed",
					message=error_message,
					is_completed=True,
					modified=timezone.now()
				)
				scan_obj.scan_status = False
				scan_obj.save()
			else:
				try:
					json_response = response
				except:
					json_response = None
				try:
					response_text = response.text
				except:
					response_text = None
				if json_response and json_response.get('error'):
					error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error'))
				elif json_response and not json_response.get('error'):
					error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:   " + str(json_response)
				elif response:
					error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response)
				elif response_text:
					error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response_text)
				else:
					error_message = "There is either a network connection problem "\
						"or the API itself is not returning data.."
				self.dns_logging.update(
					status="Completed",
					message=error_message,
					is_completed=True,
					modified=timezone.now()
				)
				AppNotification.objects.create(
					issue_type='error',
					notification_message="Scan Failed for application {}. {}".format(
						scan_obj.application,
						error_message
					)
				)
				scan_obj.scan_status = False
				scan_obj.save()
		elif response and response.get('status') == "FAILED":
			try:
				json_response = response
			except:
				json_response = None
			try:
				response_text = response.text
			except:
				response_text = None
			if json_response and json_response.get('error'):
				error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error'))
			elif json_response and not json_response.get('error'):
				error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:   " + str(json_response)
			elif response:
				error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response)
			elif response_text:
				error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response_text)
			else:
				error_message = "There is either a network connection problem "\
					"or the API itself is not returning data.."
			AppNotification.objects.create(
				issue_type='error',
				notification_message="Scan Failed for application {}. {}".format(
					scan_obj.application,
					error_message
				)
			)
			self.dns_logging.update(
				status="Error",
				is_completed=True,
				message=error_message,
				result=error_message,
				modified=timezone.now()
			)
			scan_obj.scan_status = False
			scan_obj.save()
		else:
			try:
				json_response = response
			except:
				json_response = None
			try:
				response_text = response.text
			except:
				response_text = None
			if json_response and json_response.get('error'):
				error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error'))
			elif json_response and not json_response.get('error'):
				error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:   " + str(json_response)
			elif response:
				error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response)
			elif response_text:
				error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response_text)
			else:
				error_message = "There is either a network connection problem "\
					"or the API itself is not returning data.."
			self.dns_logging.update(
				status="Completed",
				message=error_message,
				is_completed=True,
				modified=timezone.now()
			)
			AppNotification.objects.create(
				issue_type='error',
				notification_message="Scan Failed for application {}. {}".format(
					scan_obj.application,
					error_message
				)
			)
			scan_obj.scan_status = False
			scan_obj.save()


def internal_application_scan(task_id):
	app_obj = Applications.objects.filter(
		network_type="Internal",
		scanning_enabled=True,
		burp_scanning=False
	).first() # Get the first Internal application
	if app_obj:
		appliance = get_appliance("Internal") # Get Internal Appliance
		scan_obj = ApplicationScanHelper(
			appliance.appliance_setting.pk,
			app_obj.pk,
			task_id,
			"Internal"
		)
		scan_obj.create_application_scan() #  Start Burp Scan on the first internal host



def external_application_scan(task_id):
	app_obj = Applications.objects.filter(
		network_type="External",
		scanning_enabled=True,
		burp_scanning=False
	).first()  # Get the first external application
	if app_obj:
		appliance = get_appliance("External") # Get External Appliance
		# for appliance in appliances:
		scan_obj = ApplicationScanHelper(
			appliance.appliance_setting.pk,
			app_obj.pk,
			task_id,
			"External"
		)
		scan_obj.create_application_scan() # Start Burp Scan on the first host



@task(name='process_burp_scan')
def process_burp(url, appliance_pk, application_pk,  network_type, log_pk, task_id):
	appliance_obj = Appliances.objects.get(pk=appliance_pk) # Get current Appliance
	application_obj = Applications.objects.get(pk=application_pk) # Get current Application
	auth_username = appliance_obj.appliance_setting.auth_username
	auth_password = appliance_obj.appliance_setting.auth_password
	# task_log = LogMicroServiceSslyze.objects.get(pk=log_pk)
	dns_logging = LogMicroServiceBurp.objects.filter(id=log_pk)
	response_data = get_status(url, auth_username, auth_password, dns_logging) # Check Scan Status
	if response_data and response_data.get('status') == "PENDING":
		process_burp.apply_async([url, appliance_pk, application_pk, network_type, log_pk, task_id], countdown=300) # Check in 5 minutes
	if response_data and (response_data.get('status') == "COMPLETED") or response_data.get('status') == "FAILED":
		try:
			application_obj.burp_scanning = True
			application_obj.save()
			scan_obj = ApplicationScanHelper(
				appliance_pk,
				application_pk,
				task_id,
				network_type,
				response_data
			)
			scan_obj.update_application_scan_status()
			if network_type == "Internal":
				internal_application_scan(task_id)
			if network_type == "External":
				external_application_scan(task_id)
		except Exception as e:
			if network_type == "Internal":
				internal_application_scan(task_id)
			if network_type == "External":
				external_application_scan(task_id)

def get_status(url, auth_username, auth_password, dns_logging):
	status_curl = "curl -u {}:{} --request GET {}".format(
		auth_username,
		auth_password,
		urlparse
	)
	try:
		response = requests.get(
			url,
			auth=(auth_username, auth_password),
			timeout=240
		)
	except Exception as error:
		error_message = "error {} in getting response for application scan.Curl is: {}".format(
			error,
			status_curl
		)
		# logger.error('{}'.format(error_message))
		dns_logging.update(
			status="Error",
			message=error_message,
			is_completed=True,
			modified=timezone.now()
		)
		AppNotification.objects.create(
			issue_type='error',
			notification_message=error_message
		)
		response = None
	try:
		if response and response.status_code == 200:
			response_data = response.json()
			try:
				error_message = response_data.get('exception')
			except:
				error_message = None
			if error_message:
				message = "𝗘𝘅𝗰𝗲𝗽𝘁𝗶𝗼𝗻:: {} \n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   {}".format(
					error_message,
					status_curl
				)
				dns_logging.update(
					status="Error",
					message=message,
					modified=timezone.now(),
					is_completed=True
				)
			return response_data
		elif response.status_code == 400:
			try:
				json_response = response.json()
			except:
				json_response = None
			try:
				response_text = response.text
			except:
				response_text = None
			if json_response and json_response.get('error'):
				error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) + \
								"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
			elif json_response and not json_response.get('error'):
				error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:   " + str(json_response) + \
								"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
			elif response:
				error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) + \
								"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
			elif response_text:
				error_message = "(400 Bad Request).\n𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + \
								str(response_text) + "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
			else:
				error_message = "(400 Bad Request)." + \
								"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
			dns_logging.update(
				status="Error",
				message=error_message,
				is_completed=True,
				modified=timezone.now()
			)
			return
		elif response.status_code == 401:
			try:
				json_response = response.json()
			except:
				json_response = None
			try:
				response_text = response.text
			except:
				response_text = None
			if json_response and json_response.get('error'):
				error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) + \
								"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
			elif json_response and not json_response.get('error'):
				error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:   " + str(json_response) + \
								"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
			elif response:
				error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) + \
								"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
			elif response_text:
				error_message = "(401 Unauthorized).\n𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + \
								str(response_text) + "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
			else:
				error_message = "(401 Unauthorized)." + \
								"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
			dns_logging.update(
				status="Error",
				message=error_message,
				modified=timezone.now(),
				is_completed=True
			)
			AppNotification.objects.create(
				issue_type='error',
				notification_message=error_message
			)
			return
		elif response.status_code == 404:
			try:
				json_response = response.json()
			except:
				json_response = None
			try:
				response_text = response.text
			except:
				response_text = None
			if json_response and json_response.get('error'):
				error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) + \
								"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
			elif json_response and not json_response.get('error'):
				error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:   " + str(json_response) + \
								"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
			elif response:
				error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) + \
								"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
			elif response_text:
				error_message = "(404 not found).\n𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + \
								str(response_text) + "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
			else:
				error_message = "(404 not found)." + \
								"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
			dns_logging.update(
				status="Error",
				message=error_message,
				modified=timezone.now(),
				is_completed=True
			)
			return
		elif response.status_code == 504:
			try:
				json_response = response.json()
			except:
				json_response = None
			try:
				response_text = response.text
			except:
				response_text = None
			if json_response and json_response.get('error'):
				error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) + \
								"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
			elif json_response and not json_response.get('error'):
				error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:   " + str(json_response) + \
								"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
			elif response:
				error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) + \
								"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
			elif response_text:
				error_message = "(504 Gateway Timeout error).\n𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + \
								str(response_text) + "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
			else:
				error_message = "(504 Gateway Timeout error)." + \
								"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
			dns_logging.update(
				status="Error",
				message=error_message,
				is_completed=True,
				modified=timezone.now()
			)
			return
		elif response.status_code == 500:
			try:
				json_response = response.json()
			except:
				json_response = None
			try:
				response_text = response.text
			except:
				response_text = None
			if json_response and json_response.get('error'):
				error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) + \
								"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
			elif json_response and not json_response.get('error'):
				error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:   " + str(json_response) + \
								"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
			elif response:
				error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) + \
								"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
			elif response_text:
				error_message = "(500 Internal Server Error).\n𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + \
								str(response_text) + "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
			else:
				error_message = "(500 Internal Server Error)." + \
								"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
			dns_logging.update(
				status="Error",
				message=error_message,
				is_completed=True,
				modified=timezone.now()
			)
			return
		elif response.status_code == 502:
			try:
				json_response = response.json()
			except:
				json_response = None
			try:
				response_text = response.text
			except:
				response_text = None
			if json_response and json_response.get('error'):
				error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) + \
								"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
			elif json_response and not json_response.get('error'):
				error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:   " + str(json_response) + \
								"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
			elif response:
				error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) + \
								"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
			elif response_text:
				error_message = "(502 Bad Gateway).\n𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + \
								str(response_text) + "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
			else:
				error_message = "(502 Bad Gateway)." + \
								"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
			dns_logging.update(
				status="Error",
				message=error_message,
				is_completed=True,
				modified=timezone.now()
			)
			return
		else:
			try:
				json_response = response.json()
			except:
				json_response = None
			try:
				response_text = response.text
			except:
				response_text = None
			if json_response and json_response.get('error'):
				error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) + \
								"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
			elif json_response and not json_response.get('error'):
				error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:   " + str(json_response) + \
								"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
			elif response:
				error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) + \
								"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
			elif response_text:
				error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + \
								str(response_text) + "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
			else:
				error_message = "There is either a network connection problem " \
								"or the API itself is not returning data." \
								"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
			dns_logging.update(
				status="Error",
				message=error_message,
				is_completed=True,
				modified=timezone.now()
			)
			return
	except Exception as e:
		try:
			json_response = response.json()
		except:
			json_response = None
		try:
			response_text = response.text
		except:
			response_text = None
		if json_response and json_response.get('error'):
			error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) + \
							"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
		elif json_response and not json_response.get('error'):
			error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:   " + str(json_response) + \
							"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
		elif response:
			error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) + \
							"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
		elif response_text:
			error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + \
							str(response_text) + "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
		else:
			error_message = "There is either a network connection problem " \
							"or the API itself is not returning data.." \
							"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
		dns_logging.update(
			status="Error",
			message=error_message,
			modified=timezone.now(),
			is_completed=True
		)
		return

def application_scan(task_id):
	internal_appliance = get_appliance("Internal")
	external_appliance = get_appliance("External")
	if internal_appliance:
		internal_application_scan(task_id) # Start Internal Burp Scan
	if external_appliance:
		external_application_scan(task_id) # Start External Burp Scan



def get_application_scan_result(response_url, response_curl, auth_username, auth_password, log_obj):
	try:
		response = requests.get(
			response_url,
			auth=(auth_username, auth_password),
			timeout=240
		)
	except requests.Timeout as timeout_exc:
		message="𝗘𝘅𝗰𝗲𝗽𝘁𝗶𝗼𝗻::  {} while fetching response for application {}"\
			"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   {}".format(
				timeout_exc,
				log_obj.application.application_url,
				response_url
			)
		AppNotification.objects.create(
			issue_type='error',
			notification_message=message
		)
		log_obj.status="Error"
		log_obj.message=message
		log_obj.is_completed=True
		log_obj.modified=timezone.now()
		log_obj.save()
		response = None
	except Exception as error:
		error_message = "𝗘𝘅𝗰𝗲𝗽𝘁𝗶𝗼𝗻::    {} while fetching response for application {}"\
			"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   {}".format(
			error,
			log_obj.application.application_url,
			response_url
		)
		log_obj.status = "Error"
		log_obj.message = error_message
		log_obj.is_completed = True
		log_obj.modified = timezone.now()
		log_obj.save()
		AppNotification.objects.create(
			issue_type='error',
			notification_message=error_message
		)
		response = None
	try:
		if response and response.status_code == 200:
			try:
				response_data = response.json()
			except:
				response_data = None
			try:
				error_message = response_data.get('exception')
			except:
				error_message = None
			if error_message:
				message = "𝗘𝘅𝗰𝗲𝗽𝘁𝗶𝗼𝗻:: {} \n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   {}".format(
					error_message,
					response_url
				)
				log_obj.status="Error"
				log_obj.message=message
				log_obj.modified=timezone.now()
				log_obj.is_completed=True
				log_obj.save()
				return
			return response_data
		elif response.status_code == 400:
			try:
				json_response = response.json()
			except:
				json_response = None
			try:
				response_text = response.text
			except:
				response_text = None
			if json_response and json_response.get('error'):
				error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) +\
					"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + response_url
			elif json_response and not json_response.get('error'):
				error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:   " + str(json_response) +\
					"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + response_url
			elif response:
				error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) +\
					"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + response_url
			elif response_text:
				error_message = "(400 Bad Request).\n𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " +\
					str(response_text) + "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + response_url
			else:
				error_message = "(400 Bad Request)." +\
					"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + response_url
			log_obj.status="Error"
			log_obj.message=error_message
			log_obj.is_completed=True
			log_obj.modified=timezone.now()
			log_obj.save()
			return
		elif response.status_code == 401:
			try:
				json_response = response.json()
			except:
				json_response = None
			try:
				response_text = response.text
			except:
				response_text = None
			if json_response and json_response.get('error'):
				error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) +\
					"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + response_url
			elif json_response and not json_response.get('error'):
				error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:   " + str(json_response) +\
					"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + response_url
			elif response:
				error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) +\
					"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + response_url
			elif response_text:
				error_message = "(401 Unauthorized).\n𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " +\
					str(response_text) + "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + response_url
			else:
				error_message = "(401 Unauthorized)." +\
					"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + response_url
			log_obj.status="Error"
			log_obj.message=error_message
			log_obj.modified=timezone.now()
			log_obj.is_completed=True
			log_obj.save()
			AppNotification.objects.create(
				issue_type='error',
				notification_message=error_message
			)
			return
		elif response.status_code == 404:
			try:
				json_response = response.json()
			except:
				json_response = None
			try:
				response_text = response.text
			except:
				response_text = None
			if json_response and json_response.get('error'):
				error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) +\
					"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + response_url
			elif json_response and not json_response.get('error'):
				error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:   " + str(json_response) +\
					"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + response_url
			elif response:
				error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) +\
					"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + response_url
			elif response_text:
				error_message = "(404 not found).\n𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " +\
					str(response_text) + "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + response_url
			else:
				error_message = "(404 not found)." +\
					"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + response_url
			log_obj.status="Error"
			log_obj.message=error_message,
			log_obj.modified=timezone.now()
			log_obj.is_completed=True
			log_obj.save()
			return
		elif response.status_code == 504:
			try:
				json_response = response.json()
			except:
				json_response = None
			try:
				response_text = response.text
			except:
				response_text = None
			if json_response and json_response.get('error'):
				error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) +\
					"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + response_url
			elif json_response and not json_response.get('error'):
				error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:   " + str(json_response) +\
					"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + response_url
			elif response:
				error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) +\
					"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + response_url
			elif response_text:
				error_message = "(504 Gateway Timeout error).\n𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " +\
					str(response_text) + "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + response_url
			else:
				error_message = "(504 Gateway Timeout error)." +\
					"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + response_url
			log_obj.status="Error"
			log_obj.message=error_message
			log_obj.is_completed=True
			log_obj.modified=timezone.now()
			log_obj.save()
			return
		elif response.status_code == 500:
			try:
				json_response = response.json()
			except:
				json_response = None
			try:
				response_text = response.text
			except:
				response_text = None
			if json_response and json_response.get('error'):
				error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) +\
					"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + response_url
			elif json_response and not json_response.get('error'):
				error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:   " + str(json_response) +\
					"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + response_url
			elif response:
				error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) +\
					"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + response_url
			elif response_text:
				error_message = "(500 Internal Server Error).\n𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " +\
					str(response_text) + "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + response_url
			else:
				error_message = "(500 Internal Server Error)." +\
					"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + response_url
			log_obj.status="Error"
			log_obj.message=error_message
			log_obj.is_completed=True
			log_obj.modified=timezone.now()
			log_obj.save()
			return
		elif response.status_code == 502:
			try:
				json_response = response.json()
			except:
				json_response = None
			try:
				response_text = response.text
			except:
				response_text = None
			if json_response and json_response.get('error'):
				error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) +\
					"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + response_url
			elif json_response and not json_response.get('error'):
				error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:   " + str(json_response) +\
					"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + response_url
			elif response:
				error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) +\
					"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + response_url
			elif response_text:
				error_message = "(502 Bad Gateway).\n𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " +\
					str(response_text) + "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + response_url
			else:
				error_message = "(502 Bad Gateway)." +\
					"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + response_url
			log_obj.status="Error"
			log_obj.message=error_message
			log_obj.is_completed=True
			log_obj.modified=timezone.now()
			log_obj.save()
			return
		else:
			try:
				json_response = response.json()
			except:
				json_response = None
			try:
				response_text = response.text
			except:
				response_text = None
			if json_response and json_response.get('error'):
				error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) +\
					"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + response_url
			elif json_response and not json_response.get('error'):
				error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:   " + str(json_response) +\
					"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + response_url
			elif response:
				error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) +\
					"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + response_url
			elif response_text:
				error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " +\
					str(response_text) + "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + response_url
			else:
				error_message = "There is either a network connection problem "\
					"or the API itself is not returning data."\
					"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + response_url
			log_obj.status="Error"
			log_obj.message=error_message
			log_obj.is_completed=True
			log_obj.modified=timezone.now()
			log_obj.save()
			return
	except Exception as e:
		try:
			json_response = response.json()
		except:
			json_response = None
		try:
			response_text = response.text
		except:
			response_text = None
		if json_response and json_response.get('error'):
			error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) +\
				"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + response_url
		elif json_response and not json_response.get('error'):
			error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:   " + str(json_response) +\
				"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + response_url
		elif response:
			error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) +\
				"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + response_url
		elif response_text:
			error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " +\
				str(response_text) + "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + response_url
		else:
			error_message = "There is either a network connection problem "\
				"or the API itself is not returning data.."\
				"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + response_url
		log_obj.status="Error"
		log_obj.message=error_message
		log_obj.modified=timezone.now()
		log_obj.is_completed=True
		log_obj.save()
		return


def process_encoded_request(request_json):
	request_str = ""
	if request_json:
		for req in request_json:
			encode_str = req.get('data')
			if encode_str:
				raw_str = base64.b64decode(encode_str)
				try:
					raw_str.decode('utf-8')
					request_str = "{}{}".format(request_str, raw_str)
				except UnicodeDecodeError, UnicodeError:
					response_str = "{}\n{}".format(response_str, encode_str)
				except:
					sentry_client.captureException()
	return request_str.replace('\x00', '')


def process_encoded_response(response_json):
	response_str = ""
	if response_json:
		for res in response_json:
			encode_str = res.get('data')
			if encode_str:
				raw_str = base64.b64decode(encode_str)
				try:
					raw_str.decode('utf-8')
					response_str = "{}{}".format(response_str, raw_str)
				except UnicodeDecodeError, UnicodeError:
					response_str = "{}\n{}".format(response_str, encode_str)
				except:
					sentry_client.captureException()
	return response_str.replace('\x00', '')


def process_evidence(app_scan_obj, evidence_list):
	for evidence in evidence_list:
		request_response = evidence.get("request_response")
		if request_response:
			url = request_response.get("url")
			if url:
				encoded_request = request_response.get("request")
				encoded_response = request_response.get("response")
				request_str = process_encoded_request(encoded_request)
				response_str = process_encoded_response(encoded_response)
				BurpEvidence.objects.create(
					issue = app_scan_obj,
					url = url,
					request = request_str,
					response = response_str
					)


def update_pending_application_scans():
	log_objs = LogMicroServiceBurp.objects.filter(
		status="Running"
	)
	for log_obj in log_objs:
		if log_obj.status == "Running" and log_obj.scan_id and log_obj.appliance\
				and log_obj.application:
			try:
				scan_obj = ApplicationScans.objects.get(scan_id=log_obj.scan_id)
			except:
				scan_obj = None
			try:
				appliance_obj = Appliances.objects.get(id=log_obj.appliance)
			except:
				appliance_obj = None
			if appliance_obj and scan_obj and appliance_obj.network_type ==\
					log_obj.application.network_type:
				appliance_setting = appliance_obj.appliance_setting
				scan_url = appliance_setting.burp_url
				parsed_uri = urlparse(scan_url)
				domain = '{uri.scheme}://{uri.netloc}/{prefix}'.format(
					uri=parsed_uri,
					prefix="burp/scan/"
				)
				status_url = "{}{}/status".format(
					domain,
					log_obj.scan_id
				)
				status_curl = "curl -u {}:{} --request GET {}".format(
					appliance_setting.auth_username,
					appliance_setting.auth_password,
					status_url
				)
				try:
					response = requests.get(
						status_url,
						auth=(
							appliance_setting.auth_username,
							appliance_setting.auth_password
						),
						timeout=240
					)
				except requests.Timeout as timeout_exc:
					message="𝗘𝘅𝗰𝗲𝗽𝘁𝗶𝗼𝗻::  {} while fetching response for application {}"\
						"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   {}".format(
							timeout_exc,
							log_obj.application.application_url,
							status_curl
						)
					AppNotification.objects.create(
						issue_type='error',
						notification_message=message
					)
					log_obj.status="Error"
					log_obj.message=message
					log_obj.is_completed=True
					log_obj.modified=timezone.now()
					log_obj.save()
					response = None
				except Exception as error:
					error_message = "𝗘𝘅𝗰𝗲𝗽𝘁𝗶𝗼𝗻::    {} while fetching response for "\
						"application {} \n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   {}".format(
						error,
						log_obj.application.application_url,
						status_curl
					)
					log_obj.status = "Error"
					log_obj.message = error_message
					log_obj.is_completed = True
					log_obj.modified = timezone.now()
					log_obj.save()
					AppNotification.objects.create(
						issue_type='error',
						notification_message=error_message
					)
					response = None
				try:
					if response and response.status_code == 200:
						try:
							response_data = response.json()
						except:
							response_data = None
						try:
							error_message = response_data.get('exception')
						except:
							error_message = None
						if error_message:
							message = "𝗘𝘅𝗰𝗲𝗽𝘁𝗶𝗼𝗻:: {} \n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   {}".format(
								error_message,
								status_curl
							)
							log_obj.status="Error"
							log_obj.message=message
							log_obj.modified=timezone.now()
							log_obj.is_completed=True
							log_obj.save()
					elif response.status_code == 400:
						try:
							json_response = response.json()
						except:
							json_response = None
						try:
							response_text = response.text
						except:
							response_text = None
						if json_response and json_response.get('error'):
							error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) +\
								"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
						elif json_response and not json_response.get('error'):
							error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:   " + str(json_response) +\
								"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
						elif response:
							error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) +\
								"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
						elif response_text:
							error_message = "(400 Bad Request).\n𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " +\
								str(response_text) + "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
						else:
							error_message = "(400 Bad Request)." +\
								"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
						log_obj.status="Error"
						log_obj.message=error_message
						log_obj.is_completed=True
						log_obj.modified=timezone.now()
						log_obj.save()
						return
					elif response.status_code == 401:
						try:
							json_response = response.json()
						except:
							json_response = None
						try:
							response_text = response.text
						except:
							response_text = None
						if json_response and json_response.get('error'):
							error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) +\
								"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
						elif json_response and not json_response.get('error'):
							error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:   " + str(json_response) +\
								"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
						elif response:
							error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) +\
								"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
						elif response_text:
							error_message = "(401 Unauthorized).\n𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " +\
								str(response_text) + "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
						else:
							error_message = "(401 Unauthorized)." +\
								"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
						log_obj.status="Error"
						log_obj.message=error_message
						log_obj.modified=timezone.now()
						log_obj.is_completed=True
						log_obj.save()
						AppNotification.objects.create(
							issue_type='error',
							notification_message=error_message
						)
						return
					elif response.status_code == 404:
						try:
							json_response = response.json()
						except:
							json_response = None
						try:
							response_text = response.text
						except:
							response_text = None
						if json_response and json_response.get('error'):
							error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) +\
								"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
						elif json_response and not json_response.get('error'):
							error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:   " + str(json_response) +\
								"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
						elif response:
							error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) +\
								"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
						elif response_text:
							error_message = "(404 not found).\n𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " +\
								str(response_text) + "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
						else:
							error_message = "(404 not found)." +\
								"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
						log_obj.status="Error"
						log_obj.message=error_message,
						log_obj.modified=timezone.now()
						log_obj.is_completed=True
						log_obj.save()
						return
					elif response.status_code == 504:
						try:
							json_response = response.json()
						except:
							json_response = None
						try:
							response_text = response.text
						except:
							response_text = None
						if json_response and json_response.get('error'):
							error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) +\
								"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
						elif json_response and not json_response.get('error'):
							error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:   " + str(json_response) +\
								"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
						elif response:
							error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) +\
								"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
						elif response_text:
							error_message = "(504 Gateway Timeout error).\n𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " +\
								str(response_text) + "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
						else:
							error_message = "(504 Gateway Timeout error)." +\
								"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
						log_obj.status="Error"
						log_obj.message=error_message
						log_obj.is_completed=True
						log_obj.modified=timezone.now()
						log_obj.save()
						return
					elif response.status_code == 500:
						try:
							json_response = response.json()
						except:
							json_response = None
						try:
							response_text = response.text
						except:
							response_text = None
						if json_response and json_response.get('error'):
							error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) +\
								"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
						elif json_response and not json_response.get('error'):
							error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:   " + str(json_response) +\
								"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
						elif response:
							error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) +\
								"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
						elif response_text:
							error_message = "(500 Internal Server Error).\n𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " +\
								str(response_text) + "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
						else:
							error_message = "(500 Internal Server Error)." +\
								"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
						log_obj.status="Error"
						log_obj.message=error_message
						log_obj.is_completed=True
						log_obj.modified=timezone.now()
						log_obj.save()
						return
					elif response.status_code == 502:
						try:
							json_response = response.json()
						except:
							json_response = None
						try:
							response_text = response.text
						except:
							response_text = None
						if json_response and json_response.get('error'):
							error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) +\
								"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
						elif json_response and not json_response.get('error'):
							error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:   " + str(json_response) +\
								"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
						elif response:
							error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) +\
								"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
						elif response_text:
							error_message = "(502 Bad Gateway).\n𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " +\
								str(response_text) + "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
						else:
							error_message = "(502 Bad Gateway)." +\
								"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
						log_obj.status="Error"
						log_obj.message=error_message
						log_obj.is_completed=True
						log_obj.modified=timezone.now()
						log_obj.save()
						return
					else:
						try:
							json_response = response.json()
						except:
							json_response = None
						try:
							response_text = response.text
						except:
							response_text = None
						if json_response and json_response.get('error'):
							error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) +\
								"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
						elif json_response and not json_response.get('error'):
							error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:   " + str(json_response) +\
								"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
						elif response:
							error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) +\
								"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
						elif response_text:
							error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " +\
								str(response_text) + "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
						else:
							error_message = "There is either a network connection problem "\
								"or the API itself is not returning data."\
								"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
						log_obj.status="Error"
						log_obj.message=error_message
						log_obj.is_completed=True
						log_obj.modified=timezone.now()
						log_obj.save()
						return
				except Exception as e:
					try:
						json_response = response.json()
					except:
						json_response = None
					try:
						response_text = response.text
					except:
						response_text = None
					if json_response and json_response.get('error'):
						error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) +\
							"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
					elif json_response and not json_response.get('error'):
						error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:   " + str(json_response) +\
							"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
					elif response:
						error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) +\
							"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
					elif response_text:
						error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " +\
							str(response_text) + "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
					else:
						error_message = "There is either a network connection problem "\
							"or the API itself is not returning data.."\
							"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
					log_obj.status="Error"
					log_obj.message=error_message
					log_obj.modified=timezone.now()
					log_obj.is_completed=True
					log_obj.save()
					return
				if response_data and response_data.get('status') != "PENDING":
					if response_data and response_data.get('status') == "COMPLETED":
						application_obj = log_obj.application
						result_uri = response_data.get("result_uri")
						result_domain = '{uri.scheme}://{uri.netloc}/{prefix}'.format(
							uri=parsed_uri,
							prefix="burp"
						)
						result_url = "{}{}".format(
							result_domain,
							result_uri
						)
						response_curl = "curl -u {}:{} --request GET {}".format(
							appliance_setting.auth_username,
							appliance_setting.auth_password,
							result_url
						)
						log = "scan completed can check the result by url\n{}".format(result_url)
						log_obj.status="Completed"
						log_obj.message=log
						log_obj.modified=timezone.now()
						result = get_application_scan_result(
							result_url,
							response_curl,
							appliance_setting.auth_username,
							appliance_setting.auth_password,
							log_obj
							)
						issues = result.get('results').get('issue_events')
						issues_len = 0
						for issue_list in issues:
							issue = issue_list.get('issue')
							origin = issue.get('origin')
							confidence = issue.get('confidence')
							name = issue.get('name')
							description = issue.get('description')
							caption = issue.get('caption')
							type_index = issue.get('type_index')
							internal_data = issue.get('internal_data')
							path = issue.get('path')
							serial_number = issue.get('serial_number')
							severity = issue.get('severity')
							evidence_list = issue.get('evidence')
							if not ApplicationScanData.objects.filter(
									origin=origin,
									confidence=confidence,
									name=name,
									description=description,
									caption=caption,
									type_index=type_index,
									internal_data=internal_data,
									path=path,
									severity=severity
								) and ApplicationScanData.objects.filter(
									origin=origin,
									application_fk=application_obj,
									name=name
								).count() <= 25:
								app_scan_obj = ApplicationScanData.objects.create(
									application=scan_obj,
									application_fk=application_obj,
									origin=origin,
									confidence=confidence,
									name=name,
									description=description,
									caption=caption,
									type_index=type_index,
									internal_data=internal_data,
									path=path,
									serial_number=serial_number,
									severity=severity,
								)
								issues_len += 1
								if evidence_list:
									process_evidence(
										app_scan_obj,
										evidence_list
									)
							scan_obj.scan_status = False
							scan_obj.save()
						if issues_len > 0:
							result = "{} issues discovered.".format(issues_len)
							log = "scan completed and {} subdomains discovered.".format(issues_len)
						else:
							result = "No issues discovered."
							log = "scan completed and no new issues discovered."
						log_obj.status="Completed"
						log_obj.message=log
						log_obj.is_completed=True
						log_obj.result=result
						log_obj.modified=timezone.now()
						log_obj.save()
						application_obj.last_scan = timezone.now()
						application_obj.save()
						processBurpData('cron_job')
					elif response_data and response_data.get('status') == "FAILED":
						try:
							json_response = response_data
						except:
							json_response = None
						try:
							response_text = response.text
						except:
							response_text = None
						if json_response and json_response.get('error'):
							error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) +\
								"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
						elif json_response and not json_response.get('error'):
							error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:   " + str(json_response) +\
								"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
						elif response:
							error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) +\
								"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
						elif response_text:
							error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response_text) +\
								"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
						else:
							error_message = "There is either a network connection problem "\
								"or the API itself is not returning data.." +\
								"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
						log_obj.status="Completed"
						log_obj.message=error_message
						log_obj.is_completed=True
						log_obj.modified=timezone.now()
						log_obj.save()
						scan_obj.scan_status = False
						scan_obj.save()
					else:
						try:
							json_response = response_data
						except:
							json_response = None
						try:
							response_text = response.text
						except:
							response_text = None
						if json_response and json_response.get('error'):
							error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) +\
								"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
						elif json_response and not json_response.get('error'):
							error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:   " + str(json_response) +\
								"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
						elif response:
							error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) +\
								"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
						elif response_text:
							error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response_text) +\
								"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
						else:
							error_message = "There is either a network connection problem "\
								"or the API itself is not returning data.." +\
								"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + status_curl
						log_obj.status="Completed"
						log_obj.message=error_message
						log_obj.is_completed=True
						log_obj.modified=timezone.now()
						log_obj.save()
						AppNotification.objects.create(
							issue_type='error',
							notification_message="Scan Failed for application {}. {}".format(
								scan_obj.application,
								error_message
							)
						)
						scan_obj.scan_status = False
						scan_obj.save()
