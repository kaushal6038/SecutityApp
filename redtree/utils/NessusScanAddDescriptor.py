# -*- coding: utf-8 -*-
import requests
import json
from redtree_app.models import *
from utils.scans_helpers import get_nessus_ips
from utils.helpers import (
	get_appliance
)
from urlparse import urlparse

from celery.utils.log import get_task_logger

logger = get_task_logger(__name__)


class NessusScanAddDescriptor(object):
	"""docstring for NessusScanAddDescriptor"""
	def __init__(self, task_id, appliance, ips, network_type):

		print 'appliance',appliance,'????',appliance.id
		logger.info('nessus scan started')
		log_obj = LogMicroServiceNessus.objects.create(
			ips=ips,
			network_type=network_type,
			appliance=appliance.appliance.id,
			task_id=task_id,
			status="Queued"
		)
		self.nessus_logging = LogMicroServiceNessus.objects.filter(id=log_obj.id)
		self.client_conf_obj = ClientConfiguration.objects.first()
		self.client_name = self.client_conf_obj.client_name
		self.ips = ips
		self.scan_url = appliance.nessus_driver_url
		self.auth_username = appliance.auth_username
		self.auth_password = appliance.auth_password
		self.appliance_retry = 0
		self.retry = 0
		curl_scan_url = self.scan_url + "create-scan/"
		curl_request_data = {
			"client_name": self.client_name,
			"targets": self.ips,
			"policy_name": "basic"
		}
		self.curl_request = "curl -u {}:{} --header 'Content-Type: application/json' "\
			"--request POST --data '{}' {}".format(
				self.auth_username,
				self.auth_password,
				json.dumps(curl_request_data),
				curl_scan_url
			)

	def create_nessus_scan(self):
		if not self.ips:
			self.nessus_logging.update(
                status="Completed",
                message="No hosts for scanning",
                is_completed=True,
                modified=timezone.now(),
                duration=timezone.now()
            )
			return

		try:
			request_header = {
				"Content-Type": "application/json"
			}
			request_data = {
				"client_name": self.client_name,
				"targets": self.ips,
				"policy_name": "basic"
			}
			url = self.scan_url + "create-scan/"
			response = requests.post(
				url,
				auth=(self.auth_username, self.auth_password),
				json = request_data,
				headers = request_header,
				timeout = 180
			)
			print 'response::',response
		except requests.Timeout as timeout_exc:
			self.appliance_retry = self.appliance_retry + 1
			print 'appliance_retry::',self.appliance_retry
			if self.appliance_retry < 4:
				error_message = "𝗘𝘅𝗰𝗲𝗽𝘁𝗶𝗼𝗻::  {} in nessus scan."\
					"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::  {}".format(
						timeout_exc,
						self.curl_request
					)
				print 'error_message',error_message
				# logger.error("{}".format(error_message))
				time.sleep(30)
				self.create_nessus_scan()
			elif self.appliance_retry >= 4:
				error_message = "𝗘𝘅𝗰𝗲𝗽𝘁𝗶𝗼𝗻::  {} in nessus scan."\
					"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::  {}".format(
						timeout_exc,
						self.curl_request
					)
				# logger.error("{}".format(error_message))
				print 'error_message',error_message
				self.nessus_logging.update(
	                status="Error",
	                message=error_message,
	                is_completed=True,
	                modified=timezone.now(),
	                duration=timezone.now()
	            )
				AppNotification.objects.create(
					issue_type='error',
					notification_message=error_message
				)
			response = None
			return
		except Exception as error:
			print 'Exception',error
			error_message = "𝗘𝘅𝗰𝗲𝗽𝘁𝗶𝗼𝗻::  {} in nessus scan."\
				"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::  {}".format(
					error,
					self.curl_request
				)
			# logger.error("{}".format(error_message))
			print 'error_message',error_message
			self.nessus_logging.update(
                status="Error",
                message=error_message,
                is_completed=True,
                modified=timezone.now(),
                duration=timezone.now()
            )
			AppNotification.objects.create(
				issue_type='error',
				notification_message=error_message
			)
			response = None
			return
		print 'response:=',response
		print 'response:====',response.text
		try:
			if response and response.status_code == 201:
				response_data = response.json()
				status_url = "{}get-status/{}".format(
					self.scan_url,
					response_data.get("scan_id")
				)
				status_curl = "curl -u {}:{} --request GET {}".format(
					self.auth_username,
					self.auth_password,
					status_url
				)
				log = "Scan added can check the status by 𝗖𝘂𝗿𝗹:: \n{}".format(
					status_curl
				)
				self.nessus_logging.update(
					status="Running",
					message=log,
					scan_id=response_data.get("scan_id"),
					modified=timezone.now(),
					duration=timezone.now()
				)
				logger.info(
					"scan generated successfull. Status url = {}".format(
						status_curl
					)
				)
			elif response.status_code == 401:
				try:
					json_response = response
				except:
					json_response = None
				if json_response and json_response.get('error'):
					error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) +\
						"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + self.curl_request
				elif json_response and not json_response.get('error'):
					error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:   " + str(json_response) +\
						"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + self.curl_request
				elif response:
					error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) +\
						"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + self.curl_request
				elif response.text:
					error_message = "(401 Unauthorized).\n𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " +\
						str(response.text) + "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + self.curl_request
				else:
					error_message = "(401 Unauthorized)." +\
						"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + self.curl_request
				# logger.info("{}".format(error_message))
				print 'error_message',error_message
				self.nessus_logging.update(
					status="Error",
					message=error_message,
					modified=timezone.now(),
					is_completed=True,
					duration=timezone.now()
				)
				AppNotification.objects.create(
					issue_type='error',
					notification_message=error_message
				)
				return
			elif response.status_code == 404:
				try:
					json_response = response
				except:
					json_response = None
				if json_response and json_response.get('error'):
					error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) +\
						"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + self.curl_request
				elif json_response and not json_response.get('error'):
					error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:   " + str(json_response) +\
						"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + self.curl_request
				elif response:
					error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) +\
						"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + self.curl_request
				elif response.text:
					error_message = "(404 not found).\n𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " +\
						str(response.text) + "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + self.curl_request
				else:
					error_message = "(404 not found)." +\
						"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + self.curl_request
				self.nessus_logging.update(
					status="Error",
					message=error_message,
					modified=timezone.now(),
					is_completed=True,
					duration=timezone.now()
				)
				# logger.error(error_message)
				print 'error_message',error_message
				return
			elif response.status_code == 400:
				try:
					json_response = response
				except:
					json_response = None
				if json_response and json_response.get('error'):
					error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) +\
						"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + self.curl_request
				elif json_response and not json_response.get('error'):
					error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:   " + str(json_response) +\
						"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + self.curl_request
				elif response:
					error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) +\
						"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + self.curl_request
				elif response.text:
					error_message = "(400 Bad Request).\n𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " +\
						str(response.text) + "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + self.curl_request
				else:
					error_message = "(400 Bad Request)." +\
						"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + self.curl_request
				self.nessus_logging.update(
					status="Error",
					message=error_message,
					modified=timezone.now(),
					is_completed=True,
					duration=timezone.now()
				)
				# logger.error(error_message)
				print 'error_message',error_message
				return
			elif response.status_code == 500:
				try:
					json_response = response
				except:
					json_response = None
				if json_response and json_response.get('error'):
					error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) +\
						"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + self.curl_request
				elif json_response and not json_response.get('error'):
					error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:   " + str(json_response) +\
						"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + self.curl_request
				elif response:
					error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) +\
						"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + self.curl_request
				elif response.text:
					error_message = "(500 Internal Server Error).\n𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " +\
						str(response.text) + "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + self.curl_request
				else:
					error_message = "(500 Internal Server Error)." +\
						"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + self.curl_request
				self.nessus_logging.update(
					status="Error",
					message=error_message,
					modified=timezone.now(),
					is_completed=True,
					duration=timezone.now()
				)
				# logger.error(error_message)
				print 'error_message',error_message
				return
			elif response.status_code == 504:
				try:
					json_response = response
				except:
					json_response = None
				if json_response and json_response.get('error'):
					error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) +\
						"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + self.curl_request
				elif json_response and not json_response.get('error'):
					error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:   " + str(json_response) +\
						"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + self.curl_request
				elif response:
					error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) +\
						"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + self.curl_request
				elif response.text:
					error_message = "(504 Gateway Timeout error).\n𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " +\
						str(response.text) + "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + self.curl_request
				else:
					error_message = "(504 Gateway Timeout error)." +\
						"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + self.curl_request
				# logger.error(error_message)
				print 'error_message',error_message
				self.nessus_logging.update(
					status="Error",
					message=error_message,
					is_completed=True,
					modified=timezone.now(),
					duration=timezone.now()
				)
				return
			elif response.status_code == 502:
				try:
					json_response = response
				except:
					json_response = None
				if json_response and json_response.get('error'):
					error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) +\
						"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + self.curl_request
				elif json_response and not json_response.get('error'):
					error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:   " + str(json_response) +\
						"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + self.curl_request
				elif response:
					error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) +\
						"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + self.curl_request
				elif response.text:
					error_message = "(502 Bad Gateway).\n𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " +\
						str(response.text) + "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + self.curl_request
				else:
					error_message = "(502 Bad Gateway)." +\
						"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + self.curl_request
				# logger.error(error_message)
				print 'error_message',error_message
				self.nessus_logging.update(
					status="Error",
					message=error_message,
					is_completed=True,
					modified=timezone.now(),
					duration=timezone.now()
				)
				return
			else:
				try:
					json_response = response
				except:
					json_response = None
				if json_response and json_response.get('error'):
					error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) +\
						"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + self.curl_request
				elif json_response and not json_response.get('error'):
					error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:   " + str(json_response) +\
						"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + self.curl_request
				elif response:
					error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) +\
						"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + self.curl_request
				elif response.text:
					error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response.text) +\
						"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + self.curl_request
				else:
					error_message = "There is either a network connection problem "\
						"or the API itself is not returning data."\
						"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + self.curl_request
				self.nessus_logging.update(
					status="Error",
					message=error_message,
					modified=timezone.now(),
					is_completed=True,
					duration=timezone.now()
				)
				# logger.error(error_message)
				print 'error_message',error_message
				return
		except Exception as e:
			print "Exception::..",e
			try:
				json_response = response
			except:
				json_response = None
			if json_response and json_response.get('error'):
				error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) +\
					"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + self.curl_request
			elif json_response and not json_response.get('error'):
				error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:   " + str(json_response) +\
					"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + self.curl_request
			elif response:
				error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) +\
					"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + self.curl_request
			elif response.text:
				error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response.text) +\
					"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + self.curl_request
			else:
				error_message = "There is either a network connection problem "\
					"or the API itself is not returning data.."\
					"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + self.curl_request
			self.nessus_logging.update(
				status="Error",
				message=error_message,
				modified=timezone.now(),
				is_completed=True,
				duration=timezone.now()
			)
			# logger.error(error_message)
			print 'error_message',error_message
			return


def external_nessus_scan(task_id):
	ips = get_nessus_ips()
	external_ips = ips.get('external_ips')
	external_appliances = Appliances.objects.filter(network_type="External")
	for appliance in external_appliances:
		appliance_settings = appliance.appliance_setting
		scan_helper = NessusScanAddDescriptor(
			task_id,
			appliance_settings,
			external_ips,
			"External"
		)
		scan_helper.create_nessus_scan()


def internal_nessus_scan(task_id):
	ips = get_nessus_ips()
	internal_ips = ips.get('internal_ips')
	internal_appliances = get_appliance("Internal")
	appliance_settings = internal_appliances.appliance_setting
	scan_helper = NessusScanAddDescriptor(
		task_id,
		appliance_settings,
		internal_ips,
		"Internal"
	)
	scan_helper.create_nessus_scan()


def nessus_scan(task_id):
	ips = get_nessus_ips()
	external_ips = ips.get('external_ips')
	internal_ips = ips.get('internal_ips')
	external_appliances = get_appliance("External")
	internal_appliances = get_appliance("Internal")
	if external_appliances:
		appliance_settings = external_appliances.appliance_setting
		ext_scan_helper = NessusScanAddDescriptor(
			task_id,
			appliance_settings,
			external_ips,
			"External"
		)
		ext_scan_helper.create_nessus_scan()

	if internal_appliances:
		appliance_settings = internal_appliances.appliance_setting
		int_scan_helper = NessusScanAddDescriptor(
			task_id,
			appliance_settings,
			internal_ips,
			"Internal"
		)
		int_scan_helper.create_nessus_scan()
