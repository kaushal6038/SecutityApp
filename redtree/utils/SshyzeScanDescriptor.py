from request_ip import get_request_ip
import requests
import json
from urlparse import urlparse
import time
from redtree_app.models import *
from playground.models import *
from django.utils import timezone
from utils.scans_helpers import (
    get_ip_type,
)
from utils.helpers import (
	get_appliance
)
from celery.utils.log import get_task_logger

logger = get_task_logger(__name__)


class SshyzeScanDescriptor:

	def __init__(self, task_id, appliance_obj, host, port):
		logger.info('sshyze scan started for {} and {}'.format(host, port))
		log_obj = LogMicroServiceSshyze.objects.create(
			host=host,
			port=int(port),
			status="Queued",
			task_id=task_id,
            appliance=appliance_obj.id
		)
		self.appliance_ip = appliance_obj.appliance_ip
		self.sshyze_logging = LogMicroServiceSshyze.objects.filter(id=log_obj.id)
		self.host = host
		self.port = port
		self.scan_url = appliance_obj.appliance_setting.sshyze_scan_url
		self.auth_username = appliance_obj.appliance_setting.auth_username
		self.auth_password = appliance_obj.appliance_setting.auth_password
		self.parsed_uri = urlparse(self.scan_url)
		self.domain = '{uri.scheme}://{uri.netloc}/{prefix}'.format(
			uri=self.parsed_uri, 
			prefix='sshyze'
		)


	def get_status(self, url):
		status_curl = "curl -u {}:{} --request GET {}".format(
			self.auth_username,
			self.auth_password,
			url
		)
		print status_curl
		try:
			response = requests.get(url, 
				auth=(self.auth_username, self.auth_password),
				timeout=240
			)
		except requests.Timeout as timeout_exc:
			error_message = "error in getting response for sshyze scan due to Maximum"\
                "connect time limit exceeded.Curl is {}".format(
				status_curl
			)
			# error_message = "Appliance is taking too long to respond."
			logger.error('{}'.format(error_message))
			AppNotification.objects.create(
				issue_type='error',
				notification_message=error_message
			)
			self.sshyze_logging.update(
				status="Error",
				message=error_message,
				is_completed=True,
				modified=timezone.now()
			)
			return
		except Exception as error:
			error_message = "error {} in getting response for sshyze scan.Curl is: {}".format(
				error,
				status_curl
			)
			logger.error('{}'.format(error_message))
			AppNotification.objects.create(
				issue_type='error',
				notification_message=error_message
			)
			self.sshyze_logging.update(
				status="Error",
				message=error_message,
				is_completed=True,
				modified=timezone.now()
			)
			return

		try:
			if response.status_code == 200:
				status = response.json()
				try:
					error_message = status.get('exception')
				except:
					error_message = None
				if error_message:
					message = "Exception:: {}, Curl is: {}".format(
						error_message,
						status_curl
					)
					self.sshyze_logging.update(
						status="Error",
						message=message,
						modified=timezone.now(),
						is_completed=True
					)
					return
				return status
			elif response.status_code == 400:
				try:
					json_response = response.json()
				except:
					json_response = None
				if json_response and json_response.get('error'):
					error_message = json_response.get('error') + " Curl request is: " + status_curl
				elif json_response and not json_response.get('error'):
					error_message = json_response + " Curl request is: " + status_curl
				elif response:
					error_message = response + " Curl request is: " + status_curl
				else:
					error_message = "(400 Bad Request). Curl request "\
						"is: " + status_curl
				self.sshyze_logging.update(
					status="Error",
					message=error_message,
					modified=timezone.now(),
					is_completed=True
				)
				logger.error(error_message)
				return
			elif response.status_code == 401:
				try:
					json_response = response.json()
				except:
					json_response = None
				if json_response and json_response.get('error'):
					error_message = json_response.get('error') + " Curl request is: " + status_curl
				elif json_response and not json_response.get('error'):
					error_message = json_response + " Curl request is: " + status_curl
				elif response:
					error_message = response + " Curl request is: " + status_curl
				else:
					error_message = "(401 Unauthorized). Curl request "\
						"is: " + status_curl
				logger.info("{}".format(error_message))
				self.sshyze_logging.update(
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
				if json_response and json_response.get('error'):
					error_message = json_response.get('error') + " Curl request is: " + status_curl
				elif json_response and not json_response.get('error'):
					error_message = json_response + " Curl request is: " + status_curl
				elif response:
					error_message = response + " Curl request is: " + status_curl
				else:
					error_message = "(404 not found). Curl request "\
						"is: " + status_curl
				self.sshyze_logging.update(
					status="Error",
					message=error_message,
					modified=timezone.now(),
					is_completed=True
				)
				logger.error(error_message)
				return
			elif response.status_code == 500:
				try:
					json_response = response.json()
				except:
					json_response = None
				if json_response and json_response.get('error'):
					error_message = json_response.get('error') + " Curl request is: " + status_url
				elif json_response and not json_response.get('error'):
					error_message = json_response + " Curl request is: " + status_url
				elif response:
					error_message = response + " Curl request is: " + status_url
				else:
					error_message = "(500 Internal Server Error). Curl request "\
						"is: " + status_url
				self.sshyze_logging.update(
					status="Error",
					message=error_message,
					modified=timezone.now(),
					is_completed=True
				)
				logger.error(error_message)
				return
			elif response.status_code == 504:
				try:
					json_response = response.json()
				except:
					json_response = None
				if json_response and json_response.get('error'):
					error_message = json_response.get('error') + " Curl request is: " + status_curl
				elif json_response and not json_response.get('error'):
					error_message = json_response + " Curl request is: " + status_curl
				elif response:
					error_message = response + " Curl request is: " + status_curl
				else:
					error_message = "(504 Gateway Timeout error). Curl request "\
						"is: " + status_curl
				logger.error(error_message)
				self.sshyze_logging.update(
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
				if json_response and json_response.get('error'):
					error_message = json_response.get('error') + " Curl request is: " + status_curl
				elif json_response and not json_response.get('error'):
					error_message = json_response + " Curl request is: " + status_curl
				elif response:
					error_message = response + " Curl request is: " + status_curl
				else:
					error_message = "There is either a network connection problem "\
						"or the API itself is not returning data. Curl request "\
						"is: " + status_curl
				self.sshyze_logging.update(
					status="Error",
					message=error_message,
					modified=timezone.now(),
					is_completed=True
				)
				logger.error(error_message)
				return
		except Exception as e:
			print "Exception::..",e
			try:
				json_response = response.json()
			except:
				json_response = None
			if json_response and json_response.get('error'):
				error_message = json_response.get('error') + " Curl request is: " + status_curl
			elif json_response and not json_response.get('error'):
				error_message = json_response + " Curl request is: " + status_curl
			elif response:
				error_message = response + " Curl request is: " + status_curl
			else:
				error_message = "There is either a network connection problem "\
					"or the API itself is not returning data.. Curl request "\
					"is: " + status_curl
			self.sshyze_logging.update(
				status="Error",
				message=error_message,
				modified=timezone.now(),
				is_completed=True
			)
			logger.error(error_message)
			return

	def create_sshyze_cipher_scan(self):
		request_data = {
			"host": self.host,
			"port": self.port
		}
		create_curl_req = "curl -u {}:{} --header 'Content-Type: application/json' "\
			"--request POST --data '{}' {}".format(
				self.auth_username,
				self.auth_password,
				json.dumps(request_data),
				self.scan_url
			)
		print "create_curl_req", create_curl_req
		try:
			request_header = {
				"Content-Type": "application/json"
			}
			response = requests.post(
				self.scan_url,
				auth=(self.auth_username, self.auth_password), 
				headers=request_header, 
				json=request_data,
				timeout=240
			)
		except requests.Timeout as timeout_exc:
			error_message = "Maximum connect time exceeded on appliance {} for Sshyze for "\
				"scanning {} and {}".format(
				self.appliance_ip,
				self.host,
				self.port
			)
			logger.error("{}".format(error_message))
			self.sshyze_logging.update(
                status="Error",
                message=error_message,
                is_completed=True,
                modified=timezone.now()
            )
			AppNotification.objects.create(
				issue_type='error',
				notification_message=error_message
			)
			return
		except Exception as error:
			error_message = "error {} in sshyze scan.Curl request is {}.".format(
				error,
				create_curl_req
			)
			logger.error("{}".format(error_message))
			self.sshyze_logging.update(
                status="Error",
                message=error_message,
                is_completed=True,
                modified=timezone.now()
            )
			AppNotification.objects.create(
				issue_type='error',
				notification_message=error_message
			)
			return
		try:
			if response.status_code == 200:
				response_data = response.json()
				try:
					error_message = response_data.get('exception')
				except:
					error_message = None
				if error_message:
					message = "Exception :: {}.Curl is {}.".format(
						error_message,
						create_curl_req
					)
					self.sshyze_logging.update(
						status="Error",
						message=message,
						modified=timezone.now(),
						is_completed=True
					)
					return
				status_url = self.domain + response_data.get("status_uri")
				log = "scan added can check the status by status_url {}".format(status_url)
				self.sshyze_logging.update(
					status="Running",
					message=log,
					modified=timezone.now(),
					scan_id=response_data.get("scan_id")
				)
				logger.info("scan generated status url = {}".format(status_url))
				self.process_sshyze_cipher_scan(status_url)
			elif response.status_code == 400:
				try:
					json_response = response.json()
				except:
					json_response = None
				if json_response and json_response.get('error'):
					error_message = json_response.get('error') + " Curl request is: " + create_curl_req
				elif json_response and not json_response.get('error'):
					error_message = json_response + " Curl request is: " + create_curl_req
				elif response:
					error_message = response + " Curl request is: " + create_curl_req
				else:
					error_message = "(400 Bad Request). Curl request "\
						"is: " + create_curl_req
				self.sshyze_logging.update(
					status="Error",
					message=error_message,
					modified=timezone.now(),
					is_completed=True
				)
				logger.error(error_message)
				return
			elif response.status_code == 401:
				try:
					json_response = response.json()
				except:
					json_response = None
				if json_response and json_response.get('error'):
					error_message = json_response.get('error') + " Curl request is: " + create_curl_req
				elif json_response and not json_response.get('error'):
					error_message = json_response + " Curl request is: " + create_curl_req
				elif response:
					error_message = response + " Curl request is: " + create_curl_req
				else:
					error_message = "(401 Unauthorized). Curl request "\
						"is: " + create_curl_req
				logger.info("{}".format(error_message))
				self.sshyze_logging.update(
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
				if json_response and json_response.get('error'):
					error_message = json_response.get('error') + " Curl request is: " + create_curl_req
				elif json_response and not json_response.get('error'):
					error_message = json_response + " Curl request is: " + create_curl_req
				elif response:
					error_message = response + " Curl request is: " + create_curl_req
				else:
					error_message = "(404 not found). Curl request "\
						"is: " + create_curl_req
				self.sshyze_logging.update(
					status="Error",
					message=error_message,
					modified=timezone.now(),
					is_completed=True
				)
				logger.error(error_message)
				return
			elif response.status_code == 500:
				try:
					json_response = response.json()
				except:
					json_response = None
				if json_response and json_response.get('error'):
					error_message = json_response.get('error') + " Curl request is: " + create_curl_req
				elif json_response and not json_response.get('error'):
					error_message = json_response + " Curl request is: " + create_curl_req
				elif response:
					error_message = response + " Curl request is: " + create_curl_req
				else:
					error_message = "(500 Internal Server Error). Curl request "\
						"is: " + create_curl_req
				self.sshyze_logging.update(
					status="Error",
					message=error_message,
					modified=timezone.now(),
					is_completed=True
				)
				logger.error(error_message)
				return
			elif response.status_code == 504:
				try:
					json_response = response.json()
				except:
					json_response = None
				if json_response and json_response.get('error'):
					error_message = json_response.get('error') + " Curl request is: " + create_curl_req
				elif json_response and not json_response.get('error'):
					error_message = json_response + " Curl request is: " + create_curl_req
				elif response:
					error_message = response + " Curl request is: " + create_curl_req
				else:
					error_message = "(504 Gateway Timeout error). Curl request "\
						"is: " + create_curl_req
				logger.error(error_message)
				self.sshyze_logging.update(
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
				if json_response and json_response.get('error'):
					error_message = json_response.get('error') + " Curl request is: " + create_curl_req
				elif json_response and not json_response.get('error'):
					error_message = json_response + " Curl request is: " + create_curl_req
				elif response:
					error_message = response + " Curl request is: " + create_curl_req
				else:
					error_message = "There is either a network connection problem "\
						"or the API itself is not returning data. Curl request "\
						"is: " + create_curl_req
				self.sshyze_logging.update(
					status="Error",
					message=error_message,
					modified=timezone.now(),
					is_completed=True
				)
				logger.error(error_message)
				return
		except Exception as e:
			print "Exception::..",e
			try:
				json_response = response.json()
			except:
				json_response = None
			if json_response and json_response.get('error'):
				error_message = json_response.get('error') + " Curl request is: " + create_curl_req
			elif json_response and not json_response.get('error'):
				error_message = json_response + " Curl request is: " + create_curl_req
			elif response:
				error_message = response + " Curl request is: " + create_curl_req
			else:
				error_message = "There is either a network connection problem "\
					"or the API itself is not returning data.. Curl request "\
					"is: " + create_curl_req
			self.sshyze_logging.update(
				status="Error",
				message=error_message,
				modified=timezone.now(),
				is_completed=True
			)
			logger.error(error_message)
			return

	def process_sshyze_cipher_scan(self, scan_url):
		response = self.get_status(scan_url)
		if response and (response.get('status') not in ["FAILED", "ERROR"]):
			while response and response.get('status') == "PENDING":
				logger.info("processing scan.......{}".format(timezone.now()))
				time.sleep(5)
				response = self.get_status(scan_url)
 
			if response and response.get('status') == "COMPLETED":
				logger.info("scan completed extracting data from result")
				result_uri = response.get("results_uri")
				result_url = self.domain + result_uri
				log = "scan complete you can aslo check the results by {}".format(result_url)
				self.sshyze_logging.update(
					status="Completed",
					message=log,
					modified=timezone.now()
				)
				response = self.get_status(result_url)
				if response:
					ssh_ciphers = response.get('ssh')
					if ssh_ciphers:
						algorithms = ssh_ciphers.get('algorithms')
						types = algorithms.keys()

						for typ in types:
							type_object, created  = SshyzeType.objects.get_or_create(name=typ)
							object_name_value = algorithms.get(typ)
							for name_value in object_name_value:
								sshyze_obj = SshyzeCiphers.objects.filter(
									cipher_type=type_object, 
									ciphers=name_value, 
									host=self.host,
									port=self.port
								)
								if sshyze_obj:
									sshyze_obj.update(modified=timezone.now())
								else:
									SshyzeCiphers.objects.create(
										cipher_type=type_object, 
										ciphers=name_value,
										host=self.host,
										port=self.port
									)
						log = "Scan completed successfully."
						self.sshyze_logging.update(
							status="Completed",
							message=log,
							modified=timezone.now(),
							is_completed=True
						)


def process_sshyze_ciphers(task_id):
	nessus_obj = NessusData.objects.filter(plugin_id='10881')
	external_appliances = get_appliance("External")
	internal_appliances = get_appliance("Internal")
	for data in nessus_obj:
		host = data.host
		port = data.port
		ip_type = get_ip_type(host)
		if ip_type == "Internal":
			if internal_appliances: # Checks if Internal Appliance Present
				scan_helper = SshyzeScanDescriptor(
					task_id,
					internal_appliances,
					host,
					port
				)
				scan_helper.create_sshyze_cipher_scan()
				
		elif ip_type == "External":
			if external_appliances: # Checks if External Appliance Present
				scan_helper = SshyzeScanDescriptor(
					task_id,
					external_appliances,
					host,
					port
				)
				scan_helper.create_sshyze_cipher_scan()


def external_sshyze_cipher(task_id):
	nessus_obj = NessusData.objects.filter(plugin_id='10881')
	external_appliances = get_appliance("External")
	for data in nessus_obj:
		host = data.host
		port = data.port
		ip_type = get_ip_type(host)
		if ip_type == "External":
			scan_helper = SshyzeScanDescriptor(
				task_id,
				external_appliances,
				host,
				port
			)
			scan_helper.create_sshyze_cipher_scan()


def internal_sshyze_cipher(task_id):
	nessus_obj = NessusData.objects.filter(plugin_id='10881')
	internal_appliances = get_appliance("Internal")
	for data in nessus_obj:
		host = data.host
		port = data.port
		ip_type = get_ip_type(host)
		if ip_type == "Internal":
			scan_helper = SshyzeScanDescriptor(
				task_id,
				internal_appliances,
				host,
				port
			)
			scan_helper.create_sshyze_cipher_scan()
