# core imports
import requests
import time

# in house files import
from redtree_app.models import *
from playground.models import *
import base64
import json
from utils.helpers import (
	get_appliance
)
from utils.views import (
    get_subdomain_ip_scope
)
from urlparse import urlparse
import socket
from django.utils import timezone
from celery.utils.log import get_task_logger

logger = get_task_logger(__name__)


class DnsEnumHelper(object):
	"""It will create the dnsenum scans"""

	def __init__(self, appliance, domain, task_id):
		log_obj = LogMicroServiceDnsEnum.objects.create(
			domain=domain,
			status="Queued",
			task_id=task_id,
            appliance=appliance.id
		)
		self.dns_logging = LogMicroServiceDnsEnum.objects.filter(id=log_obj.id)
		self.scan_url = appliance.appliance_setting.dnsenum_url
		self.auth_username = appliance.appliance_setting.auth_username
		self.auth_password = appliance.appliance_setting.auth_password
		self.parsed_uri = urlparse(self.scan_url)
		self.domain = '{uri.scheme}://{uri.netloc}/{prefix}'.format(
			uri=self.parsed_uri,
			prefix="dnsenum"
			)
		self.domain_obj = domain
		self.target_domain = domain.domain_name

	def get_status(self, url):
		status_curl = "curl -u {}:{} --request GET {}".format(
			self.auth_username,
			self.auth_password,
			url
		)
		try:
			response = requests.get(
				url,
				auth=(self.auth_username, self.auth_password),
				timeout=240
			)
		except requests.Timeout as timeout_exc:
			error_message = "error in getting response for dnsenum scan due to Maximum"\
                "connect time limit exceeded.Curl is {}".format(
				status_curl
			)
			# error_message = "Appliance is taking too long to respond."
			logger.error('{}'.format(error_message))
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
			return

		except Exception as error:
			error_message = "error {} in getting response for dnsenum scan.Curl is: {}".format(
				error,
				status_curl
			)
			logger.error('{}'.format(error_message))
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
					self.dns_logging.update(
						status="Error",
						message=message,
						modified=timezone.now(),
						is_completed=True
					)
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
				self.dns_logging.update(
					status="Error",
					message=error_message,
					is_completed=True,
					modified=timezone.now()
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
				self.dns_logging.update(
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
				self.dns_logging.update(
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
				self.dns_logging.update(
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
				if json_response and json_response.get('error'):
					error_message = json_response.get('error') + " Curl request is: " + status_url
				elif json_response and not json_response.get('error'):
					error_message = json_response + " Curl request is: " + status_url
				elif response:
					error_message = response + " Curl request is: " + status_url
				else:
					error_message = "(500 Internal Server Error). Curl request "\
						"is: " + status_url
				self.dns_logging.update(
					status="Error",
					message=error_message,
					is_completed=True,
					modified=timezone.now()
				)
				logger.error(error_message)
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
				self.dns_logging.update(
					status="Error",
					message=error_message,
					is_completed=True,
					modified=timezone.now()
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
			self.dns_logging.update(
				status="Error",
				message=error_message,
				modified=timezone.now(),
				is_completed=True
			)
			logger.error(error_message)
			return

	def get_host(self, hostname):
		try:
			host = socket.gethostbyname_ex(hostname)[2][0]
		except socket.gaierror:
			host = None
		return host

	def process_domain_scan(self, scan_url):
		response = self.get_status(scan_url)
		if response and (response.get('status') not in ["FAILED", "ERROR"]):
			while response and response.get('status') == "PENDING":
				print "processing :: {}".format(response)
				time.sleep(5)
				response = self.get_status(scan_url)
		if response and response.get('status') == "COMPLETED":
			result_url = "{}{}".format(
				self.domain,
				response.get("results_uri")
			)
			log = "scan completed can check the result by url {}".format(result_url)
			self.dns_logging.update(
				status="Completed",
				message=log
			)
			time.sleep(25)
			response = self.get_status(result_url)
			if response:
				for subdomain_name in response:
					subdomain_name = subdomain_name.lower()
					if subdomain_name and not EnumeratedSubdomains.objects.filter(
							subdomain=subdomain_name
						).exists():
						host = self.get_host(subdomain_name)
						if host:
							scope = get_subdomain_ip_scope(host)
						else:
							scope = False
						EnumeratedSubdomains.objects.create(
							domain=self.domain_obj,
							subdomain=subdomain_name,
							domain_host=host,
							in_scope=scope
						)
				subdomain_count = len(response)
				if subdomain_count:
					result = "{} subdomains discovered.".format(subdomain_count)
					log = "scan completed and {} subdomains discovered.".format(subdomain_count)
				else:
					result = "No subdomains discovered."
					log = "scan completed and no subdomains discovered."
				self.dns_logging.update(
					status="Completed",
					message=log,
					is_completed=True,
					result=result,
					modified=timezone.now()
				)
			else:
				result = "No subdomains discovered."
				log = "scan completed and no subdomains discovered."
				self.dns_logging.update(
					status="Completed",
					message=log,
					is_completed=True,
					result=result,
					modified=timezone.now()
				)


	def create_domain_scan(self):
		request_data = {
			"host": self.target_domain
		}
		create_curl_req = "curl -u {}:{} --header 'Content-Type: application/json' "\
			"--request POST --data '{}' {}".format(
				self.auth_username,
				self.auth_password,
				json.dumps(request_data),
				self.scan_url
			)
		try:
			request_header = {
				"Content-Type": "application/json"
			}
			response = requests.post(
				self.scan_url,
				auth=(self.auth_username, self.auth_password),
				json = request_data,
				headers = request_header,
				timeout=240
			)
		except requests.Timeout as timeout_exc:
			error_message = "Unable to start dnsenum scanning for {} due to Maximum connect time limit exceeded.".format(
				self.target_domain
			)
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
			return 

		except Exception as error:
			error_message = "error {} in DnsEnumHelper scan.Curl request is {}.".format(
				error,
				create_curl_req
			)
			logger.error("{}".format(error_message))
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
					self.dns_logging.update(
						status="Error",
						message=message,
						modified=timezone.now(),
						is_completed=True
					)
					return
				status_url = "{}{}".format(
					self.domain,
					response_data.get("status_uri")
					)
				log = "scan added can check the status by status_url {}".format(status_url)
				self.dns_logging.update(
					status="Running",
					message=log,
					scan_id=response_data.get("scan_id")
					)
				self.process_domain_scan(status_url)
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
				self.dns_logging.update(
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
				self.dns_logging.update(
					status="Error",
					message=error_message,
					is_completed=True,
					modified=timezone.now()
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
				self.dns_logging.update(
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
				if json_response and json_response.get('error'):
					error_message = json_response.get('error') + " Curl request is: " + create_curl_req
				elif json_response and not json_response.get('error'):
					error_message = json_response + " Curl request is: " + create_curl_req
				elif response:
					error_message = response + " Curl request is: " + create_curl_req
				else:
					error_message = "(500 Internal Server Error). Curl request "\
						"is: " + create_curl_req
				self.dns_logging.update(
					status="Error",
					message=error_message,
					is_completed=True,
					modified=timezone.now()
				)
				logger.error(error_message)
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
			self.dns_logging.update(
				status="Error",
				message=error_message,
				modified=timezone.now(),
				is_completed=True
			)
			logger.error(error_message)
			return

def process_internal_domains(task_id):
	domains = Domains.objects.filter(network_type="Internal")
	appliances = get_appliance("Internal")
	for domain in domains:
		if appliances:
			scan_obj = DnsEnumHelper(
				appliances,
				domain,
				task_id
			)
			scan_obj.create_domain_scan()


def process_external_domains(task_id):
	domains = Domains.objects.filter(network_type="External")
	appliances = get_appliance("External")
	for domain in domains:
		if appliances:
			scan_obj = DnsEnumHelper(
				appliances,
				domain,
				task_id
			)
			scan_obj.create_domain_scan()


def process_domains(task_id):
	domains = Domains.objects.all()
	for domain in domains:
		if domain.network_type == "Internal":
			appliances = get_appliance("Internal")
			if appliances:
				scan_obj = DnsEnumHelper(
					appliances,
					domain,
					task_id
				)
				scan_obj.create_domain_scan()
		if domain.network_type == "External":
			appliances = get_appliance("External")
			if appliances:
				scan_obj = DnsEnumHelper(
					appliances,
					domain,
					task_id
				)
				scan_obj.create_domain_scan()


def prior_domain_scan(task_id, domain_id):
	try:
		domain = Domains.objects.get(pk=domain_id)
	except:
		domain = None
	if domain:
		if domain.network_type == "Internal":
			appliance = get_appliance("Internal")

			scan_obj = DnsEnumHelper(
				appliance,
				domain,
				task_id
			)
			scan_obj.create_domain_scan()
		if domain.network_type == "External":
			appliance = get_appliance("External")

			scan_obj = DnsEnumHelper(
				appliance,
				domain,
				task_id
			)
			scan_obj.create_domain_scan()

