# -*- coding: utf-8 -*-
# core imports
import requests
import json

# in house files import
from redtree_app.models import *
from utils.helpers import (
	get_appliance
)
from urlparse import urlparse
from django.utils import timezone
from celery.utils.log import get_task_logger

logger = get_task_logger(__name__)


class ApplicationScreenshotScanHelper():
	"""It will create the application screenshot scans"""

	def __init__(self, task_id, appliance, application):
		print application
		log_obj = LogMicroServiceScreenshot.objects.create(
			application=application,
			status="Queued",
			task_id=task_id
		)
		self.logging = LogMicroServiceScreenshot.objects.filter(id=log_obj.id)
		self.scan_url = appliance.webscreenshot_app_url
		self.auth_username = appliance.auth_username
		self.auth_password = appliance.auth_password
		self.parsed_uri = urlparse(self.scan_url)
		self.domain = '{uri.scheme}://{uri.netloc}/{prefix}'.format(
			uri=self.parsed_uri,
			prefix="screenshot"
		)
		self.application = application.application_url
		self.app_obj = application
		self.client_obj = ClientConfiguration.objects.first()

	def create_application_screenshot_scan(self):
		post_data = {
			'url': self.application
		}
		headers = {
			'Content-Type': 'application/json',
		}
		curl_req = "curl -u {}:{} --header 'Content-Type: application/json' "\
			"--request POST --data '{}' {}".format(
				self.auth_username,
				self.auth_password,
				json.dumps(post_data),
				self.scan_url
			)
		try:
			response = requests.post(
				self.scan_url, 
				json = post_data,
				auth=(self.auth_username, self.auth_password),
				headers = headers,
				timeout=240
			)
			print "application screenshot scan generated successfully"
		except requests.Timeout as timeout_exc:
			response = None
			message = "Unable to add application screenshot scan due to Maximum connect time limit exceeded"
			AppNotification.objects.create(
				issue_type='error',
				notification_message=message
			)
			self.logging.update(
				status="Error",
				is_completed=True,
				message=message,
				modified=timezone.now(),
				duration=timezone.now()
			)
			return
		except Exception as error:
			response = None
			print "unable to create application screenshot scan {}".format(error)
			message = "Unable to add application screenshot scan due to {}".format(error)
			AppNotification.objects.create(
				issue_type='error',
				notification_message=message
			)
			self.logging.update(
				status="Error",
				is_completed=True,
				message=message,
				modified=timezone.now(),
				duration=timezone.now()
			)
			return
		print 'response::',response
		try:
			if response.status_code == 200:
				data = response.json()
				if data.get("success") and data.get("image"):
					# To check if screenshot title overwrite is allowed
					if not self.app_obj.screenshot_title:
						filename = data.get("filename")
						image = data.get("image")
						url_title = data.get("url_title")
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
						self.app_obj.screenshot_filename = filename
						self.app_obj.application_title = url_title
						self.app_obj.screenshot_path = os.path.join(
							"/media/screenshots/",
							filename
						)
						base_path = str(settings.BASE_DIR)
						image_path = base_path + self.app_obj.screenshot_path
						image_file = File(open(image_path, 'rb'))
						if self.client_obj and self.client_obj.storage_type=="S3":
							image_key = ''.join(['screenshots/', filename])
							media_uploader = MediaUploader(
								self.client_obj,
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
					self.app_obj.last_seen = timezone.now()
					self.app_obj.save()
					self.logging.update(
						status="Completed",
						is_completed=True,
						result="Screenshot updated successfully.",
						modified=timezone.now(),
						duration=timezone.now()
					)
				else:
					error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response.text) +\
						"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_req
					self.logging.update(
						status="Error",
						message=error_message,
						modified=timezone.now(),
						is_completed=True,
						duration=timezone.now()
					)
			elif response.status_code == 400:
				try:
					json_response = response.json()
				except:
					json_response = None
				if json_response and json_response.get('error'):
					error_message = str(json_response.get('error')) + " Curl request is: " + curl_req
				elif json_response and not json_response.get('error'):
					error_message = str(json_response) + " Curl request is: " + curl_req
				elif response:
					error_message = str(response) + " Curl request is: " + curl_req
				else:
					error_message = "(400 Bad Request). Curl request "\
						"is: " + curl_req
				self.logging.update(
					status="Error",
					message=error_message,
					modified=timezone.now(),
					is_completed=True,
					duration=timezone.now()
				)
				logger.error(error_message)
				return
			elif response.status_code == 401:
				try:
					json_response = response.json()
				except:
					json_response = None
				if json_response and json_response.get('error'):
					error_message = str(json_response.get('error')) + " Curl request is: " + curl_req
				elif json_response and not json_response.get('error'):
					error_message = str(json_response) + " Curl request is: " + curl_req
				elif response:
					error_message = str(response) + " Curl request is: " + curl_req
				else:
					error_message = "(401 Unauthorized). Curl request "\
						"is: " + curl_req
				self.logging.update(
					status="Error",
					is_completed=True,
					message=error_message,
					modified=timezone.now(),
					duration=timezone.now()
				)
				AppNotification.objects.create(
					issue_type='error',
					notification_message="Unable to add application screenshot"
						" scan for {} {}".format(
						self.application,
						error_message
					)
				)
			elif response.status_code == 404:
				try:
					json_response = response.json()
				except:
					json_response = None
				if json_response and json_response.get('error'):
					error_message = str(json_response.get('error')) + " Curl request is: " + curl_req
				elif json_response and not json_response.get('error'):
					error_message = str(json_response) + " Curl request is: " + curl_req
				elif response:
					error_message = str(response) + " Curl request is: " + curl_req
				else:
					error_message = "(404 not found). Curl request "\
						"is: " + curl_req
				self.logging.update(
					status="Error",
					message=error_message,
					is_completed=True,
					modified=timezone.now(),
					duration=timezone.now()
				)
				logger.error(error_message)
				return
			elif response.status_code == 504:
				try:
					json_response = response.json()
				except:
					json_response = None
				if json_response and json_response.get('error'):
					error_message = str(json_response.get('error')) + " Curl request is: " + curl_req
				elif json_response and not json_response.get('error'):
					error_message = str(json_response) + " Curl request is: " + curl_req
				elif response:
					error_message = str(response) + " Curl request is: " + curl_req
				else:
					error_message = "(504 Gateway Timeout error). Curl request "\
						"is: " + curl_req
				self.logging.update(
					status="Error",
					is_completed=True,
					message=error_message,
					modified=timezone.now(),
					duration=timezone.now()
				)
				AppNotification.objects.create(
					issue_type='error',
					notification_message="Unable to add application screenshot"
						"scan for {} {}".format(
							self.application,
							error_message
						)
				)
			elif response.status_code == 500:
				try:
					json_response = response.json()
				except:
					json_response = None
				if json_response and json_response.get('error'):
					error_message = json_response.get('error') + " Curl request is: " + curl_req
				elif json_response and not json_response.get('error'):
					error_message = str(json_response) + " Curl request is: " + curl_req
				elif response:
					error_message = str(response) + " Curl request is: " + curl_req
				else:
					error_message = "(500 Internal Server Error). Curl request "\
						"is: " + curl_req
				self.logging.update(
					status="Error",
					message=error_message,
					is_completed=True,
					modified=timezone.now(),
					duration=timezone.now()
				)
				logger.error(error_message)
				return
			else:
				try:
					json_response = response.json()
				except:
					json_response = None
				if json_response and json_response.get('error'):
					error_message = str(json_response.get('error')) + " Curl request is: " + curl_req
				elif json_response and not json_response.get('error'):
					error_message = str(json_response) + " Curl request is: " + curl_req
				elif response:
					error_message = str(response) + " Curl request is: " + curl_req
				else:
					error_message = "There is either a network connection problem "\
						"or the API itself is not returning data. Curl request "\
						"is: " + curl_req
				self.logging.update(
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
				logger.error(error_message)
				return
		except Exception as error:
			if error:
				message = "Error in screenshot script 'Error:: {}'".format(error)
				self.logging.update(
					status="Error",
					message=message,
					modified=timezone.now(),
					is_completed=True,
					duration=timezone.now()
				)
				logger.error(message)
			else:
				try:
					json_response = response.json()
				except:
					json_response = None
				if json_response and json_response.get('error'):
					error_message = json_response.get('error') + " Curl request is: " + curl_req
				elif json_response and not json_response.get('error'):
					error_message = json_response + " Curl request is: " + curl_req
				elif response:
					error_message = response + " Curl request is: " + curl_req
				else:
					error_message = "There is either a network connection problem "\
						"or the API itself is not returning data.. Curl request "\
						"is: " + curl_req
				self.logging.update(
					status="Error",
					message=error_message,
					modified=timezone.now(),
					is_completed=True,
					duration=timezone.now()
				)
				logger.error(error_message)
			return


def perform_scan(task_id, appliance, application):
	# for appliance in appliances:
	scan_obj = ApplicationScreenshotScanHelper(
		task_id,
		appliance.appliance_setting,
		application
	)
	scan_obj.create_application_screenshot_scan()


def external_application_screenshot_generator_scan(task_id):
	app_obj = Applications.objects.filter(network_type="External")
	appliance = get_appliance("External")
	if appliance:
		for application in app_obj:
			perform_scan(task_id, appliance, application)
	else:
		error_message = "External Screenshot Scan can't be initiated, because appliance is not set."
		AppNotification.objects.create(
			issue_type='cron_error',
			notification_message=error_message
		)


def internal_application_screenshot_generator_scan(task_id):
	app_obj = Applications.objects.filter(network_type="Internal")
	appliance = get_appliance("Internal")
	if appliance:
		for application in app_obj:
			perform_scan(task_id, appliance, application)
	else:
		error_message = "Internal Screenshot Scan can't be initiated, because appliance is not set."
		AppNotification.objects.create(
			issue_type='cron_error',
			notification_message=error_message
		)


def application_screenshot_generator_scan(task_id):
	external_application_screenshot_generator_scan(task_id)
	internal_application_screenshot_generator_scan(task_id)