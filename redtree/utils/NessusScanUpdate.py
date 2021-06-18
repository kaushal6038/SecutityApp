# -*- coding: utf-8 -*-
# django import
from django.db.models import Q

# import from in house apps
from utils.process_nessus_file import process_file
from redtree_app.models import *
from utils.nessus_upload_helper import upload_file
from celery.utils.log import get_task_logger

logger = get_task_logger(__name__)


class NessusScanUpdator:

	def __init__(self):
		pass

	def get_status(self, url, auth_username, auth_password, nessus_obj):
		curl_request = "curl -u {}:{} --request GET {}".format(
			auth_username,
			auth_password,
			url
		)
		nessus_logging = LogMicroServiceNessus.objects.filter(id=nessus_obj.id)
		try:
			response = requests.get(
				url,
				auth=(auth_username, auth_password)
			)
		except requests.Timeout as timeout_exc:
			error_message = "Error in getting response for nessus scan due to Maximum"\
				"connect time limit exceeded.\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::  {}".format(
					curl_request
				)
			# logger.error('{}'.format(error_message))
			print 'error_message',error_message
			AppNotification.objects.create(
				issue_type='error',
				notification_message=error_message
			)
			nessus_logging.update(
				status="Error",
				message=error_message,
				is_completed=True,
				modified=timezone.now(),
				duration=timezone.now()
			)
			return
		except Exception as error:
			error_message = "𝗘𝘅𝗰𝗲𝗽𝘁𝗶𝗼𝗻:: {} in getting response for nessus scan."\
				"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::  {}".format(
					error,
					curl_request
				)
			# logger.error('{}'.format(error_message))
			print 'error_message',error_message
			AppNotification.objects.create(
				issue_type='error',
				notification_message=error_message
			)
			nessus_logging.update(
				status="Error",
				message=error_message,
				is_completed=True,
				modified=timezone.now(),
				duration=timezone.now()
			)
			return
		print 'status_code::',response
		try:
			if response.status_code == 200:
				return response
			elif response.status_code == 401:
				try:
					json_response = response.json()
				except:
					json_response = None
				if json_response and json_response.get('error'):
					error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) +\
						"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
				elif json_response and not json_response.get('error'):
					error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response) +\
						"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
				elif response:
					error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) +\
						"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
				elif response.text:
					error_message = "(401 Unauthorized).\n𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " +\
						str(response.text) + "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
				else:
					error_message = "(401 Unauthorized).\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " +\
						curl_request
				# logger.info("{}".format(error_message))
				print 'error_message',error_message
				nessus_logging.update(
					status="Error",
					is_completed=True,
					message=error_message,
					modified=timezone.now(),
					duration=timezone.now()
				)
				return
			elif response.status_code == 404:
				try:
					json_response = response.json()
				except:
					json_response = None
				if json_response and json_response.get('error'):
					error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) +\
						"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
				elif json_response and not json_response.get('error'):
					error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response) +\
						"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
				elif response:
					error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) +\
						"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
				elif response.text:
					error_message = "(404 not found).\n𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " +\
						str(response.text) + "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
				else:
					error_message = "(404 not found).\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " +\
						curl_request
				print 'error_message',error_message
				nessus_logging.update(
					status="Error",
					message=error_message,
					is_completed=True,
					modified=timezone.now(),
					duration=timezone.now()
				)
				# logger.error(error_message)
				return
			elif response.status_code == 502:
				try:
					json_response = response.json()
				except:
					json_response = None
				if json_response and json_response.get('error'):
					error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) +\
						"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
				elif json_response and not json_response.get('error'):
					error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response) +\
						"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
				elif response:
					error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) +\
						"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
				elif response.text:
					error_message = "(502 Bad Gateway).\n𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " +\
						str(response.text) + "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
				else:
					error_message = "(502 Bad Gateway).\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " +\
						curl_request
				print 'error_message',error_message
				nessus_logging.update(
					status="Error",
					message=error_message,
					is_completed=True,
					modified=timezone.now(),
					duration=timezone.now()
				)
				# logger.error(error_message)
				return
			elif response.status_code == 400:
				try:
					json_response = response.json()
				except:
					json_response = None
				if json_response and json_response.get('error'):
					error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) +\
						"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
				elif json_response and not json_response.get('error'):
					error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response) +\
						"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
				elif response:
					error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) +\
						"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
				elif response.text:
					error_message = "(400 Bad Request).\n𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " +\
						str(response.text) + "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
				else:
					error_message = "(400 Bad Request).\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " +\
						curl_request
				print 'error_message',error_message
				nessus_logging.update(
					status="Error",
					message=error_message,
					is_completed=True,
					modified=timezone.now(),
					duration=timezone.now()
				)
				# logger.error(error_message)
				return
			elif response.status_code == 504:
				try:
					json_response = response.json()
				except:
					json_response = None
				if json_response and json_response.get('error'):
					error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) +\
						"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
				elif json_response and not json_response.get('error'):
					error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response) +\
						"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
				elif response:
					error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) +\
						"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
				elif response.text:
					error_message = "(504 Gateway Timeout error).\n𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " +\
						str(response.text) + "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
				else:
					error_message = "(504 Gateway Timeout error).\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " +\
						curl_request
				print 'error_message',error_message
				nessus_logging.update(
					message=error_message,
					modified=timezone.now(),
					duration=timezone.now()
				)
				# logger.error(error_message)
				return
			elif response.status_code == 500:
				try:
					json_response = response.json()
				except:
					json_response = None
				if json_response and json_response.get('error'):
					error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) +\
						"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
				elif json_response and not json_response.get('error'):
					error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response) +\
						"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
				elif response:
					error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) +\
						"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
				elif response.text:
					error_message = "(500 Internal Server Error).\n𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " +\
						str(response.text) + "\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
				else:
					error_message = "(500 Internal Server Error).\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " +\
						curl_request
				if "Scan is not finished yet" in error_message:
					nessus_logging.update(
						message=error_message,
						modified=timezone.now(),
						duration=timezone.now()
					)
				else:
					nessus_logging.update(
						status="Error",
						message=error_message,
						is_completed=True,
						modified=timezone.now(),
						duration=timezone.now()
					)
				# logger.error(error_message)
				print 'error_message',error_message
				return
			else:
				try:
					json_response = response.json()
				except:
					json_response = None
				if json_response and json_response.get('error'):
					error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) +\
						"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
				elif json_response and not json_response.get('error'):
					error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response) +\
						"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
				elif response:
					error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) +\
						"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
				elif response.text:
					error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response.text) +\
						"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
				else:
					error_message = "There is either a network connection problem "\
						"or the API itself is not returning data."\
						"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
				nessus_logging.update(
					status="Error",
					message=error_message,
					is_completed=True,
					modified=timezone.now(),
					duration=timezone.now()
				)
				# logger.error(error_message)
				print ('error_message',error_message)
				return
		except Exception as e:
			try:
				json_response = response.json()
			except:
				json_response = None
			if json_response and json_response.get('error'):
				error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response.get('error')) +\
					"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
			elif json_response and not json_response.get('error'):
				error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(json_response) +\
					"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
			elif response:
				error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response) +\
					"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
			elif response.text:
				error_message = "𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲:  " + str(response.text) +\
					"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
			else:
				error_message = "There is either a network connection problem "\
					"or the API itself is not returning data.."\
					"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::   " + curl_request
			nessus_logging.update(
				status="Error",
				message=error_message,
				is_completed=True,
				modified=timezone.now(),
				duration=timezone.now()
			)
			# logger.error(error_message)
			print ('error_message',error_message)
			return

	def update_nessus_scan_status(self):
		nessus_objs = LogMicroServiceNessus.objects.filter(
			is_completed=False,
			status='Running'
		)
		print 'nessus_objs',nessus_objs
		for nessus_obj in nessus_objs:
			if nessus_obj.appliance:
				try:
					appliance_obj = Appliances.objects.get(id=nessus_obj.appliance)
				except:
					appliance_obj = None
				if appliance_obj:
					appliance_setting_obj = appliance_obj.appliance_setting
					status_url = "{}get-status/{}".format(
						appliance_setting_obj.nessus_driver_url,
						nessus_obj.scan_id
					)
					auth_username = appliance_setting_obj.auth_username
					auth_password = appliance_setting_obj.auth_password
					status_curl = "curl -u {}:{} --request GET {}".format(
						auth_username,
						auth_password,
						status_url
					)
					response = self.get_status(
						status_url,
						auth_username,
						auth_password,
						nessus_obj
					)
					print 'status_url::',status_url
					try:
						response_data = response.json()
					except:
						response_data = None
					if response_data and response_data.get('status') == "SUCCEEDED":
						logger.info("scan completed extracting data from result")
						result_url = "{}get-result/{}".format(
							appliance_setting_obj.nessus_driver_url,
							nessus_obj.scan_id
						)
						result_curl = "curl -u {}:{} --request GET {}".format(
							auth_username,
							auth_password,
							result_url
						)
						log = "Scan completed you can aslo check the results by "\
							"𝗖𝘂𝗿𝗹::\n{}".format(
							result_curl
						)
						nessus_obj.status="Running"
						nessus_obj.message=log
						nessus_obj.modified=timezone.now()
						nessus_obj.duration=timezone.now()
						nessus_obj.save()
						result_data = self.get_status(
							result_url,
							auth_username,
							auth_password,
							nessus_obj
						)
						if result_data and result_data.status_code == 200:
							try:
								data = result_data.__dict__.get('_content')
							except:
								data = None
							if data:
								nessus_data = process_file(data)
								upload_file(nessus_obj.scan_id, nessus_data)
							nessus_obj.status="Completed"
							nessus_obj.message="Scan completed successfully"
							nessus_obj.modified=timezone.now()
							nessus_obj.duration=timezone.now()
							nessus_obj.is_completed=True
							nessus_obj.save()
						elif result_data and result_data.get('error'):
							log = "𝗘𝘅𝗰𝗲𝗽𝘁𝗶𝗼𝗻::  {}  while fetching nessus result."\
								"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::  {}".format(
									str(response_data.get('error')),
									result_curl
								)
							nessus_obj.status="Error"
							nessus_obj.message=log
							nessus_obj.modified=timezone.now()
							nessus_obj.is_completed=True
							nessus_obj.duration=timezone.now()
							nessus_obj.save()
					elif response_data and response_data.get('status') == "FAILED": 
						log = "𝗘𝘅𝗰𝗲𝗽𝘁𝗶𝗼𝗻::  {}  while fetching nessus result."\
							"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::  {}".format(
								str(response_data.get('detail')),
								status_curl
							)
						nessus_obj.status="Error"
						nessus_obj.message=log
						nessus_obj.modified=timezone.now()
						nessus_obj.is_completed=True
						nessus_obj.duration=timezone.now()
						nessus_obj.save()
					elif response_data and response_data.get('status') == "UNDEFINED":
						try:
							log = str(response_data.get('detail'))
						except:
							log = "getting UNDEFINED response for nessus"
						error_message = "𝗘𝘅𝗰𝗲𝗽𝘁𝗶𝗼𝗻::  {}  while fetching nessus result."\
							"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::  {}".format(
								log,
								status_curl
							)
						nessus_obj.status="Error"
						nessus_obj.message=error_message
						nessus_obj.modified=timezone.now()
						nessus_obj.is_completed=True
						nessus_obj.duration=timezone.now()
						nessus_obj.save()
					elif response_data and response_data.get('error'):
						log = "𝗘𝘅𝗰𝗲𝗽𝘁𝗶𝗼𝗻::  {}  while fetching nessus result."\
							"\n𝗖𝘂𝗿𝗹 𝗿𝗲𝗾𝘂𝗲𝘀𝘁 𝗶𝘀::  {}".format(
								str(response_data.get('error')),
								status_curl
							)
						nessus_obj.status="Error"
						nessus_obj.message=log
						nessus_obj.modified=timezone.now()
						nessus_obj.is_completed=True
						nessus_obj.duration=timezone.now()
						nessus_obj.save()
				else:
					nessus_obj.status="Error"
					nessus_obj.message="Appliance Doesn't exists."
					nessus_obj.modified=timezone.now()
					nessus_obj.is_completed=True
					nessus_obj.duration=timezone.now()
					nessus_obj.save()
			else:
				nessus_obj.status="Error"
				nessus_obj.message="Scan data doesn't exists."
				nessus_obj.modified=timezone.now()
				nessus_obj.is_completed=True
				nessus_obj.duration=timezone.now()
				nessus_obj.save()