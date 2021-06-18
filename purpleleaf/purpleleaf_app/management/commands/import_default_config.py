from django.core.management.base import BaseCommand
import json
import os
from account.models import *


class Command(BaseCommand):

    def handle(self, *args, **options):
		BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(
			os.path.dirname(os.path.abspath(__file__)))))
		json_file_path = os.path.join(BASE_DIR, "configuration/default_configuration.json")
		file = open(json_file_path, 'r')
		file_data = file.read()
		json_data = json.loads(file_data)

		
		# PurpleLeaf data
		purpleLeaf = json_data.get("purpleLeaf")
		active = purpleLeaf.get("active")
		mailgun_api_key = purpleLeaf.get("mailgun_api_key")
		hostname = purpleLeaf.get("hostname")
		mailgun_base_url = purpleLeaf.get("mailgun_base_url")
		redtree_auth_key = purpleLeaf.get("redtree_auth_key")
		twilio_account_sid = purpleLeaf.get("twilio_account_sid")
		twilio_auth_key = purpleLeaf.get("twilio_auth_key")
		twilio_account_number = purpleLeaf.get("twilio_account_number")
		application_status = purpleLeaf.get("application_status")
		analytics_status = purpleLeaf.get("analytics_status")
		session_timeout_length = purpleLeaf.get("session_timeout_length")
		manual_hours_purchased = purpleLeaf.get("manual_hours_purchased")
		manual_hours_remaining = purpleLeaf.get("manual_hours_remaining")
		max_ips = purpleLeaf.get("max_ips")


		# Image Upload Data
		image_upload = json_data.get("image_upload")
		storage_type = image_upload.get("storage_type")
		# if os.environ.get('READ_WRITE_ACCESS_KEY') and os.environ.get('READ_WRITE_SECRET_KEY') and os.environ.get('S3_BUCKET_NAME') is not None:
		s3_access_token = os.environ.get('READ_ONLY_ACCESS_KEY')
		s3_secret_access_token = os.environ.get('READ_ONLY_SECRET_KEY')
		s3_bucket_name = os.environ.get('S3_BUCKET_NAME')
		# else:
		# 	s3_access_token = image_upload.get("s3_access_token")
		# 	s3_secret_access_token = image_upload.get("s3_secret_access_token")
		# 	s3_bucket_name = image_upload.get("s3_bucket_name")
		pre_signed_time_length = image_upload.get("pre_signed_time_length")

		# Redtree Data
		redtree = json_data.get("redtree")
		data_auth_key = redtree.get("data_auth_key")
		redtree_base_url = redtree.get("redtree_base_url")


		conf_obj = Configuration.objects.first()
		if not conf_obj:
			Configuration.objects.create(
				active = active,
				mailgun_api_key = mailgun_api_key,
				hostname = hostname,
				mailgun_base_url = mailgun_base_url,
				redtree_auth_key = redtree_auth_key,
				twilio_account_sid = twilio_account_sid,
				twilio_auth_key = twilio_auth_key,
				twilio_account_number = twilio_account_number,
				application_status = application_status,
				analytics_status = analytics_status,
				storage_type = storage_type,
				s3_access_token = s3_access_token,
				s3_secret_access_token = s3_secret_access_token,
				s3_bucket_name = s3_bucket_name,
				pre_signed_time_length = pre_signed_time_length,
				session_timeout_length = session_timeout_length,
				manual_hours_purchased = manual_hours_purchased,
				manual_hours_remaining = manual_hours_remaining,
				max_ips = max_ips)
		else:
			if not conf_obj.mailgun_api_key:
				conf_obj.mailgun_api_key = mailgun_api_key
			elif not conf_obj.hostname:
				conf_obj.hostname = hostname
			elif not conf_obj.mailgun_base_url:
				conf_obj.mailgun_base_url = mailgun_base_url
			elif not conf_obj.redtree_auth_key:
				conf_obj.redtree_auth_key = redtree_auth_key
			elif not conf_obj.twilio_account_sid:
				conf_obj.twilio_account_sid = twilio_account_sid
			elif not conf_obj.twilio_auth_key:
				conf_obj.twilio_auth_key = twilio_auth_key
			elif not conf_obj.twilio_account_number:
				conf_obj.twilio_account_number = twilio_account_number
			elif not conf_obj.application_status:
				conf_obj.application_status = application_status
			elif not conf_obj.analytics_status:
				conf_obj.analytics_status = analytics_status
			elif not conf_obj.storage_type:
				conf_obj.storage_type = storage_type
			elif not conf_obj.s3_access_token:
				conf_obj.s3_access_token = s3_access_token
			elif not conf_obj.s3_secret_access_token:
				conf_obj.s3_secret_access_token = s3_secret_access_token
			elif not conf_obj.s3_bucket_name:
				conf_obj.s3_bucket_name = s3_bucket_name
			elif not conf_obj.pre_signed_time_length:
				conf_obj.pre_signed_time_length = pre_signed_time_length
			elif not conf_obj.session_timeout_length:
				conf_obj.session_timeout_length = session_timeout_length
			elif not conf_obj.manual_hours_purchased:
				conf_obj.manual_hours_purchased = manual_hours_purchased
			elif not conf_obj.manual_hours_remaining:
				conf_obj.manual_hours_remaining = manual_hours_remaining
			elif not conf_obj.max_ips:
				conf_obj.max_ips = max_ips
			conf_obj.save()


		private_conf_obj = PrivateConfiguration.objects.first()
		if not private_conf_obj:
			PrivateConfiguration.objects.create(
				redtree_base_url = redtree_base_url,
				data_auth_key = data_auth_key)
		else:
			if not private_conf_obj.redtree_base_url:
				private_conf_obj.redtree_base_url = redtree_base_url
			elif not private_conf_obj.data_auth_key:
				private_conf_obj.data_auth_key = data_auth_key
			private_conf_obj.save()