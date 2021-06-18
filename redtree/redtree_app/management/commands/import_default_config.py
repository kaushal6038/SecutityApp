from django.core.management.base import BaseCommand
import json
import os
from redtree_app.models import *
from nessus.models import *


class Command(BaseCommand):

    def handle(self, *args, **options):
        BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(
            os.path.dirname(os.path.abspath(__file__)))))
        json_file_path = os.path.join(BASE_DIR, "configuration/default_configuration.json")
        file = open(json_file_path, 'r')
        file_data = file.read()
        json_data = json.loads(file_data)

        # Knowlwdgwbase API data
        knowledgebase_api = json_data.get("knowledgebase_api")
        kb_base_url = knowledgebase_api.get("kb_base_url")
        api = knowledgebase_api.get("api")
        kb_auth_token = knowledgebase_api.get("kb_auth_token")

        # Notifications data
        notifications = json_data.get("notifications")
        for notification_data in notifications:
            email = notification_data.get("email")

        # PurpleLeaf data
        purpleLeaf = json_data.get("purpleLeaf")
        client_name = os.environ.get('NAME')
        client_legal_name = os.environ.get('ENTITY')
        mailgun_api_key = purpleLeaf.get("mailgun_api_key")
        hostname = purpleLeaf.get("hostname")
        mailgun_base_url = purpleLeaf.get("mailgun_base_url")
        authentication_token = purpleLeaf.get("authentication_token")
        twilio_account_sid = purpleLeaf.get("twilio_account_sid")
        twilio_auth_key = purpleLeaf.get("twilio_auth_key")
        twilio_account_number = purpleLeaf.get("twilio_account_number")
        application_status = purpleLeaf.get("application_status")
        analytics_status = purpleLeaf.get("analytics_status")
        session_timeout_length = purpleLeaf.get("session_timeout_length")
        manual_hours_purchased = purpleLeaf.get("manual_hours_purchased")
        manual_hours_remaining = purpleLeaf.get("manual_hours_remaining")
        max_ips = purpleLeaf.get("max_ips")

        # Redtree data
        redtree = json_data.get("redtree")
        # App Configurations Data
        app_configurations = redtree.get("app_configurations")
        purpleleaf_auth_key = app_configurations.get("purpleleaf_auth_key")
        scanning_status = app_configurations.get("scanning_status")
        # Image Upload Data
        image_upload = redtree.get("image_upload")
        storage_type = image_upload.get("storage_type")
        # if os.environ.get('READ_WRITE_ACCESS_KEY') and  os.environ.get('READ_WRITE_SECRET_KEY') and os.environ.get('S3_BUCKET_NAME') is not None:
        s3_access_token = os.environ.get('READ_WRITE_ACCESS_KEY')
        s3_secret_access_token = os.environ.get('READ_WRITE_SECRET_KEY')
        s3_bucket_name = os.environ.get('S3_BUCKET_NAME')
        # else:
        # 	s3_access_token = image_upload.get("s3_access_token")
        # 	s3_secret_access_token = image_upload.get("s3_secret_access_token")
        # 	s3_bucket_name = image_upload.get("s3_bucket_name")
        pre_signed_time_length = image_upload.get("pre_signed_time_length")

        # Microservice data
        microservice = json_data.get("microservice")
        # Microservice Settings
        microservice_settings = microservice.get("microservice_settings")
        s3_bucket_scan_url = microservice_settings.get("s3_bucket_scan_url")
        webscreenshot_app_url = microservice_settings.get("webscreenshot_app_url")
        access_token = microservice_settings.get("access_token")
        secret_access_token = microservice_settings.get("secret_access_token")
        scan_frequency = microservice_settings.get("scan_frequency")
        # Nessus Settings
        nessus_settings = microservice.get("nessus_settings")
        nessus_url = nessus_settings.get("nessus_url")
        nessus_username = nessus_settings.get("nessus_username")
        nessus_password = nessus_settings.get("nessus_password")
        nessus_driver_url = nessus_settings.get("nessus_driver_url")
        max_simul_hosts = nessus_settings.get("max_simul_hosts")
        # Sslyze Settings
        sslyze_settings = microservice.get("sslyze_settings")
        microservice_scan_url = sslyze_settings.get("microservice_scan_url")
        sslyze_max_simul_hosts = sslyze_settings.get("sslyze_max_simul_hosts")
        # Burp Settings
        burp_settings = microservice.get("burp_settings")
        burp_url = burp_settings.get("burp_url")
        # Masscan Settings
        masscan_settings = microservice.get("masscan_settings")
        masscan_ip_address = masscan_settings.get("masscan_ip_address")
        masscan_ports = masscan_settings.get("masscan_ports")
        masscan_maximum_hosts_per_scan = masscan_settings.get("masscan_maximum_hosts_per_scan")

        # Appliance Settings
        appliance_settings = json_data.get("appliance_settings")
        appliance_ip = appliance_settings.get("appliance_ip")
        network_type = appliance_settings.get("network_type")

        client_conf_obj = ClientConfiguration.objects.first()
        if not client_conf_obj:
            ClientConfiguration.objects.create(
                client_name=client_name,
                client_legal_name=client_legal_name,
                mailgun_api_key=mailgun_api_key,
                hostname=hostname,
                mailgun_base_url=mailgun_base_url,
                authentication_token=authentication_token,
                twilio_account_sid=twilio_account_sid,
                twilio_auth_key=twilio_auth_key,
                twilio_account_number=twilio_account_number,
                storage_type=storage_type,
                s3_access_token=s3_access_token,
                s3_secret_access_token=s3_secret_access_token,
                s3_bucket_name=s3_bucket_name,
                pre_signed_time_length=pre_signed_time_length,
                scan_frequency=scan_frequency,
                application_status=application_status,
                analytics_status=analytics_status,
                session_timeout_length=session_timeout_length,
                manual_hours_purchased=manual_hours_purchased,
                manual_hours_remaining=manual_hours_remaining,
                max_ips=max_ips
            )
        else:
            if not client_conf_obj.client_name:
                client_conf_obj.client_name = client_name
            elif not client_conf_obj.client_legal_name:
                client_conf_obj.client_legal_name = client_legal_name
            elif not client_conf_obj.mailgun_api_key:
                client_conf_obj.mailgun_api_key = mailgun_api_key
            elif not client_conf_obj.hostname:
                client_conf_obj.hostname = hostname
            elif not client_conf_obj.mailgun_base_url:
                client_conf_obj.mailgun_base_url = mailgun_base_url
            elif not client_conf_obj.authentication_token:
                client_conf_obj.authentication_token = authentication_token
            elif not client_conf_obj.twilio_account_sid:
                client_conf_obj.twilio_account_sid = twilio_account_sid
            elif not client_conf_obj.twilio_auth_key:
                client_conf_obj.twilio_auth_key = twilio_auth_key
            elif not client_conf_obj.twilio_account_number:
                client_conf_obj.twilio_account_number = twilio_account_number
            elif not client_conf_obj.storage_type:
                client_conf_obj.storage_type = storage_type
            elif not client_conf_obj.s3_access_token:
                client_conf_obj.s3_access_token = s3_access_token
            elif not client_conf_obj.s3_secret_access_token:
                client_conf_obj.s3_secret_access_token = s3_secret_access_token
            elif not client_conf_obj.s3_bucket_name:
                client_conf_obj.s3_bucket_name = s3_bucket_name
            elif not client_conf_obj.pre_signed_time_length:
                client_conf_obj.pre_signed_time_length = pre_signed_time_length
            elif not client_conf_obj.scan_frequency:
                client_conf_obj.scan_frequency = scan_frequency
            elif not client_conf_obj.application_status:
                client_conf_obj.application_status = application_status
            elif not client_conf_obj.analytics_status:
                client_conf_obj.analytics_status = analytics_status
            elif not client_conf_obj.session_timeout_length:
                client_conf_obj.session_timeout_length = session_timeout_length
            elif not client_conf_obj.manual_hours_purchased:
                client_conf_obj.manual_hours_purchased = manual_hours_purchased
            elif not client_conf_obj.manual_hours_remaining:
                client_conf_obj.manual_hours_remaining = manual_hours_remaining
            client_conf_obj.save()

        conf_obj = Configuration.objects.first()
        if not conf_obj:
            Configuration.objects.create(
                scanning_status=scanning_status,
                purpleleaf_auth_key=purpleleaf_auth_key)
        else:
            if not conf_obj.purpleleaf_auth_key:
                conf_obj.purpleleaf_auth_key = purpleleaf_auth_key
            conf_obj.save()

        api_list_obj = ApiList.objects.first()
        if not api_list_obj:
            ApiList.objects.create(api=api,
                                   kb_base_url=kb_base_url,
                                   kb_auth_token=kb_auth_token)
        else:
            if not api_list_obj.api:
                api_list_obj.api = api
            elif not api_list_obj.kb_base_url:
                api_list_obj.kb_base_url = kb_base_url
            elif not api_list_obj.kb_auth_token:
                api_list_obj.kb_auth_token = kb_auth_token
            api_list_obj.save()

        appl_obj = Appliances.objects.first()
        if not appl_obj:
            Appliances.objects.create(
                appliance_ip=appliance_ip,
                network_type=network_type)
        else:
            if not appl_obj.appliance_ip:
                appl_obj.appliance_ip = appliance_ip
            elif not appl_obj.network_type:
                appl_obj.network_type = network_type
            appl_obj.save()
