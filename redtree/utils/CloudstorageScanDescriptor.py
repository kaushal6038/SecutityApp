# core imports
import requests
import time
import json
# in house files import
from redtree_app.models import *
from playground.models import *
import base64
from utils.helpers import (
    get_appliance
)
from urlparse import urlparse
import socket
from django.utils import timezone


class CloudStorageHelper(object):
    """It will create the cloudstorage scans"""

    def __init__(self, appliance, cloud_storage_obj):
        log_obj = LogMicroServiceCloudstorage.objects.create(
            bucket=cloud_storage_obj,
            status="Queued"
        )
        self.cloudstorage_logging = LogMicroServiceCloudstorage.objects.filter(id=log_obj.id)
        self.scan_url = appliance.cloudstorage_url
        self.auth_username = appliance.auth_username
        self.auth_password = appliance.auth_password
        self.parsed_uri = urlparse(self.scan_url)
        self.domain = '{uri.scheme}://{uri.netloc}/{prefix}'.format(
            uri=self.parsed_uri,
            prefix="cloudstorage"
            )
        self.cloud_storage_obj = cloud_storage_obj
        self.target_bucket = cloud_storage_obj.bucket
        category = cloud_storage_obj.category
        self.bucket_category = None
        if category == "S3":
            self.bucket_category = "s3"
        elif category == "GCP":
            self.bucket_category = "gcp"
        elif category == "Azure":
            self.bucket_category = "azure"


    def bucket_scan(self):
        self.cloud_storage_obj.cloud_storage_scan_data.all().delete()
        self.cloud_storage_obj.last_scan = timezone.now()
        self.cloud_storage_obj.save()
        try:
            request_header = {
                "Content-Type": "application/json"
            }
            request_data = {
                "bucket_name": self.target_bucket,
                "type": self.bucket_category
            }
            response = requests.post(
                self.scan_url,
                auth=(self.auth_username, self.auth_password),
                json = request_data,
                headers = request_header,
                timeout=240
            )
        except requests.Timeout as timeout_exc:
            error_message = "error in getting response for scanning the bucket {} due to Maximum"\
                "connect time limit exceeded.".format(
                self.target_bucket
            )
            self.cloudstorage_logging.update(
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
            return
        except Exception as error:
            error_message = "error {} scanning the bucket {}".format(
                error,
                self.target_bucket
            )
            self.cloudstorage_logging.update(
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
            return
        log = "Scan is running"
        self.cloudstorage_logging.update(status="Running", message=log)
        print 'response :: ',response
        if response.status_code == 200:
            try:
                response_data = response.json()
            except:
                response_data = None
            try:
                unauthenticated_data = response_data.get('unauthenticated').get(
                    self.target_bucket
                )
            except:
                unauthenticated_data = []
            try:
                unauthenticated_files = unauthenticated_data.get('files')
            except:
                unauthenticated_files = []
            try:
                unauthenticated_errors = unauthenticated_data.get('errors')
            except:
                unauthenticated_errors = []
            try:
                unauthenticated_issues = unauthenticated_data.get('issues')
            except:
                unauthenticated_issues = []
            try:
                authenticated_data = response_data.get('authenticated').get(
                    self.target_bucket
                )
            except:
                authenticated_data = []
            try:
                authenticated_files = authenticated_data.get('files')
            except:
                authenticated_files = []
            try:
                authenticated_errors = authenticated_data.get('errors')
            except:
                authenticated_errors = []
            try:
                authenticated_issues = authenticated_data.get('issues')
            except:
                authenticated_issues = []
            for error in unauthenticated_errors:
                if error not in ['none', 'None']:
                    try:
                        cloud_storage_scan_obj = CloudstorageScanData.objects.get(
                            cloud_asset_bucket=self.cloud_storage_obj,
                            bucket_name=error
                        )
                    except:
                        cloud_storage_scan_obj = None
                    if not cloud_storage_scan_obj:
                        obj = CloudstorageScanData.objects.create(
                            cloud_asset_bucket=self.cloud_storage_obj,
                            bucket_name=error,
                            unauthenticated_status=True
                        )
                    else:
                        cloud_storage_scan_obj.unauthenticated_status = True
                        cloud_storage_scan_obj.save()
            for issue in unauthenticated_issues:
                if issue not in ['none', 'None']:
                    try:
                        cloud_storage_scan_obj = CloudstorageScanData.objects.get(
                            cloud_asset_bucket=self.cloud_storage_obj,
                            bucket_name=issue
                        )
                    except:
                        cloud_storage_scan_obj = None
                    if not cloud_storage_scan_obj:
                        CloudstorageScanData.objects.create(
                            cloud_asset_bucket=self.cloud_storage_obj,
                            bucket_name=issue,
                            unauthenticated_status=False
                            )
                    else:
                        cloud_storage_scan_obj.unauthenticated_status = False
                        cloud_storage_scan_obj.save()
            for error in authenticated_errors:
                if error not in ['none', 'None']:
                    try:
                        cloud_storage_scan_obj = CloudstorageScanData.objects.get(
                            cloud_asset_bucket=self.cloud_storage_obj,
                            bucket_name=error
                        )
                    except:
                        cloud_storage_scan_obj = None
                    if not cloud_storage_scan_obj:
                        CloudstorageScanData.objects.create(
                            cloud_asset_bucket=self.cloud_storage_obj,
                            bucket_name=error,
                            authenticated_status=True
                        )
                    else:
                        cloud_storage_scan_obj.authenticated_status = True
                        cloud_storage_scan_obj.save()
            for issue in authenticated_issues:
                if issue not in ['none', 'None']:
                    try:
                        cloud_storage_scan_obj = CloudstorageScanData.objects.get(
                            cloud_asset_bucket=self.cloud_storage_obj,
                            bucket_name=issue
                        )
                    except:
                        cloud_storage_scan_obj = None
                    if not cloud_storage_scan_obj:
                        CloudstorageScanData.objects.create(
                            cloud_asset_bucket=self.cloud_storage_obj,
                            bucket_name=issue,
                            authenticated_status=False
                        )
                    else:
                        cloud_storage_scan_obj.authenticated_status = False
                        cloud_storage_scan_obj.save()

            files = unauthenticated_files + authenticated_files
            for file in files:
                if file not in ['none', 'None']:
                    try:
                        cloud_storage_scan_obj = CloudstorageScanData.objects.get(
                            cloud_asset_bucket=self.cloud_storage_obj,
                            file=file
                        )
                    except:
                        cloud_storage_scan_obj = None
                    if not cloud_storage_scan_obj:
                        CloudstorageScanData.objects.create(
                            cloud_asset_bucket=self.cloud_storage_obj,
                            file=file
                        )
            log = "Scan completed successfully."
            self.cloudstorage_logging.update(
                status="Completed",
                message=log,
                is_completed=True,
                modified=timezone.now()
            )
        elif response.status_code == 401:
            error_message = "unable to start cloudstorage scanning for {} "\
                "due to invalid authentication.".format(
                self.target_bucket
            )
            self.cloudstorage_logging.update(
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
            error_message = "error 404"
            self.cloudstorage_logging.update(
                status="Error",
                message=error_message,
                is_completed=True,
                modified=timezone.now()
            )
        elif response.status_code == 500:
            error_message = "error 500"
            self.cloudstorage_logging.update(
                status="Error",
                message=error_message,
                is_completed=True,
                modified=timezone.now()
            )
        elif response.status_code == 504:
            error_message = "error 504"
            self.cloudstorage_logging.update(
                status="Error",
                message=error_message,
                is_completed=True,
                modified=timezone.now()
            )
        else:
            error_message = "Undefined Error in service cloudstorage"
            self.cloudstorage_logging.update(
                status="Error",
                message=error_message,
                is_completed=True,
                modified=timezone.now()
            )
            AppNotification.objects.create(
                issue_type='error',
                notification_message=error_message
            )


def cloudstorage_bucket_scan():
    cloud_asset_objs = CloudAssetsData.objects.all()
    for cloud_asset_obj in cloud_asset_objs:
        appliances = get_appliance("External")
        if appliances:
            scan_obj = CloudStorageHelper(
                appliances.appliance_setting,
                cloud_asset_obj
            )
            scan_obj.bucket_scan()