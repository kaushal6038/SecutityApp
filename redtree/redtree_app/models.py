from __future__ import unicode_literals
from django.db import models
from django.db.models import *
from markdownx.models import MarkdownxField
from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver
import os
from datetime import date, datetime, timedelta
import requests
from markdownx.utils import markdownify
from django.conf import settings
from django.core.files import File
from utils.MediaUploader import MediaUploader
from redtree_app.markdown_helper import get_markdown_with_images
import re
from django.utils import timezone
import time
from utils.base_models import LoggingBaseModel, BaseModel
from django_celery_beat.models import PeriodicTask, IntervalSchedule
import uuid
import logging


def send_mail(reciever, subject, html_content):
    client_conf = ClientConfiguration.objects.first()
    if client_conf:
        key = client_conf.mailgun_api_key
        base_url = client_conf.mailgun_base_url
        request_url = base_url + "/messages"
        try:
            request = requests.post(request_url, auth=('api', key), data={
                'from': "Redtree Notification<noreply@purpleleaf.io>",
                'to': reciever,
                'subject': subject,
                'html': html_content
            })
        except:
            pass


class Configuration(BaseModel):
    scanning_status = models.BooleanField(default=False)
    purpleleaf_auth_key = models.CharField(max_length=500, null=True, blank=True)
    auth_reset = models.BooleanField(default=False)

    def __str__(self):
        return str(self.scanning_status)

    class Meta:
        verbose_name_plural = "Configurations"


class ClientConfiguration(BaseModel):
    client_name = models.CharField(max_length=500, blank=True, null=True)
    client_legal_name = models.CharField(max_length=500, blank=True, null=True)
    mailgun_api_key = models.CharField(max_length=1000, blank=True, null=True)
    hostname = models.CharField(max_length=500, blank=True, null=True)
    mailgun_base_url = models.CharField(max_length=500, blank=True, null=True)
    authentication_token = models.CharField(max_length=500, blank=True, null=True)
    twilio_account_sid = models.CharField(max_length=500, blank=True, null=True)
    twilio_auth_key = models.CharField(max_length=500, blank=True, null=True)
    twilio_account_number = models.CharField(max_length=20, blank=True, null=True)
    storage_type = models.CharField(max_length=20, blank=True, null=True)
    s3_access_token = models.CharField(max_length=500, blank=True, null=True)
    s3_secret_access_token = models.CharField(max_length=500, blank=True, null=True)
    s3_bucket_name = models.CharField(max_length=200, blank=True, null=True)
    pre_signed_time_length = models.IntegerField(blank=True, null=True)
    scan_frequency = models.IntegerField(blank=True, null=True)
    application_status = models.BooleanField(default=False)
    analytics_status = models.BooleanField(default=False)
    frequency_changed = models.BooleanField(default=False)
    last_scan = models.DateTimeField(null=True, blank=True, default=timezone.now)
    next_scan = models.CharField(max_length=32, blank=True, null=True)
    next_scan_date = models.DateTimeField(null=True, blank=True, default=timezone.now)
    session_timeout_length = models.IntegerField(null=True, blank=True)
    manual_hours_purchased = models.CharField(max_length=200, blank=True, null=True)
    manual_hours_remaining = models.CharField(max_length=200, blank=True, null=True)
    max_ips = models.CharField(max_length=200, blank=True, null=True)
    time_zone = models.CharField(max_length=200, blank=True, null=True)
    auth_reset = models.BooleanField(default=False)

    def __str__(self):
        return self.client_name

    class Meta:
        verbose_name_plural = "Client Configuration"


@receiver(post_save, sender=ClientConfiguration)
def update_scan_frequency(sender, created, instance, **kwargs):
    scan_frequency = int(instance.scan_frequency)
    if instance.next_scan and scan_frequency:
        try:
            run_scan_task = PeriodicTask.objects.get(
                task='redtree_app.tasks.run_scan'
            )
            run_scan_cronobj = run_scan_task.crontab
        except:
            run_scan_cronobj = None
        try:
            run_masscan_task = PeriodicTask.objects.get(
                task='redtree_app.tasks.run_masscan'
            )
            run_masscan_cronobj = run_masscan_task.crontab
        except:
            run_masscan_cronobj = None
        try:
            sslyze_cipher_task = PeriodicTask.objects.get(
                task='redtree_app.tasks.sslyze_cipher'
            )
            sslyze_cipher_cronobj = sslyze_cipher_task.crontab
        except:
            sslyze_cipher_cronobj = None
        try:
            sshyze_cipher_task = PeriodicTask.objects.get(
                task='redtree_app.tasks.sshyze_cipher'
            )
            sshyze_cipher_cronobj = sshyze_cipher_task.crontab
        except:
            sshyze_cipher_cronobj = None
        try:
            generate_application_scan_task = PeriodicTask.objects.get(
                task='redtree_app.tasks.generate_application_scan'
            )
            generate_application_scan_cronobj = generate_application_scan_task.crontab
        except:
            generate_application_scan_cronobj = None
        try:
            domain_enum_task = PeriodicTask.objects.get(
                task='redtree_app.tasks.domain_enum'
            )
            domain_enum_cronobj = domain_enum_task.crontab
        except:
            domain_enum_cronobj = None
        try:
            application_screenshot_generator_task = PeriodicTask.objects.get(
                task='redtree_app.tasks.application_screenshot_generator'
            )
            application_screenshot_generator_cronobj = application_screenshot_generator_task.crontab
        except:
            application_screenshot_generator_cronobj = None
        try:
            cloudstorage_s3_bucket_scan_task = PeriodicTask.objects.get(
                task='redtree_app.tasks.cloudstorage_s3_bucket_scan'
            )
            cloudstorage_s3_bucket_scan_cronobj = cloudstorage_s3_bucket_scan_task.crontab
        except:
            cloudstorage_s3_bucket_scan_cronobj = None
        try:
            whois_scan_task = PeriodicTask.objects.get(
                task='redtree_app.tasks.whois_scan'
            )
            whois_scan_cronobj = whois_scan_task.crontab
        except:
            whois_scan_cronobj = None

        if run_scan_cronobj:
            if scan_frequency > 1:
                run_scan_cronobj.day_of_month=instance.next_scan
            else:
                run_scan_cronobj.day_of_month="*"
            run_scan_cronobj.save()

        if run_masscan_cronobj:
            if scan_frequency > 1:
                run_masscan_cronobj.day_of_month=instance.next_scan
            else:
                run_masscan_cronobj.day_of_month="*"
            run_masscan_cronobj.save()

        if sslyze_cipher_cronobj:
            if scan_frequency > 1:
                sslyze_cipher_cronobj.day_of_month=instance.next_scan
            else:
                sslyze_cipher_cronobj.day_of_month="*"
            sslyze_cipher_cronobj.save()

        if sshyze_cipher_cronobj:
            if scan_frequency > 1:
                sshyze_cipher_cronobj.day_of_month=instance.next_scan
            else:
                sshyze_cipher_cronobj.day_of_month="*"
            sshyze_cipher_cronobj.save()

        if generate_application_scan_cronobj:
            if scan_frequency > 1:
                generate_application_scan_cronobj.day_of_month=instance.next_scan
            else:
                generate_application_scan_cronobj.day_of_month="*"
            generate_application_scan_cronobj.save()

        if domain_enum_cronobj:
            if scan_frequency > 1:
                domain_enum_cronobj.day_of_month=instance.next_scan
            else:
                domain_enum_cronobj.day_of_month="*"
            domain_enum_cronobj.save()

        if application_screenshot_generator_cronobj:
            if scan_frequency > 1:
                application_screenshot_generator_cronobj.day_of_month=instance.next_scan
            else:
                application_screenshot_generator_cronobj.day_of_month="*"
            application_screenshot_generator_cronobj.save()

        if cloudstorage_s3_bucket_scan_cronobj:
            if scan_frequency > 1:
                cloudstorage_s3_bucket_scan_cronobj.day_of_month=instance.next_scan
            else:
                cloudstorage_s3_bucket_scan_cronobj.day_of_month="*"
            cloudstorage_s3_bucket_scan_cronobj.save()

        if whois_scan_cronobj:
            if scan_frequency > 1:
                whois_scan_cronobj.day_of_month=instance.next_scan
            else:
                whois_scan_cronobj.day_of_month="*"
            whois_scan_cronobj.save()


class PurpleleafUsers(BaseModel):
    user_email = models.EmailField(null=True, blank=True)
    user_name = models.CharField(max_length=30, null=True, blank=True)
    purpleleaf_id = models.CharField(max_length=30, null=True, blank=True)
    active = models.BooleanField(default=False)
    activation_key = models.CharField(max_length=40, null=True, blank=True)
    def __str__(self):
        return self.user_email

    class Meta:
        verbose_name_plural = "Purpleleaf Users"


class NotificationEmails(BaseModel):
    email = models.CharField(max_length=50, blank=True, null=True)

    def __str__(self):
        return self.email

    class Meta:
        verbose_name_plural = "Notification Emails List"


class Networks(BaseModel):
    network = models.CharField(max_length=100, null=True, blank=True)
    network_type = models.CharField(max_length=20, blank=True, null=True)

    def __str__(self):
        return str(self.network)

    def ip_count(self):
        host_obj = UserHosts.objects.filter(
            network=self
            )
        if host_obj:
            host_count = host_obj.aggregate(host_sum=Sum('count'))['host_sum']
        else:
            host_count = 0
        return host_count

    def vulnerabilities(self):
        host_count = 0
        hosts = UserHosts.objects.filter(
            network=self
        )
        if hosts:
            host_count = hosts.aggregate(host_sum=Sum('count'))['host_sum']
        vulnerability_obj = Vulnerability.objects.filter(
            host__user_host__network=self)
        active_hosts = vulnerability_obj.distinct('host').count()
        open_ports_vulnerabilities = vulnerability_obj.filter(
            title="Open TCP Port"
            )
        vulnerabilities_data = {
            'count': vulnerability_obj.count(),
            'critical': vulnerability_obj.filter(risk='Critical').count(),
            'medium': vulnerability_obj.filter(risk='Medium').count(),
            'high': vulnerability_obj.filter(risk='High').count(),
            'low': vulnerability_obj.filter(risk='Low').count(),
            'active_ips_count': active_hosts,
            'host_count': host_count
        }
        return vulnerabilities_data

    class Meta:
        verbose_name_plural = "Networks"



class ClientAwsAssets(BaseModel):
    client_aws_access_token = models.CharField(max_length=512, blank=True, null=True)
    client_aws_secret_token = models.CharField(max_length=512, blank=True, null=True)
    token_description = models.CharField(max_length=25, blank=True, null=True)
    scan_status = models.BooleanField(default=False)
    scan_state = models.CharField(max_length=256, blank=True, null=True, default="NotInitiated")
    ec2_count = models.IntegerField(blank=True, null=True)
    s3_count = models.IntegerField(blank=True, null=True)
    rds_count = models.IntegerField(blank=True, null=True)
    application_count = models.IntegerField(blank=True, null=True)

    def __str__(self):
        return '{} - {}'.format(
        self.client_aws_access_token,
        self.client_aws_secret_token
        )

    class Meta:
        verbose_name_plural = "Client Aws Assets"


class UserHosts(BaseModel):
    host = models.CharField(max_length=500, null=True, blank=True)
    host_type = models.CharField(max_length=100, null=True, blank=True)
    network = models.ForeignKey(Networks, related_name="network_hosts")
    count = models.IntegerField(null=True, blank=True)
    aws_link = models.ForeignKey(ClientAwsAssets, null=True, blank=True, related_name="user_aws_hosts")
    aws_existence = models.BooleanField(default=False)
    service = models.CharField(max_length=100, blank=True, null=True)
    source = models.CharField(max_length=20, null=True, blank=True, default="user")
    owner = models.CharField(max_length=100, null=True, blank=True)
    host_network_type = models.CharField(max_length=10, null=True, blank=True)

    def __str__(self):
        return "{} - {}".format(self.host_type, self.host)

    class Meta:
        verbose_name_plural = "User Hosts"
        db_table = 'user_hosts'

    @property
    def related_host_id(self):
        if self.host_type in ['ip', 'host_name']:
            return self.user_host.first().id
        else:
            return self.id


@receiver(post_save, sender=UserHosts)
def update_host(sender, created, instance, **kwargs):
    if created:
        if instance.host_type in ['ip', 'host_name']:
            Host.objects.create(
                user_host=instance,
                host=instance.host
            )



class Host(BaseModel):
    user_host = models.ForeignKey(UserHosts, related_name="user_host")
    host = models.CharField(max_length=500, null=True, blank=True)

    def __str__(self):
        return "{}".format(self.host)

    class Meta:
        verbose_name_plural = "Hosts"
        db_table = 'hosts'


def nessus_directory_path(instance, filename):

    return 'NessusFiles/{}'.format(filename)


class NessusFile(BaseModel):
    file = models.FileField(upload_to=nessus_directory_path, blank=True, null=True)
    file_code = models.CharField(max_length=500, null=True, blank=True)
    low_risk_count = models.CharField(max_length=100, null=True, blank=True)
    medium_risk_count = models.CharField(max_length=100, null=True, blank=True)
    high_risk_count = models.CharField(max_length=100, null=True, blank=True)
    critical_risk_count = models.CharField(max_length=100, null=True, blank=True)
    low_new_issue = models.CharField(max_length=100, null=True, blank=True)
    medium_new_issue = models.CharField(max_length=100, null=True, blank=True)
    high_new_issue = models.CharField(max_length=100, null=True, blank=True)
    critical_new_issue = models.CharField(max_length=100, null=True, blank=True)
    uploaded_at = models.DateField(auto_now_add=True)
    xml_process_status = models.BooleanField(default=False)
    applications_process_status = models.BooleanField(default=False)
    vulnerabilities_process_status = models.BooleanField(default=False)
    is_accepted = models.BooleanField(default=False)
    hosts_list = models.TextField(null=True, blank=True)
    is_completed = models.BooleanField(default=False)
    error_message = models.TextField(null=True, blank=True)

    def __str__(self):
        return "{}".format(self.file)

    class Meta:
        verbose_name_plural = "Nessus Files"


@receiver(models.signals.post_delete, sender=NessusFile)
def auto_delete_nessus_file_on_delete(sender, instance, **kwargs):
    if instance.file:
        if os.path.isfile(instance.file.path):
            os.remove(instance.file.path)


class NessusData(BaseModel):
    linked_file = models.ForeignKey(NessusFile)
    plugin_id = models.IntegerField(null=True, blank=True)
    risk = models.CharField(max_length=100, null=True, blank=True)
    host = models.CharField(max_length=200, null=True, blank=True)
    user_host = models.ForeignKey(UserHosts, related_name="user_host_issues", null=True, blank=True)
    host_link = models.ForeignKey(Host, related_name="host_issues", null=True, blank=True)
    protocol = models.CharField(max_length=100, null=True, blank=True)
    port = models.IntegerField(null=True, blank=True)
    name = models.CharField(max_length=500, null=True, blank=True)
    svc_type = models.CharField(max_length=100, null=True, blank=True)
    first_identified = models.CharField(max_length=50, null=True, blank=True)
    last_seen = models.CharField(max_length=256, null=True, blank=True)
    confirmed = models.BooleanField(default=False)
    date_confirmed = models.DateField(null=True, blank=True)
    description = models.TextField(null=True, blank=True)
    synopsis = models.TextField(null=True, blank=True)
    solution = models.TextField(null=True, blank=True)
    plugin_output = models.TextField(null=True, blank=True)
    virtue_id = models.IntegerField(null=True, blank=True)
    banner = models.CharField(max_length=1000, null=True, blank=True)

    def __str__(self):
        return self.name

    @property
    def service_count(self):
        ser = NessusData.objects.filter(
            svc_type=self.svc_type,
            host_link=self.host_link,
            port=self.port
        ).count()
        return ser

    class Meta:
        verbose_name_plural = "Nessus Data"


class NessusFileRecord(BaseModel):
    file = models.ForeignKey(NessusFile)
    issues_read = models.CharField(max_length=50, null=True, blank=True)
    issues_detected = models.CharField(max_length=50, null=True, blank=True)
    issues_undetected = models.CharField(max_length=50, null=True, blank=True)
    duplicate_issues = models.CharField(max_length=50, null=True, blank=True)

    def __str__(self):
        return self.issues_read

    class Meta:
        verbose_name_plural = "Nessus File Record"


try:
    client_conf_obj = ClientConfiguration.objects.first()
except:
    client_conf_obj = None


class Applications(BaseModel):
    scope_choices = [
        ("black", "black"), 
        ("grey", "grey"), 
        ("white", "white")
    ]
    host = models.ForeignKey(UserHosts, related_name="user_host_applications", null=True, blank=True)
    host_link = models.ForeignKey(Host, related_name="host_applications", null=True, blank=True)
    application_url = models.CharField(max_length=100, null=True, blank=True)
    application_title = models.CharField(max_length=100, null=True, blank=True)
    screenshot_filename = models.CharField(max_length=100, null=True, blank=True)
    screenshot_path = models.TextField(null=True, blank=True)
    scope = models.CharField(max_length=20, 
        choices=scope_choices, null=True, blank=True, 
        default=scope_choices[0][0]
        )
    network_type = models.CharField(max_length=20, blank=True, null=True)
    scanning_enabled = models.BooleanField(default=True)
    burp_scanning = models.BooleanField(default=False)
    last_seen = models.DateTimeField(null=True, blank=True)
    last_scan = models.DateTimeField(null=True, blank=True)
    screenshot_title = models.BooleanField(default=False)

    def __str__(self):
        return str(self.application_url)

    @property
    def s3_image(self):
        if client_conf_obj and client_conf_obj.storage_type=="S3":
            if self.screenshot_filename:
                image_key = ''.join(['screenshots/', self.screenshot_filename])
                media_uploader = MediaUploader(client_conf_obj, image_key)
                s3_image_link = media_uploader.get_link()
                return s3_image_link
        if client_conf_obj and client_conf_obj.storage_type == "local":
            if self.screenshot_filename:
                s3_image_link = ''.join(self.screenshot_path)
                return s3_image_link

    class Meta:
        verbose_name_plural = "Applications"


@receiver(post_save, sender=Applications)
def send_application_notification(sender, created, instance, **kwargs):
    if created:
        from redtree_app.tasks import (
            app_screenshot_generator
        )   # to remove circular dependency
        app_screenshot_generator.delay(
            id=instance.id
        )


class Vulnerability(BaseModel):
    virtue_id = models.IntegerField(null=True, blank=True)
    plugin_id = models.CharField(max_length=500, null=True, blank=True)
    host_ip = models.CharField(max_length=500, blank=True, null=True)
    host = models.ForeignKey(Host, related_name="host_vulnerability")
    port = models.CharField(max_length=200, null=True, blank=True)
    risk = models.CharField(max_length=200, null=True, blank=True)
    title = models.CharField(max_length=500, null=True, blank=True)
    banner = models.CharField(max_length=1000, null=True, blank=True)
    description = MarkdownxField(null=True, blank=True)
    remediation = MarkdownxField(null=True, blank=True)
    evidence = MarkdownxField(null=True, blank=True)
    post_status = models.BooleanField(default=False)
    masscan_post_status = models.BooleanField(default=False)
    network_type = models.CharField(max_length=500, null=True, blank=True)
    modified_date = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return self.title

    def retest(self):
        try:
            retest_obj = self.retest
        except RetestVulnerabilities.DoesNotExist:
            retest_obj = RetestVulnerabilities.objects.create(
                vulnerability=self
            )
        return retest_obj.status
        
    @property
    def formatted_description(self):
        markdown_images = get_markdown_with_images(self.description)
        return markdownify(markdown_images)

    @property
    def formatted_remediation(self):
        markdown_images = get_markdown_with_images(self.remediation)
        return markdownify(markdown_images)

    @property
    def formatted_evidence(self):
        if self.evidence:
            markdown_images = get_markdown_with_images(self.evidence)
            return markdownify(markdown_images)

    @property
    def retest_note(self):
        return self.retest_notes.all()

    class Meta:
        verbose_name_plural = "Vulnerabilities"


@receiver(post_save, sender=Vulnerability)
def update_chart(sender, created, instance, **kwargs):
    if created:
        from utils.views import update_vulnerabilities_chart
        update_vulnerabilities_chart()


@receiver(models.signals.pre_delete, sender=Vulnerability)
def delete_ciphers(sender, instance, **kwargs):
    from playground.models import SshyzeCiphers   # to remove circular dependency
    if instance.title == "Open TCP Port":
        Ciphers.objects.filter(
            host=instance.host,port=instance.port
        ).delete()
        SslyzeCertificates.objects.filter(
            host=instance.host,port=instance.port
        ).delete()
        SshyzeCiphers.objects.filter(
            host=instance.host,port=instance.port
        ).delete()


@receiver(models.signals.post_delete, sender=Host)
def delete_ciphers(sender, instance, **kwargs):
    from playground.models import SshyzeCiphers   # to remove circular dependency
    from utils.views import update_vulnerabilities_chart
    Ciphers.objects.filter(
        host=instance.host
    ).delete()
    SslyzeCertificates.objects.filter(
        host=instance.host
    ).delete()
    SshyzeCiphers.objects.filter(
        host=instance.host
    ).delete()
    update_vulnerabilities_chart()


class TestVulnerabilities(BaseModel):
    virtue_id = models.IntegerField(null=True, blank=True)
    nessus_id = models.ForeignKey(NessusData, null=True, blank=True)
    plugin_id = models.CharField(max_length=500, null=True, blank=True)
    port = models.CharField(max_length=200, null=True, blank=True)
    host_ip = models.CharField(max_length=700, null=True, blank=True)
    host = models.ForeignKey(Host, related_name="host_test_vulnerability")
    risk = models.CharField(max_length=200, null=True, blank=True)
    title = models.CharField(max_length=500, null=True, blank=True)
    banner = models.CharField(max_length=1000, null=True, blank=True)
    description = MarkdownxField(null=True, blank=True)
    remediation = MarkdownxField(null=True, blank=True)
    evidence = MarkdownxField(null=True, blank=True)
    post_status = models.BooleanField(default=False)
    modified_date = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return self.title

    @property
    def formatted_description(self):
        return markdownify(self.description)

    @property
    def formatted_remediation(self):
        return markdownify(self.remediation)

    @property
    def formatted_evidence(self):
        return markdownify(self.evidence)

    class Meta:
        verbose_name_plural = "Test Vulnerabilities"


class RetestVulnerabilities(BaseModel):
    vulnerability = models.OneToOneField(
        Vulnerability,
        related_name="retest",
        on_delete=models.CASCADE
    )
    issue_id = models.CharField(max_length=10, null=True, blank=True)
    status = models.CharField(max_length=50, null=True, blank=True)
    host = models.CharField(max_length=50, null=True, blank=True)

    def __str__(self):
        return "{} - {}".format(self.vulnerability.title, self.status)

    class Meta:
        verbose_name_plural = "Retest Vulnerability"


class Notifications(BaseModel):
    retest_id = models.IntegerField(null=True, blank=True)
    issue = models.CharField(max_length=100, blank=True, null=True)
    status= models.CharField(max_length=500, null=True, blank=True)
    seen = models.BooleanField(default=False)

    def __str__(self):
        return "{} {}".format(self.issue, self.status)

    class Meta:
        verbose_name_plural = "Notifications"


@receiver(post_save, sender=RetestVulnerabilities)
def update_notifications(sender, instance, **kwargs):
    if instance.status == "Requested":
        RedtreeEventHistory.objects.create(
            event_type='retest',
            time_stamp=timezone.now().strftime('%s'),
            data=instance.vulnerability.title
        )
        Notifications.objects.create(
            retest_id=instance.id,
            issue=instance.vulnerability.title,
            status=instance.status
        )
        if os.environ.get('REDTREE_URL'):
            client_obj = ClientConfiguration.objects.first()
            notification_list = notification_list = list(NotificationEmails.objects.values_list(
                'email', flat=True
            ))
            redtree_url = os.environ.get('REDTREE_URL', '')
            redtree_retest_url = redtree_url+"/retest/"
            html_content = "{0} has requested a retest of {1}.<BR><BR><a href='{2}'>{2}</a>"\
                .format(client_obj.client_name, instance.vulnerability.title, redtree_retest_url)
            subject = "[{0}] New retest request generated".format(client_obj.client_name)
            reciever = notification_list
            send_mail(reciever, subject, html_content)
        else:
            logging.error('Environment variable is missing')


class CloudAssetsData(BaseModel):
    category_choices = [
        ("S3", "S3"),
        ("GCP", "GCP"),
        ("Azure", "Azure")
    ]
    category = models.CharField(max_length=20, choices=category_choices, null=True, blank=True, default=category_choices[0][0])
    bucket = models.CharField(max_length=100, blank=True, null=True)
    network = models.ForeignKey(Networks, null=True, blank=True, related_name="network_buckets")
    source = models.CharField(max_length=20, null=True, blank=True, default="user")
    aws_link = models.ForeignKey(ClientAwsAssets, null=True, blank=True, related_name="aws_buckets")
    last_scan = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return "{} - {}".format(self.category, self.bucket)

    class Meta:
        verbose_name_plural = "Cloud Assets Data"


class CloudstorageScanData(BaseModel):
    cloud_asset_bucket = models.ForeignKey(
        CloudAssetsData, null=True, on_delete=models.CASCADE,
        related_name="cloud_storage_scan_data"
    )
    authenticated_status = models.BooleanField(default=False)
    unauthenticated_status = models.BooleanField(default=False)
    bucket_name = models.TextField(null=True, blank=True)
    file = models.TextField(null=True, blank=True)

    def __str__(self):
        return "{} - {} - {}".format(
            self.cloud_asset_bucket,
            self.bucket_name,
            self.file
        )

    class Meta:
        verbose_name_plural = "Cloud Storage Scan Data"
        ordering = ['-id']


def report_directory_path(instance, filename):
    return 'Reports/{}/{}'.format(date.today(), filename)


class Reports(BaseModel):
    file = models.FileField(upload_to=report_directory_path)
    network_type = models.CharField(max_length=500, null=True, blank=True)

    def __str__(self):
        return str(self.file)

    @property
    def filename(self):
        if self.file and self.file.name:
            return os.path.basename(self.file.name)
        elif self.file_name:
            return self.file_name

    class Meta:
        verbose_name_plural = "Reports"

@receiver(models.signals.post_delete, sender=Reports)
def auto_delete_report_file_on_delete(sender, instance, **kwargs):
    if instance.file:
        if os.path.isfile(instance.file.path):
            os.remove(instance.file.path)


class NessusFileLog(models.Model):
    linked_file = models.ForeignKey(NessusFile, related_name="nessusfile_logs")
    issue_type = models.CharField(max_length=50, null=True, blank=True)
    issue = models.TextField(null=True, blank=True)
    created = models.DateField(auto_now_add=True)
    modified = models.DateField(auto_now=True)

    def __str__(self):
        return self.issue

    class Meta:
        verbose_name_plural = "Nessus File Logs"


class RetestNote(BaseModel):
    vulnerability = models.ForeignKey(Vulnerability, related_name="retest_notes", null=True, blank=True)
    note = models.TextField(null=True, blank=True)
    status = models.CharField(max_length=20, null=True, blank=True)
    vul_id = models.CharField(max_length=20, null=True, blank=True)

    def __str__(self):
        return "{} - {}".format(self.status, self.note)

    class Meta:
        verbose_name_plural = "Retest Notes"


@receiver(post_save, sender=RetestNote)
def close_vulnerability(sender, instance, **kwargs):
    if instance.status == "Closed":
        ClosedVulnerabilities.objects.create(
            title=instance.vulnerability.title,
            port=instance.vulnerability.port,
            risk=instance.vulnerability.risk,
            host=instance.vulnerability.host_ip,
            retest_note=instance.note,
            vulnerability_id=instance.vulnerability.id
        )
        ArchiveVulnerabilities.objects.create(
            virtue_id= instance.vulnerability.virtue_id,
            plugin_id= instance.vulnerability .plugin_id,
            host_ip=instance.vulnerability.host_ip,
            host= instance.vulnerability.host,
            port= instance.vulnerability.port,
            risk= instance.vulnerability.risk,
            title= instance.vulnerability.title,
            banner= instance.vulnerability.banner,
            description= instance.vulnerability.description,
            remediation= instance.vulnerability.remediation,
            evidence= instance.vulnerability.evidence,
            masscan_post_status= instance.vulnerability.masscan_post_status,
            network_type= instance.vulnerability.network_type,
            modified_date= instance.vulnerability.modified_date,
        )



class AppNotification(BaseModel):
    issue_type = models.CharField(max_length=100, blank=True, null=True)
    notification_message = models.TextField(blank=True, null=True)
    seen = models.BooleanField(default=False)

    def __str__(self):
        return self.notification_message

    class Meta:
        verbose_name_plural = "App Notifications"
        ordering = ['-id']


class RedtreeEventHistory(BaseModel):
    event_type = models.CharField(max_length=300, blank=True, null=True)
    time_stamp = models.CharField(max_length=300, blank=True, null=True)
    username = models.CharField(max_length=300, blank=True, null=True)
    ip = models.CharField(max_length=300, blank=True, null=True)
    data = models.TextField(blank=True, null=True)

    def __str__(self):
        return self.event_type

    class Meta:
        verbose_name_plural = "Redtree Event History"
        ordering = ['-created']


@receiver(post_save, sender=RedtreeEventHistory)
def update_error_notification(sender, created, instance, **kwargs):
    if created and instance.event_type == "error":
        AppNotification.objects.create(
            issue_type = instance.event_type,
            notification_message = instance.data
        )


class S3Uploads(BaseModel):
    filename = models.CharField(max_length=100, null=True, blank=True)
    key = models.CharField(max_length=100, null=True, blank=True)

    def __str__(self):
        return self.filename


class Ciphers(BaseModel):
    host = models.CharField(max_length=100, null=True, blank=True)
    port = models.CharField(max_length=100, null=True, blank=True)
    protocol = models.CharField(max_length=100, null=True, blank=True)
    cipher = models.CharField(max_length=100, null=True, blank=True)
    key_size = models.CharField(max_length=100, null=True, blank=True)
    strength = models.CharField(max_length=16, null=True, blank=True)

    def __str__(self):
        return '{}:{}'.format(self.host, self.port)

    class Meta:
        verbose_name_plural = "Ciphers"


class AwsRegion(BaseModel):
    region = models.CharField(max_length=100, null=True, blank=True)
    status = models.BooleanField(default=True)

    def __str__(self):
        return self.region


class ApplicationVulnerability(BaseModel):
    application = models.ForeignKey(
        Applications,
        null=True,
        blank=True,
        related_name='application_vulnerabilities',
        on_delete=models.CASCADE
    )
    virtue_id = models.IntegerField(null=True, blank=True)
    plugin_id = models.CharField(max_length=500, null=True, blank=True)
    port = models.CharField(max_length=200, null=True, blank=True)
    risk = models.CharField(max_length=200, null=True, blank=True)
    title = models.CharField(max_length=500, null=True, blank=True)
    banner = models.CharField(max_length=1000, null=True, blank=True)
    description = MarkdownxField(null=True, blank=True)
    remediation = MarkdownxField(null=True, blank=True)
    evidence = MarkdownxField(null=True, blank=True)
    post_status = models.BooleanField(default=False)
    application_scan_id = models.CharField(max_length=700, null=True, blank=True)
    modified_date = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return self.title

    @property
    def formatted_description(self):
        if self.description:
            markdown_text = markdownify(self.description)
            return get_markdown_with_images(markdown_text)
        else:
            return

    @property
    def formatted_remediation(self):
        if self.remediation:
            markdown_text = markdownify(self.remediation)
            return get_markdown_with_images(markdown_text)
        else:
            return

    @property
    def formatted_evidence(self):
        if self.evidence:
            markdown_text = markdownify(self.evidence)
            return get_markdown_with_images(markdown_text)
        else:
            return

    class Meta:
        verbose_name_plural = "Application Vulnerabilities"


class Appliances(BaseModel):
    appliance_ip = models.CharField(max_length=200, null=True, blank=True)
    port = models.CharField(max_length=200, null=True, blank=True, default=443)
    source_ip = models.CharField(max_length=200, null=True, blank=True)
    network_type = models.CharField(max_length=20, blank=True, null=True)

    def __str__(self):
        return self.appliance_ip

    class Meta:
        verbose_name_plural = 'Appliances'


@receiver(post_save, sender=Appliances)
def post_appliance(sender, instance, created, **kwargs):
    if created:
        appl_setting_obj = ApplianceSettings.objects.create(appliance=instance)
        appl_setting_obj.s3_bucket_scan_url = "https://{}:{}/cloudstorage/scan".format(instance.appliance_ip, instance.port)
        appl_setting_obj.nessus_url = "https://{}:8834".format(instance.appliance_ip)
        appl_setting_obj.nessus_driver_url = "https://{}:{}/nessus/".format(instance.appliance_ip, instance.port)
        appl_setting_obj.microservice_scan_url = "https://{}:{}/sslyze/scan/new".format(instance.appliance_ip, instance.port)
        appl_setting_obj.sshyze_scan_url = "https://{}:{}/sshyze/scan/new".format(instance.appliance_ip, instance.port)
        appl_setting_obj.burp_url = "https://{}:{}/burp/scan/new".format(instance.appliance_ip, instance.port)
        appl_setting_obj.masscan_ip_address = "https://{}:{}/masscan/scan/new".format(instance.appliance_ip, instance.port)
        appl_setting_obj.webscreenshot_app_url = "https://{}:{}/screenshot/post_url/".format(instance.appliance_ip, instance.port)
        appl_setting_obj.dnsenum_url = "https://{}:{}/dnsenum/scan/new".format(instance.appliance_ip, instance.port)
        appl_setting_obj.cloudstorage_url = "https://{}:{}/cloudstorage/scan".format(instance.appliance_ip, instance.port)
        appl_setting_obj.save()
        if instance.network_type == "Internal":
            from redtree_app.tasks import get_source_ip
            get_source_ip.delay(appliance_id=instance.id)
    else:
        appl_setting_obj = instance.appliance_setting
        appl_setting_obj.s3_bucket_scan_url = "https://{}:{}/cloudstorage/scan".format(instance.appliance_ip, instance.port)
        appl_setting_obj.nessus_url = "https://{}:8834".format(instance.appliance_ip)
        appl_setting_obj.nessus_driver_url = "https://{}:{}/nessus/".format(instance.appliance_ip, instance.port)
        appl_setting_obj.microservice_scan_url = "https://{}:{}/sslyze/scan/new".format(instance.appliance_ip, instance.port)
        appl_setting_obj.sshyze_scan_url = "https://{}:{}/sshyze/scan/new".format(instance.appliance_ip, instance.port)
        appl_setting_obj.burp_url = "https://{}:{}/burp/scan/new".format(instance.appliance_ip, instance.port)
        appl_setting_obj.masscan_ip_address = "https://{}:{}/masscan/scan/new".format(instance.appliance_ip, instance.port)
        appl_setting_obj.webscreenshot_app_url = "https://{}:{}/screenshot/post_url/".format(instance.appliance_ip, instance.port)
        appl_setting_obj.dnsenum_url = "https://{}:{}/dnsenum/scan/new".format(instance.appliance_ip, instance.port)
        appl_setting_obj.cloudstorage_url = "https://{}:{}/cloudstorage/scan".format(instance.appliance_ip, instance.port)
        appl_setting_obj.save()


class ApplianceSettings(BaseModel):
    appliance = models.OneToOneField(Appliances, related_name='appliance_setting')
    auth_username = models.CharField(max_length=128, blank=True, null=True, default="test")
    auth_password = models.CharField(max_length=128, blank=True, null=True, default="testpassword")
    s3_bucket_scan_url = models.CharField(max_length=500, blank=True, null=True)
    access_token = models.CharField(max_length=500, blank=True, null=True, default="AKIAIFYY77MPTLPF44HQ")
    secret_access_token = models.CharField(max_length=500, blank=True, null=True, default="WPLi2dQdwzID4CKiGvTWxIuYCPUM8mDmT+Ua1JZH")
    nessus_url = models.CharField(max_length=200, blank=True, null=True)
    nessus_username = models.CharField(max_length=200, blank=True, null=True, default="redtree")
    nessus_password = models.CharField(max_length=200, blank=True, null=True, default="redtree1234!")
    nessus_driver_url = models.CharField(max_length=200, blank=True, null=True)
    max_simul_hosts = models.IntegerField(blank=True, null=True, default="500")
    microservice_scan_url = models.CharField(max_length=500, blank=True, null=True)
    sslyze_max_simul_hosts = models.IntegerField(blank=True, null=True, default=10)
    sshyze_scan_url = models.CharField(max_length=500, blank=True, null=True)
    sshyze_max_simul_hosts = models.IntegerField(blank=True, null=True, default=10)
    burp_url =  models.CharField(max_length=500, blank=True, null=True)
    masscan_ip_address = models.CharField(max_length=200, blank=True, null=True)
    masscan_ports = models.CharField(max_length=200, blank=True, null=True, default='1-65535')
    masscan_maximum_hosts_per_scan = models.CharField(max_length=200, blank=True, null=True, default="10")
    webscreenshot_app_url = models.CharField(max_length=500, blank=True, null=True)
    dnsenum_url = models.CharField(max_length=500, blank=True, null=True)
    cloudstorage_url = models.CharField(max_length=256, blank=True, null=True)

    def __str__(self):
        return str(self.appliance)

    class Meta:
        verbose_name_plural = "Appliance Settings"


class Domains(BaseModel):
    domain_name = models.CharField(max_length=350, null=True, blank=True)
    purpleleaf_id = models.CharField(max_length=20, null=True, blank=True)
    network_type = models.CharField(max_length=56, blank=True, null=True)

    class Meta:
        verbose_name_plural = "Domains"
        ordering = ['-id']

    def __str__(self):
        return self.domain_name

    @property
    def get_subdomains(self):
        return self.subdomains.all()


@receiver(post_save, sender=Domains)
def process_dnsenum(sender, instance, created, **kwargs):
    if created:
        from redtree_app.tasks import domain_enum
        domain_enum.delay(scan_type="Prior", target_id=instance.id)


class HistoricalData(BaseModel):
    active_ips = models.CharField(max_length=300, blank=True, null=True)
    open_ports = models.CharField(max_length=300, blank=True, null=True)
    last_update = models.DateField(auto_now=True)

    def __str__(self):
        return str(self.active_ips)


class RiskHistoricalData(BaseModel):
    critical_risk = models.CharField(max_length=300, blank=True, null=True)
    high_risk = models.CharField(max_length=300, blank=True, null=True)
    medium_risk = models.CharField(max_length=300, blank=True, null=True)
    low_risk = models.CharField(max_length=300, blank=True, null=True)
    last_update = models.DateField(auto_now=True)

    def __str__(self):
        return str(self.created)

    class Meta:
        ordering = ['-id']


class EnumeratedSubdomains(BaseModel):
    domain = models.ForeignKey(Domains, related_name="subdomains", on_delete=models.CASCADE)
    subdomain = models.CharField(max_length=400, null=True, blank=True)
    in_scope = models.BooleanField(default=False)
    domain_host = models.CharField(max_length=24, null=True, blank=True)
    client_confirmed = models.BooleanField(default=False)
    client_confirmed_date = models.DateField(blank=True, null=True)

    def __str__(self):
        return "{}-{}".format(self.domain, self.subdomain)


    class Meta:
        ordering = ['-id']


class PurpleleafEventHistory(BaseModel):
    event_type = models.CharField(max_length=300, blank=True, null=True)
    time_stamp = models.CharField(max_length=300, blank=True, null=True)
    username = models.CharField(max_length=300, blank=True, null=True)
    ip = models.CharField(max_length=300, blank=True, null=True)
    data = models.TextField(blank=True, null=True)

    def __str__(self):
        return self.event_type

    class Meta:
        verbose_name_plural = "Purpleleaf Event History"
        ordering = ['-created']


class PurpleleafUserEventHistory(BaseModel):
    event_type = models.TextField(blank=True, null=True)
    time_stamp = models.CharField(max_length=300, blank=True, null=True)
    username = models.CharField(max_length=300, blank=True, null=True)
    ip = models.CharField(max_length=300, blank=True, null=True)
    data = models.TextField(blank=True, null=True)

    def __str__(self):
        return self.event_type

    class Meta:
        verbose_name_plural = "PurpleleafUser Event History"
        ordering = ['-created']


class RedtreeUserEventHistory(BaseModel):
    event_type = models.TextField(blank=True, null=True)
    time_stamp = models.CharField(max_length=300, blank=True, null=True)
    username = models.CharField(max_length=300, blank=True, null=True)
    ip = models.CharField(max_length=300, blank=True, null=True)
    data = models.TextField(blank=True, null=True)

    def __str__(self):
        return self.event_type

    class Meta:
        verbose_name_plural = "RedtreeUser Event History"
        ordering = ['-created']


class ActivityLog(BaseModel):
    activity = models.CharField(max_length=1000, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_modified_at = models.DateTimeField(auto_now=True)


    def __str__(self):
        return self.activity

    class Meta:
        verbose_name_plural = "Activity Logs"


class ClosedVulnerabilities(BaseModel):
    title = models.TextField(null=True, blank=True)
    host = models.CharField(max_length=100, null=True, blank=True)
    port = models.IntegerField(null=True, blank=True)
    risk = models.CharField(max_length=50, null=True, blank=True)
    retest_note = models.TextField(null=True, blank=True)
    vulnerability_id = models.IntegerField(blank=True, null=True)
    closed_date = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.title

    class Meta:
        ordering = ['-closed_date']
        verbose_name_plural = "Closed Vulnerabilities"


class ArchiveVulnerabilities(BaseModel):
    virtue_id = models.IntegerField(null=True, blank=True)
    plugin_id = models.CharField(max_length=500, null=True, blank=True)
    host_ip = models.CharField(max_length=500, blank=True, null=True)
    host = models.ForeignKey(Host, related_name="archived_vulnerabilities")
    port = models.CharField(max_length=200, null=True, blank=True)
    risk = models.CharField(max_length=200, null=True, blank=True)
    title = models.CharField(max_length=500, null=True, blank=True)
    banner = models.CharField(max_length=1000, null=True, blank=True)
    description = MarkdownxField(null=True, blank=True)
    remediation = MarkdownxField(null=True, blank=True)
    evidence = MarkdownxField(null=True, blank=True)
    masscan_post_status = models.BooleanField(default=False)
    network_type = models.CharField(max_length=500, null=True, blank=True)
    modified_date = models.DateTimeField(default=timezone.now)
    archive_date = models.DateField(auto_now_add=True)
    
    def __str__(self):
        return self.title

    class Meta:
        verbose_name_plural = "Archived Vulnerabilities"

class AwsDomains(models.Model):
    aws_link = models.ForeignKey(ClientAwsAssets,
        null=True,blank=True,
        related_name="aws_domains"
    )
    domain = models.CharField(max_length=500, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_modified_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return "{}".format(self.domain)

    class Meta:
        ordering = ['-id']
        verbose_name_plural = "Aws Domains"


class LogMicroServiceDnsEnum(LoggingBaseModel):
    domain = models.ForeignKey(
        Domains, null=True, on_delete=models.SET_NULL,
        related_name="dnsenum_logs"
    )

    def __str__(self):
        return "{} - {}".format(self.domain, self.status)

    class Meta:
        db_table = 'log_microservice_dnsenum'
        ordering = ['-id']

class LogMicroServiceBurp(LoggingBaseModel):
    application = models.ForeignKey(
        Applications, null=True, on_delete=models.SET_NULL,
        related_name="burp_logs"
    )

    def __str__(self):
        return "{} - {}".format(self.application, self.status)

    class Meta:
        db_table = 'log_microservice_burp'
        ordering = ['-id']


class LogMicroServiceSslyze(LoggingBaseModel):
    host = models.CharField(max_length=128, null=True, blank=True)
    port = models.IntegerField(null=True, blank=True)

    def __str__(self):
        return "{}:{} - {}".format(self.host, self.port, self.status)

    class Meta:
        db_table = 'log_microservice_sslyze'
        ordering = ['-id']


class SslyzeCertificates(BaseModel):
    host = models.CharField(max_length=128, null=True, blank=True)
    port = models.IntegerField(null=True, blank=True)
    verified_certificate_chain = models.BooleanField(default=False)
    sha1_in_chain = models.BooleanField(default=False)
    subject = models.TextField(null=True, blank=True)
    common_name = models.TextField(null=True, blank=True)
    algorithm = models.CharField(max_length=128, null=True, blank=True)

    def __str__(self):
        return "{}:{} - {}".format(self.host, self.port, self.common_name)

    class Meta:
        db_table = 'sslyze_certificates'
        ordering = ['-id']


class LogMicroServiceSshyze(LoggingBaseModel):
    host = models.CharField(max_length=128, null=True, blank=True)
    port = models.IntegerField(null=True, blank=True)

    def __str__(self):
        return "{}:{} - {}".format(self.host, self.port, self.status)

    class Meta:
        db_table = 'log_microservice_sshyze'
        ordering = ['-id']


class LogMicroServiceMasscan(LoggingBaseModel):
    ips = models.TextField(null=True, blank=True)

    def __str__(self):
        return "{}".format(self.status)

    class Meta:
        db_table = 'log_microservice_masscan'
        ordering = ['-id']


class LogMicroServiceScreenshot(LoggingBaseModel):
    application = models.ForeignKey(
        Applications, null=True, on_delete=models.SET_NULL,
        related_name="screenshot_logs"
    )

    def __str__(self):
        return "{} - {}".format(self.application, self.status)

    class Meta:
        db_table = 'log_microservice_screenshot'
        ordering = ['-id']


class LogMicroServiceCloudstorage(LoggingBaseModel):
    bucket = models.ForeignKey(
        CloudAssetsData, null=True, on_delete=models.SET_NULL,
        related_name="cloudstorage_logs"
    )

    def __str__(self):
        return "{} - {}".format(self.bucket, self.status)

    class Meta:
        db_table = 'log_microservice_cloudstorage'
        ordering = ['-id']


class LogMicroServiceWhois(LoggingBaseModel):
    host = models.ForeignKey(
        UserHosts, null=True, on_delete=models.SET_NULL,
        related_name="whois_logs"
    )
    domain_host = models.CharField(max_length=400, null=True, blank=True)

    def __str__(self):
        return "{} - {}".format(self.host, self.status)

    class Meta:
        db_table = 'log_microservice_whois'
        ordering = ['-id']


class LogMicroServiceNessus(LoggingBaseModel):
    ips = models.TextField(null=True, blank=True)

    def __str__(self):
        return "{}".format(self.status)

    class Meta:
        db_table = 'log_microservice_nessus'
        ordering = ['-id']


class AwsApiGateway(BaseModel):
    api_url = models.URLField(max_length=300, null=True, blank=True)
    asset_link = models.ForeignKey(ClientAwsAssets, null=True, blank=True,
        related_name="aws_gateway_api", on_delete=models.CASCADE
    )
    region = models.CharField(max_length=56, null=True, blank=True)
    content = models.TextField(null=True, blank=True)
    status_code = models.CharField(max_length=10, null=True, blank=True)
    last_scan = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return "{}".format(self.api_url)

    class Meta:
        db_table = 'aws_api_gateway'
        ordering = ['-id']


class AwsRdsEndpoint(BaseModel):
    host = models.CharField(max_length=300, null=True, blank=True)
    port = models.IntegerField(null=True, blank=True)
    asset_link = models.ForeignKey(ClientAwsAssets, null=True, blank=True,
        related_name="rds_endpoints", on_delete=models.CASCADE
    )
    region = models.CharField(max_length=56, null=True, blank=True)
    scan_status = models.NullBooleanField(default=None)
    last_scan = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return "{}:{}".format(self.host, self.port)

    class Meta:
        db_table = 'aws_rds_endpoints'
        ordering = ['-id']


class WhoisRecord(BaseModel):
    ip = models.ForeignKey(UserHosts, null=True, blank=True,
        on_delete=models.CASCADE, related_name="whois")
    domain_host = models.CharField(max_length=300, null=True, blank=True)
    asn = models.TextField(null=True, blank=True)
    raw = models.TextField(null=True, blank=True)
    asn_registry = models.TextField(null=True, blank=True)
    asn_country_code = models.TextField(null=True, blank=True)
    asn_date = models.TextField(null=True, blank=True)
    asn_cidr = models.TextField(null=True, blank=True)
    raw_referral = models.TextField(null=True, blank=True)
    nir = models.TextField(null=True, blank=True)
    query = models.TextField(null=True, blank=True)
    referral = models.TextField(null=True, blank=True)
    asn_description = models.TextField(null=True, blank=True)
    city = models.TextField(null=True, blank=True)
    longitude = models.CharField(max_length=256, null=True, blank=True)
    latitude = models.CharField(max_length=256, null=True, blank=True)

    def __str__(self):
        return "{}".format(self.ip)

    class Meta:
        db_table = 'whois_records'
        ordering = ['-id']

    def nets(self):
        return self.whois_nets.all()

    @property
    def whois_net(self):
        return WhoisNetsRecord.objects.filter(whois_record__asn=self.asn)


class WhoisNetsRecord(BaseModel):
    whois_record = models.ForeignKey(WhoisRecord, null=True, blank=True,
        on_delete=models.CASCADE, related_name="whois_nets")
    handle = models.TextField(null=True, blank=True)
    description = models.TextField(null=True, blank=True)
    postal_code = models.TextField(null=True, blank=True)
    address = models.TextField(null=True, blank=True)
    cidr = models.TextField(null=True, blank=True)
    city = models.TextField(null=True, blank=True)
    name = models.TextField(null=True, blank=True)
    created = models.TextField(null=True, blank=True)
    country = models.TextField(null=True, blank=True)
    state = models.TextField(null=True, blank=True)
    ranges = models.TextField(null=True, blank=True)
    updated = models.TextField(null=True, blank=True)
    end_address = models.TextField(null=True, blank=True)
    ip_version = models.TextField(null=True, blank=True)
    parent_handle = models.TextField(null=True, blank=True)
    start_address = models.TextField(null=True, blank=True)
    net_type = models.TextField(null=True, blank=True)
    status = models.TextField(null=True, blank=True)
    remarks = models.TextField(null=True, blank=True)

    def __str__(self):
        return "{}".format(self.whois_record)

    class Meta:
        db_table = 'whois_nets_records'
        ordering = ['-id']

    def emails(self):
        return self.whois_net_emails.all()

    def notices(self):
        return self.whois_net_notices.all()

    def events(self):
        return self.whois_net_events.all()

    def links(self):
        return self.whois_net_links.all()


class WhoisNetNoticesRecord(BaseModel):
    whois_net = models.ForeignKey(WhoisNetsRecord, null=True, blank=True,
        on_delete=models.CASCADE, related_name="whois_net_notices")
    description = models.TextField(null=True, blank=True)
    links = models.TextField(null=True, blank=True)
    title = models.TextField(null=True, blank=True)

    def __str__(self):
        return "{}".format(self.title)

    class Meta:
        db_table = 'whois_nets_notices_records'
        ordering = ['-id']


class WhoisNetEventsRecord(BaseModel):
    whois_net = models.ForeignKey(WhoisNetsRecord, null=True, blank=True,
        on_delete=models.CASCADE, related_name="whois_net_events")
    action = models.TextField(null=True, blank=True)
    actor = models.TextField(null=True, blank=True)
    timestamp = models.TextField(null=True, blank=True)

    def __str__(self):
        return "{}".format(self.action)

    class Meta:
        db_table = 'whois_nets_events_records'
        ordering = ['-id']


class WhoisNetLinksRecord(BaseModel):
    whois_net = models.ForeignKey(WhoisNetsRecord, null=True, blank=True,
        on_delete=models.CASCADE, related_name="whois_net_links")
    links = models.TextField(null=True, blank=True)

    def __str__(self):
        return "{}".format(self.links)

    class Meta:
        db_table = 'whois_nets_links_records'
        ordering = ['-id']


class WhoisNetsEmailsRecord(BaseModel):
    whois_net = models.ForeignKey(WhoisNetsRecord, null=True, blank=True,
    on_delete=models.CASCADE, related_name="whois_net_emails")
    email = models.TextField(null=True, blank=True)

    def __str__(self):
        return "{}".format(self.email)

    class Meta:
        db_table = 'whois_nets_email_records'
        ordering = ['-id']


class EventCountHistory(BaseModel):
    pl_activity = models.IntegerField(null=True, blank=True, default=0)
    microservice_error = models.IntegerField(null=True, blank=True, default=0)
    burp_error = models.IntegerField(null=True, blank=True, default=0)
    nessus_error = models.IntegerField(null=True, blank=True, default=0)
    masscan_error = models.IntegerField(null=True, blank=True, default=0)
    vulnerability_found = models.IntegerField(null=True, blank=True, default=0)

    def __str__(self):
        return "{}".format(self.created)

    class Meta:
        db_table = 'activity_line_chart_record'


class WhoisBasicRecord(BaseModel):
    asn_id = models.CharField(max_length=300, null=True, blank=True)
    asn_description = models.TextField(null=True, blank=True)
    handle = models.CharField(max_length=300, null=True, blank=True)
    network_name = models.CharField(max_length=300, null=True, blank=True)

    class Meta:
        db_table = 'whois_basic_record'
        unique_together = (("asn_id", "asn_description", "network_name"),)

    def __str__(self):
        return "{}-{}".format(self.asn_id, self.network_name)

    def whois_hosts(self):
        raw_list = list(IpWhoisRecord.objects.filter(
            whois_record=self.id
            ).values_list('target_host', flat=True))
        converted_list = ", ".join(map(str, raw_list))
        return converted_list


class IpWhoisRecord(BaseModel):
    ip = models.ForeignKey(UserHosts, null=True, blank=True,
    on_delete=models.CASCADE, related_name="ip_whois")
    whois_record = models.ForeignKey(WhoisBasicRecord, on_delete=models.CASCADE,
    related_name="whois_record", null=True, blank=True 
    )
    target_host = models.CharField(max_length=300, null=True, blank=True)
    city = models.TextField(null=True, blank=True)
    longitude = models.CharField(max_length=256, null=True, blank=True)
    latitude = models.CharField(max_length=256, null=True, blank=True)

    def __str__(self):
        return "{}".format(self.ip)

    class Meta:
        db_table = 'ip_whois_record'

    def listed_hosts(self):
        raw_list = list(IpWhoisRecord.objects.filter(
            ip=self.ip
            ).values_list('target_host', flat=True))
        converted_list = ", ".join(map(str, raw_list))
        return converted_list


class EmailRecord(BaseModel):
    email_type = models.CharField(max_length=256, null=True, blank=True)
    message = models.TextField(null=True, blank=True)
    receivers = models.TextField(null=True, blank=True)

    def __str__(self):
        return "{}".format(self.email_type, self.receivers)

    class Meta:
        db_table = 'email_record'


class EncryptionCacheCiphers(BaseModel):
    cipher_id = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    id_decimal = models.CharField(max_length=64, null=True, blank=True)
    id_hex = models.CharField(max_length=64, null=True, blank=True)
    name_openssl = models.CharField(max_length=128, null=True, blank=True)
    name_iana = models.CharField(max_length=128, null=True, blank=True)
    keyx = models.CharField(max_length=64, null=True, blank=True)
    enc = models.CharField(max_length=64, null=True, blank=True)
    bits = models.CharField(max_length=64, null=True, blank=True)
    strength = models.CharField(max_length=32, null=True, blank=True)
    anonymous = models.BooleanField(default=False)
    null = models.BooleanField(default=False)
    export = models.BooleanField(default=False)
    rc4 = models.BooleanField(default=False)
    cbc = models.BooleanField(default=False)

    def __str__(self):
        return self.id_hex

    class Meta:
        verbose_name_plural = "Encryption Cache Ciphers"
        ordering = ['id']


class EncryptionCacheSsh(BaseModel):
    ssh_cipher_id = models.UUIDField(
        default=uuid.uuid4,
        editable=False,
        unique=True
    )
    ssh_cipher = models.CharField(max_length=128, unique=True)
    cipher_type = models.CharField(max_length=64, null=True, blank=True)
    arc4 = models.BooleanField(default=False)
    cbc = models.BooleanField(default=False)
    weak = models.BooleanField(default=False)

    def __str__(self):
        return '{} - {}'.format(self.cipher_type, self.ssh_cipher)

    class Meta:
        verbose_name_plural = "Encryption Cache Ssh"
        ordering = ['id']


class ApplicationVulnerabilityChart(BaseModel):
    critical_risk = models.IntegerField(null=True, blank=True, default=0)
    high_risk = models.IntegerField(null=True, blank=True, default=0)
    medium_risk= models.IntegerField(null=True, blank=True, default=0)
    low_risk= models.IntegerField(null=True, blank=True, default=0)

    def __str__(self):
        return '{}'.format(self.critical_risk)

    class Meta:
        verbose_name_plural = "Application Vulnerability Risk History"
        ordering = ['-id']


class EncryptionChart(BaseModel):
    services = models.IntegerField(null=True, blank=True, default=0)
    high_strength = models.IntegerField(null=True, blank=True, default=0)
    medium_strength = models.IntegerField(null=True, blank=True, default=0)
    low_strength = models.IntegerField(null=True, blank=True, default=0)

    def __str__(self):
        return '{}'.format(self.services)

    class Meta:
        verbose_name_plural = "Encryption History"
        ordering = ['-id']
