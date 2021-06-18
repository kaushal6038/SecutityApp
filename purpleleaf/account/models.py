# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.utils import timezone
from django.utils.translation import ugettext_lazy as _
from django.db.models.signals import post_save
from django.dispatch import receiver
import datetime
import hashlib, random
import os
from .managers import UserManager
import requests
from django.template.loader import render_to_string

# Create your models here.

def send_mail(reciever, subject, html_content):
    client_conf = Configuration.objects.first()
    if client_conf:
        key = client_conf.mailgun_api_key
        base_url = client_conf.mailgun_base_url
        request_url = base_url + "/messages"
        try:
            request = requests.post(request_url, auth=('api', key), data={
                'from': "PurpleLeaf <noreply@purpleleaf.io>",
                'to': reciever,
                'subject': subject,
                'html': html_content
            })
        except:
            pass


class User(AbstractBaseUser, PermissionsMixin):
    name = models.CharField(_('name'), max_length=64, blank=False, null=True)
    email = models.EmailField(_('email address'), max_length=256, unique=True)
    qrcode = models.URLField(_('qr code'), max_length=500, null=True, blank=True)
    secret_key = models.CharField(_('secret key'), max_length=20, null=True, blank=True)
    activation_key = models.CharField(_('activation key'), max_length=40, null=True, blank=True)
    authentication_key = models.CharField(_('auth key'), max_length=40, null=True, blank=True)
    key_expires = models.DateTimeField(_('key expires'), null=True, blank=True)
    authenticated = models.BooleanField(_('authenticated'), default=False)
    email_confirmed = models.BooleanField(_('email confirmed'), default=False)
    twofa_status = models.BooleanField(_('twofa status'), default=False)
    twofa_type = models.CharField(_('twofa type'), max_length=20, null=True, blank=True)
    phone_number = models.CharField(_('phone number'), max_length=20, null=True, blank=True)
    redtree_user_id = models.CharField(_('redtree id'), max_length=10, null=True, blank=True)
    time_zone = models.CharField(_('time zone'), max_length=50, null=True, blank=True)
    is_staff = models.BooleanField(_('staff status'), default=False)
    is_active = models.BooleanField(_('active'), default=True)
    date_joined = models.DateTimeField(_('date joined'), default=timezone.now)
    created_at = models.DateTimeField(auto_now_add=True)
    last_modified_at = models.DateTimeField(auto_now=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    objects = UserManager()

    class Meta:
        verbose_name = _('user')
        verbose_name_plural = _('users')
        ordering = ['date_joined',]

    def get_full_name(self):
        full_name = '{} {}'.format(self.name, self.email)
        return full_name.strip()

    def get_short_name(self):
        return self.name

    def save(self, *args, **kwargs):
        if self.email and not self.password:
            salt = hashlib.sha1(str(random.random())).hexdigest()[:5]
            activation_key = hashlib.sha1(salt + self.email).hexdigest()
            key_expires = timezone.now() + datetime.timedelta(1)
            self.activation_key = activation_key
            self.key_expires = key_expires
        super(User, self).save()

    def __str__(self):
        return self.email


@receiver(post_save, sender=User)
def send_invitation(sender, created, instance, **kwargs):
    if created and instance.email and not instance.password:
        email = instance.email
        activation_key = instance.activation_key
        hostname = os.environ.get('PURPLELEAF_URL')
        if hostname:
            invitation_url  = '{0}/invite/{1}'.format(hostname,activation_key)
            logo_url = '{}/static/img/p-logo.png'.format(hostname)
            invitation_template = render_to_string(
                'email-templates/user_invitation.html',
                {
                    'invitation_url': invitation_url,
                    'logo_url': logo_url
                }
            )
            subject = 'Invitation to PurpleLeaf'
            send_mail(email, subject, invitation_template)


# to avoid circular import
from utils.base_model import BaseModel

class AccessAttempt(BaseModel):
    user = models.ForeignKey(User, null=True, blank=True)
    email = models.EmailField()
    created = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.email

    class Meta:
        verbose_name_plural = "Access Attempts"


class Configuration(BaseModel):
    active = models.BooleanField(default=False)
    mailgun_api_key = models.CharField(max_length=1000, blank=True, null=True)
    hostname = models.CharField(max_length=500, blank=True, null=True)
    mailgun_base_url = models.CharField(max_length=500, blank=True, null=True)
    redtree_auth_key = models.CharField(max_length=500, blank=True, null=True)
    twilio_account_sid = models.CharField(max_length=500, blank=True, null=True)
    twilio_auth_key = models.CharField(max_length=500, blank=True, null=True)
    twilio_account_number = models.CharField(max_length=20, blank=True, null=True)
    application_status = models.BooleanField(default=False)
    analytics_status = models.BooleanField(default=False)
    storage_type = models.CharField(max_length=20, blank=True, null=True)
    s3_access_token = models.CharField(max_length=500, blank=True, null=True)
    s3_secret_access_token = models.CharField(max_length=500, blank=True, null=True)
    s3_bucket_name = models.CharField(max_length=200, blank=True, null=True)
    pre_signed_time_length = models.IntegerField(blank=True, null=True)
    session_timeout_length = models.IntegerField(blank=True, null=True, default=43200)
    manual_hours_purchased = models.CharField(max_length=200, blank=True, null=True)
    manual_hours_remaining = models.CharField(max_length=200, blank=True, null=True)
    max_ips = models.CharField(max_length=200, blank=True, null=True)
    aws_access_token = models.CharField(max_length=200, blank=True, null=True)
    aws_secret_token = models.CharField(max_length=200, blank=True, null=True)
    auth_reset = models.BooleanField(default=False)

    def __str__(self):
        return str(self.active)

    class Meta:
        verbose_name_plural = "Configurations"


class PrivateConfiguration(BaseModel):
    redtree_base_url = models.CharField(max_length=500, blank=True, null=True)
    data_auth_key = models.CharField(max_length=500, blank=True, null=True)
    auth_reset = models.BooleanField(default=False)
    
    def __str__(self):
        return str(self.data_auth_key)

    class Meta:
        verbose_name_plural = "PrivateConfigurations"