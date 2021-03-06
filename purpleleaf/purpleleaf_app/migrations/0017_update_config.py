# -*- coding: utf-8 -*-
# Generated by Django 1.11.7 on 2019-09-06 06:05
from __future__ import unicode_literals

from django.db import migrations


def update_configuration(apps, schema_editor):
	'''
	We can't import the Post model directly as it may be a newer
	version than this migration expects. We use the historical version.
	'''
	Configuration = apps.get_model('account', 'Configuration')
	PrivateConfiguration = apps.get_model('account', 'PrivateConfiguration')
	conf_obj = Configuration.objects.first()
	private_conf_obj = PrivateConfiguration.objects.first()
	if conf_obj:
		conf_obj.auth_reset = False
		conf_obj.save()
	if private_conf_obj:
		private_conf_obj.auth_reset = False
		private_conf_obj.save()


class Migration(migrations.Migration):

    dependencies = [
        ('purpleleaf_app', '0016_update_configuration'),
    ]

    operations = [
    	migrations.RunPython(update_configuration)
    ]
