# -*- coding: utf-8 -*-
# Generated by Django 1.11.10 on 2019-11-05 10:38
from __future__ import unicode_literals

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('redtree_app', '0020_auto_20191105_0335'),
    ]

    operations = [
        migrations.RenameField(
            model_name='sslyzecertificates',
            old_name='has_sha1_in_certificate_chain',
            new_name='sha1_in_chain',
        ),
    ]
