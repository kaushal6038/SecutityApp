# -*- coding: utf-8 -*-
# Generated by Django 1.11.10 on 2020-05-09 22:39
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('redtree_app', '0037_rdsscan'),
    ]

    operations = [
        migrations.AddField(
            model_name='applications',
            name='burp_scanning',
            field=models.BooleanField(default=False),
        ),
    ]
