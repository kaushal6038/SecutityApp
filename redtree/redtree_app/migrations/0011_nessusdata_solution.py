# -*- coding: utf-8 -*-
# Generated by Django 1.11.10 on 2019-10-03 08:27
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('redtree_app', '0010_update_nessus_host_link'),
    ]

    operations = [
        migrations.AddField(
            model_name='nessusdata',
            name='solution',
            field=models.TextField(blank=True, null=True),
        ),
    ]
