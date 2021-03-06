# -*- coding: utf-8 -*-
# Generated by Django 1.11.10 on 2019-11-27 10:42
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('redtree_app', '0030_auto_20191126_0527'),
    ]

    operations = [
        migrations.AlterField(
            model_name='applicationvulnerabilitychart',
            name='critical_risk',
            field=models.IntegerField(blank=True, default=0, null=True),
        ),
        migrations.AlterField(
            model_name='applicationvulnerabilitychart',
            name='high_risk',
            field=models.IntegerField(blank=True, default=0, null=True),
        ),
        migrations.AlterField(
            model_name='applicationvulnerabilitychart',
            name='low_risk',
            field=models.IntegerField(blank=True, default=0, null=True),
        ),
        migrations.AlterField(
            model_name='applicationvulnerabilitychart',
            name='medium_risk',
            field=models.IntegerField(blank=True, default=0, null=True),
        ),
    ]
