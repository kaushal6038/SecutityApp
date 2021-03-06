# -*- coding: utf-8 -*-
# Generated by Django 1.11.10 on 2019-11-26 10:27
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('redtree_app', '0029_auto_20191125_0814'),
    ]

    operations = [
        migrations.CreateModel(
            name='ApplicationVulnerabilityChart',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('modified', models.DateTimeField(auto_now=True)),
                ('critical_risk', models.IntegerField(blank=True, null=True)),
                ('high_risk', models.IntegerField(blank=True, null=True)),
                ('medium_risk', models.IntegerField(blank=True, null=True)),
                ('low_risk', models.IntegerField(blank=True, null=True)),
            ],
            options={
                'ordering': ['-id'],
                'verbose_name_plural': 'Application Vulnerability Risk History',
            },
        ),
        migrations.DeleteModel(
            name='ApplicationVulnerabilityRiskData',
        ),
    ]
