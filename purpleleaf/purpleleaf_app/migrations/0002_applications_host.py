# -*- coding: utf-8 -*-
# Generated by Django 1.11.7 on 2018-12-21 05:53
from __future__ import unicode_literals

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('purpleleaf_app', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='applications',
            name='host',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='purpleleaf_app.Host'),
        ),
    ]