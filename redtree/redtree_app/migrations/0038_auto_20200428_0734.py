# -*- coding: utf-8 -*-
# Generated by Django 1.11.10 on 2020-04-28 12:34
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('redtree_app', '0037_rdsscan'),
    ]

    operations = [
        migrations.AlterField(
            model_name='appliances',
            name='port',
            field=models.CharField(blank=True, default=443, max_length=200, null=True),
        ),
    ]