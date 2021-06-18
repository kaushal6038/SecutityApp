from django.core.management.base import BaseCommand
import json
import os
from redtree_app.models import *
from nessus.models import *


class Command(BaseCommand):

    def handle(self, *args, **options):
        appl_obj = Appliances.objects.first()
        if not appl_obj:
            Appliances.objects.create(
                appliance_ip='167.172.225.139',
                network_type='External')
        else:
            if not appl_obj.appliance_ip:
                appl_obj.appliance_ip = '167.172.225.139'
            elif not appl_obj.network_type:
                appl_obj.network_type = 'External'
            appl_obj.save()