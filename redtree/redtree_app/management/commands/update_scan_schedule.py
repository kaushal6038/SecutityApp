from django.core.management.base import BaseCommand
import json
import os
from redtree_app.models import *


class Command(BaseCommand):

    def handle(self, *args, **options):
    	client_conf_obj = ClientConfiguration.objects.first()
    	client_conf_obj.save()
