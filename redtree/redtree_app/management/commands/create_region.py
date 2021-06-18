from django.core.management.base import BaseCommand
from redtree_app.models import *

class Command(BaseCommand):
	region_list = ['us-east-2',
					'us-east-1',
					'us-west-1',
					'us-west-2',
					'ap-south-1',
					'ap-northeast-3',
					'ap-northeast-2',
					'ap-southeast-1',
					'ap-southeast-2',
					'ap-northeast-1',
					'ca-central-1',
					'cn-north-1',
					'cn-northwest-1',
					'eu-central-1',
					'eu-west-1',
					'eu-west-2',
					'eu-west-3',
					'sa-east-1'
	]

	def handle(self ,*args,**option):
		for region in self.region_list:
			if not AwsRegion.objects.filter(region=region).exists():
				AwsRegion.objects.create(region=region)

