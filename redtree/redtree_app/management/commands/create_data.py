from django.core.management.base import BaseCommand
import json
import os
from redtree_app.models import *
import random

class Command(BaseCommand):

    def handle(self, *args, **options):
        # plugin_id = random.randint(100,99999)
        # port = random.randint(8000,9000)
        # risk = ['Critical','High','Low','Medium','Note']
        # host_ip = ['106.192.185.159','104.192.185.129','106.192.165.129','106.197.185.126']
        # network_type = ['External']
        # title = ['eeadc','efv','qef','efvf','gbrv','wefw','trgv','gtt']
        # host_obj = '106.192.185.129'
        # for i in range(300,1110):
        #     Vulnerability.objects.create(
        #         virtue_id=i,plugin_id=plugin_id,port=port,
        #         risk=random.choice(risk),title=random.choice(title)+str(i),
        #         description='An open port was discovered',
        #         remediation='N/A', post_status=True,
        #         host_ip=random.choice(host_ip),
        #         network_type=random.choice(network_type),
        #         host_id = 1,
            # )

        # host = [1,5,9]
        # application_url = ['aew1db','rew','ewwq','ewqw','gtyhdb','yhhhr2','hyt3','tr1']
        # application_title = ['eeadc','efv','qef','efvf','gbrv','wefw','trgv','gtt']
        # scope = ['black','grey','white']
        # network_type = ['External']
        # for i in range(300,1110):
        #     x = random.choice(host)
        #     Applications.objects.create(
        #         application_url = random.choice(application_url)+str(i),
        #         application_title = random.choice(application_title)+str(i+500),
        #         scope = random.choice(scope),
        #         network_type = network_type
        #         )

        host = ['106.92.185.129','106.192.185.449','106.142.185.129','106.192.185.159','104.192.185.129','106.192.165.129','106.197.185.126']
        port = [80,8008,8080,8081,8004,8006,8002,8009,8010]
        protocol = ['TLSv1_3','TLSv1_2','TLSv1_1','SSLv3','SSLv2']
        strength = ['High','Low','Medium']
        cipher = ['COQM-VEAX-QPMU','COQMAC-VEAX-QPMU','FESQ-VEAX-VQCT']
        key_size = [10,20,22,9,10,128]
        for i in range(100,1000):
            Ciphers.objects.create(
                host = random.choice(host),port = random.choice(port),
                protocol = random.choice(protocol),
                cipher = random.choice(cipher)+str(i),
                key_size = random.choice(key_size),strength = random.choice(strength)
                )