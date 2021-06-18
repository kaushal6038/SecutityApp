from __future__ import absolute_import, unicode_literals
import os
from celery import Celery
from django.conf import settings
from celery.schedules import crontab
from kombu import Exchange, Queue
###################################################################################################
#																								  #
# celery -A redtree worker -l info -B --scheduler django_celery_beat.schedulers:DatabaseScheduler #
# celery -A redtree worker --beat --scheduler django --loglevel=info -Q default,burp,masscan,     #
#	sslyze,sshyze,domainenum,nessus,cloudstorage          					  					              #
# celery -A redtree purge               														  #
#																								  #
###################################################################################################

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'redtree.settings')

app = Celery('redtree')

app.config_from_object('django.conf:settings', namespace='CELERY')
app.autodiscover_tasks()

CELERY_CREATE_MISSING_QUEUES = True

task_queues = (
    Queue('celery', routing_key='celery'),
    Queue('default', Exchange('default', delivery_mode=1, queue_arguments={'x-max-priority': 10}),
          routing_key='default', durable=True),
    Queue('burp', Exchange('burp', delivery_mode=1),
          routing_key='burp', durable=False),
    Queue('masscan', Exchange('masscan', delivery_mode=1),
          routing_key='masscan', durable=False),
    Queue('sslyze', Exchange('sslyze', delivery_mode=1),
          routing_key='sslyze', durable=False),
    Queue('sshyze', Exchange('sshyze', delivery_mode=1),
          routing_key='sshyze', durable=False),
    Queue('domainenum', Exchange('domainenum', delivery_mode=1),
          routing_key='domainenum', durable=False),
    Queue('nessus', Exchange('nessus', delivery_mode=1),
          routing_key='nessus', durable=False),
    Queue('cloudstorage', Exchange('cloudstorage', delivery_mode=1),
          routing_key='cloudstorage', durable=False),
    Queue('screenshot', Exchange('screenshot', delivery_mode=1),
          routing_key='screenshot', durable=False),
    Queue('scanrds', Exchange('scanrds', delivery_mode=1),
          routing_key='scanrds', durable=False),
    Queue('awsrefresh', Exchange('awsrefresh', delivery_mode=1),
          routing_key='awsrefresh', durable=False),
)

CELERY_ROUTES = {
    'redtree_app.tasks.generate_application_scan': {'queue': 'burp'},
    'redtree_app.tasks.masscan_playground': {'queue': 'masscan'},
    'redtree_app.tasks.sslyze_cipher': {'queue': 'sslyze'},
    'redtree_app.tasks.sshyze_cipher': {'queue': 'sshyze'},
    'redtree_app.tasks.domain_enum': {'queue': 'domainenum'},
    'redtree_app.tasks.run_scan': {'queue': 'nessus'},
    'redtree_app.tasks.update_nessus_status': {'queue': 'nessus'},
    'redtree_app.tasks.cloudstorage_s3_bucket_scan': {'queue': 'cloudstorage'},
    'redtree_app.tasks.application_screenshot_generator': {'queue': 'screenshot'},
    'redtree_app.tasks.aws_rds_scan': {'queue': 'scanrds'},
    'redtree_app.tasks.refresh_aws_asset_status': {'queue': 'awsrefresh'},

}

app.conf.task_default_queue = 'default'

app.conf.task_routes = CELERY_ROUTES

@app.task(bind=True)
def debug_task(self):
    print('Request: {0!r}'.format(self.request))
