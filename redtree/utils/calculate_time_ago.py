from django.utils import timezone
from django.utils.timesince import timesince
from datetime import date, datetime, timedelta


def calculate_time_ago(value):
    now = timezone.now()
    try:
        difference = now - value
    except:
        return value

    if difference <= timedelta(minutes=1):
        return 'just now'
    return '%(time)s ago' % {'time': timesince(value).split(', ')[0]}