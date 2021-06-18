from django import template
from datetime import timedelta, datetime
from django.utils import timezone
from django.utils.timesince import timesince
import re

register = template.Library()


@register.filter(name='get_date')
def get_date(value):
	value = datetime.strptime(value, "%Y-%m-%d %H:%M:%p")
	currentTime = datetime.now().strftime("%Y-%m-%d %H:%M")
	current_time = datetime.strptime(currentTime, "%Y-%m-%d %H:%M")
	try:
		difference = current_time - value
	except:
		return value
	if difference <= timedelta(minutes=1):
		return '0 m'
	time = '%(time)s' % {'time': timesince(value).split(', ')[0]}
	actual_time = " ".join(time.split()[1:])
	if re.search('year', actual_time):
		time = (time.strip(actual_time)).strip() + "y"
	elif re.search('month', time):
		time = (time.strip(actual_time)).strip() + "M"
	elif re.search('week', actual_time):
		time = (time.strip(actual_time)).strip() + "w"
	elif re.search('day', actual_time):
		time = (time.strip(actual_time)).strip() + "d"
	elif re.search('hour', actual_time):
		time = (time.strip(actual_time)).strip() + "h"
	elif re.search('minute', actual_time):
		time = (time.strip(actual_time)).strip() + "m"
	return time


@register.filter(name='time_ago')
def time_ago(value):
	value = datetime.strptime(value, "%B %d, %Y, %H:%M %p")
	currentTime = datetime.now().strftime("%Y-%m-%d %H:%M")
	current_time = datetime.strptime(currentTime, "%Y-%m-%d %H:%M")
	try:
		difference = current_time - value
	except:
		return value
	if difference <= timedelta(minutes=1):
		return '0 minute ago'
	time = '%(time)s' % {'time': timesince(value).split(', ')[0]}
	actual_time = " ".join(time.split()[1:])
	if re.search('year', actual_time):
		time = (time.strip(actual_time)).strip()
		if int(time) > 1:
			time = time + " years ago"
		else:
			time = time + " year ago"
	elif re.search('month', time):
		time = (time.strip(actual_time)).strip()
		if int(time) > 1:
			time = time + " Months ago"
		else:
			time = time + " Month ago"
	elif re.search('week', actual_time):
		time = (time.strip(actual_time)).strip()
		if int(time) > 1:
			time = time + " weeks ago"
		else:
			time = time + " week ago"
	elif re.search('day', actual_time):
		time = (time.strip(actual_time)).strip()
		if int(time) > 1:
			time = time + " days ago"
		else:
			time = time + " day ago"
	elif re.search('hour', actual_time):
		time = (time.strip(actual_time)).strip()
		if int(time) > 1:
			time = time + " hours ago"
		else:
			time = time + " hour ago"
	elif re.search('minute', actual_time):
		time = (time.strip(actual_time)).strip()
		if int(time) > 1:
			time = time + " minutes ago"
		else:
			time = time + " minute ago"
	return time


@register.filter(name='vul_date')
def vul_date(value):
	value = datetime.strptime(value, "%B %d, %Y, %H:%M %p")
	time = value.strftime("%B %d, %Y")
	return time
	
