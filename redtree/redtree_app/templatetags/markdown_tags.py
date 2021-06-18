from django import template
from markdownx.utils import markdownify
from datetime import datetime
from datetime import timedelta
from django.utils import timezone
from django.utils.timesince import timesince
import re

register = template.Library()

@register.filter(name='convert_markdown')
def convert_markdown(data):
	if data is not None:
		data = data.strip()
		clean_data = markdownify(data)
	else:
		clean_data = data

	return clean_data


@register.filter(name='get_date')
def get_date(date):
	event_time = datetime.strptime(date, "%Y-%m-%d %H:%M %p")
	currentTime = datetime.now().strftime("%Y-%m-%d %H:%M")
	current_time = datetime.strptime(currentTime, "%Y-%m-%d %H:%M")
	difference = current_time - event_time
	if event_time.day == current_time.day:
		hours = difference.seconds/3600
		minutes = difference.seconds/60
		if hours < 1:
			return str(abs(minutes)) + "minutes"
		elif minutes < 1:
			return "a minutes"
		else:
			return str(abs(current_time.hour - event_time.hour)) + "hours"
	else:
		if event_time.month == current_time.month:
			return str(abs(current_time.day - event_time.day)) + "days"
		else:
			if event_time.year == current_time.year:
				return str(abs(current_time.month - event_time.month)) + "months"
	return date

@register.filter(name='get_notification_time')
def get_notification_time(date):
	current_time = timezone.now()
	try:
		event_time = current_time - date
	except:
		return date

	if event_time <= timedelta(minutes=1):
		return '0 m'
	time = '%(time)s' % {'time': timesince(date).split(', ')[0]}
	currentTime = " ".join(time.split()[1:])
	if re.search('year',currentTime):
		time = (time.strip(currentTime)).strip() + "y"
	elif re.search('month', time):
		time = (time.strip(currentTime)).strip() + "M"
	elif re.search('week', currentTime):
		time = (time.strip(currentTime)).strip() + "w"
	elif re.search('day', currentTime):
		time = (time.strip(currentTime)).strip() + "d"
	elif re.search('hour', currentTime):
		time = (time.strip(currentTime)).strip() + "h"
	elif re.search('minute', currentTime):
		time = (time.strip(currentTime)).strip() + "m"
	return time

@register.filter(name='get_microservices_log_age')
def get_microservices_log_age(date):
	current_time = timezone.now()
	try:
		event_time = current_time - date
	except:
		return date

	if event_time <= timedelta(minutes=1):
		return '0 m'
	time = '%(time)s' % {'time': timesince(date).split(', ')[0]}
	currentTime = " ".join(time.split()[1:])
	if re.search('year',currentTime):
		time = (time.strip(currentTime)).strip() + "y"
	elif re.search('month', time):
		time = (time.strip(currentTime)).strip() + "M"
	elif re.search('week', currentTime):
		time = (time.strip(currentTime)).strip() + "w"
	elif re.search('day', currentTime):
		time = (time.strip(currentTime)).strip() + "d"
	elif re.search('hour', currentTime):
		time = (time.strip(currentTime)).strip() + "h"
	elif re.search('minute', currentTime):
		time = (time.strip(currentTime)).strip() + "m"
	return time

@register.filter(name='get_identified_date')
def get_identified_date(date):
	nessus_date = datetime.strptime(date, "%a %b %d %H:%M:%S %Y")
	current_year =datetime.now().year
	# if nessus_date.year == current_year:
	# 	identified_date = nessus_date.strftime("%b %d %H:%M")
	# else:
	# 	identified_date = nessus_date.strftime("%b %d %H:%M %Y")
	identified_date = nessus_date.strftime("%b %d, %Y")
	return identified_date