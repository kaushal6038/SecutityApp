from django.db import models
from django.utils import timezone
import time
import datetime
from datetime import timedelta, datetime
from django.utils import timezone


class LoggingBaseModel(models.Model):
	task_id = models.CharField(max_length=56, null=True, blank=True)
	scan_id = models.CharField(max_length=1024, null=True, blank=True)
	appliance = models.CharField(max_length=100, null=True, blank=True)
	status = models.CharField(max_length=30, null=True, blank=True)
	result = models.TextField(null=True, blank=True)
	message = models.TextField(null=True, blank=True)
	network_type = models.CharField(max_length=100, null=True, blank=True)
	is_completed = models.BooleanField(default=False)
	created = models.DateTimeField(auto_now_add=True)
	modified = models.DateTimeField(auto_now=True)
	duration = models.DateTimeField(default=timezone.now)

	class Meta:
		abstract = True

	@property
	def task_duration(self):
		if self.is_completed:
			difference = self.modified - self.created
		else:
			difference = timezone.now() - self.created
		days, seconds = int(difference.days), int(difference.seconds)
		d = datetime(1,1,1) + timedelta(seconds=seconds)
		hour, minute, second = int(d.hour), int(d.minute), int(d.second)
		if days >=1:
			return ("{}d {}h {}m").format(days, hour, minute)
		else:
			if seconds <= 59:
				return ("{}s").format(second)
			elif 3599 >= seconds >= 60:
				return ("{}m {}s").format(minute, second)
			elif 86399 >= seconds >= 3600:
				return ("{}h {}m {}s").format(hour, minute, second)
			elif seconds > 86400:
					return ("{}d {}h {}m").format(days, hour, minute)


class BaseModel(models.Model):
	created = models.DateTimeField(auto_now_add=True)
	modified = models.DateTimeField(auto_now=True)

	class Meta:
		abstract = True