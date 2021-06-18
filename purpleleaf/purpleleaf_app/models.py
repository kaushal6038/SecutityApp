from __future__ import unicode_literals
from django.db import models
from account.models import *


from utils.base_model import BaseModel

class Notifications(BaseModel):
    retest_id = models.CharField(max_length=10, null=True, blank=True)
    issue_id = models.CharField(max_length=10, null=True, blank=True)
    issue = models.CharField(max_length=500, null=True, blank=True)
    status = models.CharField(max_length=10, null=True, blank=True)
    issue_virtue_id = models.IntegerField(null=True, blank=True)
    issue_network_type = models.CharField(max_length=64, null=True, blank=True)
    seen = models.BooleanField(default=False)

    def __str__(self):
        return "{} {}".format(self.issue, self.status)

    class Meta:
        verbose_name_plural = "Notifications"


class EventHistory(BaseModel):
    event_type = models.CharField(max_length=300, blank=True, null=True)
    time_stamp = models.CharField(max_length=300, blank=True, null=True)
    username = models.CharField(max_length=300, blank=True, null=True)
    ip = models.CharField(max_length=300, blank=True, null=True)
    data = models.TextField(blank=True, null=True)

    def __str__(self):
        return str(self.event_type)

    class Meta:
        verbose_name_plural = "Event History"
        ordering = ['-id']


class ActivityLog(BaseModel):
    activity = models.CharField(max_length=1000, null=True, blank=True)

    def __str__(self):
        return self.activity

    class Meta:
        verbose_name_plural = "Activity Logs"