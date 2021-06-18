# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models
from utils.base_models import BaseModel
# Create your models here.


class ApiList(BaseModel):
    api = models.CharField(max_length=800, null=True, blank=True)
    kb_base_url = models.CharField(max_length=500, null=True, blank=True)
    kb_auth_token = models.CharField(max_length=500, null=True, blank=True)

    def __str__(self):
        return self.api

