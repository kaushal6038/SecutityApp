# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.contrib import admin
from .models import *
from django.contrib.auth import get_user_model

User = get_user_model()
# Register your models here.


admin.site.register(User)
admin.site.register(AccessAttempt)
admin.site.register(PrivateConfiguration)
admin.site.register(Configuration)