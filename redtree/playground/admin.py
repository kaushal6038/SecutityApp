# -*- coding: utf-8 -*-
from __future__ import unicode_literals

# django imports
from django.contrib import admin

#in house apps imports
from .models import (
	ApplicationScans,
	ApplicationScanData,
	SshyzeType,
	SshyzeCiphers,
	BurpEvidence
	)
# Register your models here.

admin.site.register(ApplicationScans)
admin.site.register(ApplicationScanData)
admin.site.register(SshyzeType)
admin.site.register(SshyzeCiphers)
admin.site.register(BurpEvidence)