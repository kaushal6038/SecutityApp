from uuid import uuid4

from django.db import models
from django.contrib.auth import get_user_model
#

User = get_user_model()

class BaseModel(models.Model):
    """
    All models extend from this model
    """
    created_by = models.ForeignKey(
        User,
        related_name='%(app_label)s_%(class)s_created_by',
        null=True, blank=True, on_delete=models.SET_NULL
    )
    last_modified_by = models.ForeignKey(
        User,
        related_name='%(app_label)s_%(class)s_last_modified_by',
        null=True, blank=True, on_delete=models.SET_NULL
    )
    created_at = models.DateTimeField(auto_now_add=True)
    last_modified_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True