from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('redtree_app', '0033_encryptionchart'),
    ]

    operations = [
        migrations.AddField(
            model_name='purpleleafusers',
            name='activation_key',
            field=models.CharField(blank=True, max_length=40, null=True),
        ),
    ]