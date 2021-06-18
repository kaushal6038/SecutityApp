from rest_framework.serializers import ModelSerializer
from purpleleaf_app.models import *
from account.models import *
from rest_framework import serializers
from rest_framework.validators import UniqueValidator



class UserSeriallizer(serializers.ModelSerializer):
    name = serializers.CharField(required=True)
    email = serializers.CharField(
        required=True,
        validators=[UniqueValidator(queryset=User.objects.all())]
        )

    class Meta:
        model = User
        fields = [
            'id',
            'name',
            'email',
            'activation_key'
        ]


class UserDetailSeriallizer(ModelSerializer):

    class Meta:
        model = User
        fields = [
            'id',
            'name',
            'email',
            'is_active',
        ]


class ConfigurationSerializer(ModelSerializer):
    class Meta:
        model = Configuration
        fields = [
            'mailgun_api_key', 'hostname', 'mailgun_base_url', 'redtree_auth_key', 
            'twilio_account_sid', 'twilio_auth_key', 'twilio_account_number', 'application_status', 
            'analytics_status', 'session_timeout_length','storage_type', 's3_access_token', 's3_secret_access_token',
            's3_bucket_name', 'pre_signed_time_length', 'manual_hours_purchased', 'manual_hours_remaining', 'max_ips','aws_access_token', 'aws_secret_token'
        ]


class NotificationSerializer(serializers.ModelSerializer):

    class Meta:
        model = Notifications
        fields = [
            'issue_id',
            'issue',
            'status',
            'issue_virtue_id',
            'issue_network_type',
        ]