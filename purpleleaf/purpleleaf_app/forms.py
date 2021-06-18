from django import forms
from . models import *
import pytz
import datetime
# from django.contrib.auth import get_user_model

# User = get_user_model()


class ChangePasswordForm(forms.Form):
    password = forms.CharField(max_length=100, widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'Password'}))
    new_password = forms.CharField(max_length=100, widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'New Password'}))
    confirm_password = forms.CharField(max_length=100, widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'Confirm Password'}))

    def clean(self):
        cleaned_data = super(ChangePasswordForm, self).clean()
        new_password = cleaned_data.get("new_password")
        confirm_password = cleaned_data.get("confirm_password")
        if new_password != confirm_password:
            raise forms.ValidationError(
                "New Password and Confirm password do not match"
            )


class CloudAssetsForm(forms.Form):
    category_choices = [
        ("S3", "S3"),
        ("S3", "S3"),
        ("GCP", "GCP"),
        ("Azure", "Azure")
    ]
    category = forms.ChoiceField(choices=category_choices, widget=forms.Select(attrs={'class': 'form-control'}))
    bucket = forms.CharField(required=True, widget=forms.Textarea(attrs={'rows': '10', 'class': 'form-control'}))


class TimezoneForm(forms.Form):
    timezones = ['America/New_York', 'America/Chicago', 'America/Denver', 'America/Los_Angeles']
    timezone = forms.ChoiceField(
        label=('Time Zone'),
        widget=forms.Select(attrs={'class': 'form-control'}),
        choices=[(timezone, timezone) for timezone in timezones]
    )