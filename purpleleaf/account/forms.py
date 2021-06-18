# modules import
import pytz, datetime, os
from django import forms

# djnago imports
from django.contrib.auth import get_user_model
from django.utils.http import urlsafe_base64_encode
from django.contrib.auth.forms import PasswordResetForm
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes

# import of account_app
from . models import *

# import of purpleleaf_app
from purpleleaf_app.alerts import send_mail

# import of utils
from utils.password_reset_template import invitation_header, invitation_body
from django.template.loader import render_to_string

User = get_user_model()


class RegisterUser(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'form-control signup-pwd-dsn', 'id': 'sign-pwdvisible' , 'placeholder': 'Password'}))
    confirm_password = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'form-control signup-cnf-pwd-dsn', 'id': 'sign-cnfpwdvisible' , 'placeholder': 'Confirm Password'}))

    class Meta:
        model = User
        fields = [
            'email',
            'password',
            'confirm_password',
        ]
        widgets ={
            'email' : forms.TextInput(attrs={'class': 'form-control signup-email-dsn', 'placeholder': 'Email Address', 'readonly': True})
        }

    def clean(self, *args, **kwargs):
        cleaned_data = super(RegisterUser, self).clean()
        password = cleaned_data.get('password')
        confirm_password = cleaned_data.get('confirm_password')

        if password != confirm_password:
            raise forms.ValidationError(
                "Password does not match"
            )


class LoginForm(forms.Form):
    email = forms.EmailField(
        max_length=254,
        widget=forms.TextInput(
            attrs={
                'class': 'form-control email-dsn',
                'placeholder': 'Email Address',
                'autocomplete': 'off'
            }
        )
    )
    password = forms.CharField(
        max_length=100,
        widget=forms.PasswordInput(
            attrs={
                'class': 'form-control password-dsn',
                'id': 'pwdvisible',
                'placeholder': 'Password',
                'autocomplete': 'off'
            }
        )
    )

    def clean_email(self, *args, **kwargs):
        email = self.cleaned_data.get('email')
        try:
            user = User.objects.get(email=email)
        except:
            raise forms.ValidationError(
                "Invalid username or password"
            )
        return email


class ForgotPasswordForm(forms.Form):
    email = forms.EmailField(max_length=254, widget=forms.TextInput(attrs={'class': 'form-control forgot-email-dsn', 'placeholder': 'Email Address'}))

    def clean(self):
        cleaned_data = super(ForgotPasswordForm, self).clean()
        entered_email = cleaned_data.get("email")
        try:
            userObj = User.objects.get(email__iexact=entered_email)
        except:
            userObj = None
        if not userObj:
            raise forms.ValidationError(
                "User with this email doesn't exist."
            )
        if userObj and not (userObj.authenticated and userObj.email_confirmed):
            raise forms.ValidationError(
                "You need to complete your signup process first."
            )


class CustomPasswordResetForm(PasswordResetForm):
    """
        Overriding the Email Password Resert Forms Save to be able to send custom HTML email
    """
    def save(self, request=None, **kwargs):

        base_url = os.environ.get('PURPLELEAF_URL')
        # base_url = 'http://127.0.0.1:8001'
        if base_url:
            email = super(CustomPasswordResetForm, self).clean()
            user_email = email['email']
            try:
                user = User.objects.get(email=str(user_email))
            except:
                user = None
            if user:
                uid = urlsafe_base64_encode(force_bytes(user.pk)).decode()
                token = default_token_generator.make_token(user)
                password_reset_url = '{0}/reset/{1}/{2}/'.format(base_url,uid,token)
                password_reset_template = render_to_string(
                    'email-templates/reset-password.html',
                    {'reset_link': password_reset_url}
                )
                subject = "Password Reset"
                receiver = user_email
                send_mail(receiver, subject, password_reset_template)