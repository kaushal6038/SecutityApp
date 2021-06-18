# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse
from django.shortcuts import render, redirect
from .forms import *
from .models import *
from django.utils import timezone
from utils.views import LoginRequiredView, TwoFaLoginRequiredView
from django.contrib.auth import authenticate, login, logout
from django.views import View
from django.core.urlresolvers import reverse
from django.forms.utils import ErrorList
from django.contrib.auth.views import password_reset as django_password_reset
import pyotp
from django.conf import settings
from purpleleaf_app.models import *
from purpleleaf_app.alerts import *
from django.contrib import messages
from raven.contrib.django.raven_compat.models import client as sentry_client
from utils.log_user_activity import (
    log_user_activity
)


# Create your views here.
def get_request_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


class InviteConfirm(View):
    error_template = "purpleleaf_app/404.html"

    def get(self, request, *args, **kwargs):
        activation_key = kwargs.get('activation_key')
        try:
            user_profile = User.objects.get(activation_key=activation_key)
        except (User.DoesNotExist, User.MultipleObjectsReturned):
            messages.add_message(request, messages.WARNING, "User does not exists.")
            return render(
                request,
                self.error_template
            )
            #return redirect('/error-404')
        # if timezone.now() < user_profile.key_expires and not user_profile.password:
        return redirect('/register/%s' % activation_key)
        # return HttpResponse("Your Activation key expired")


class UserRegisteration(View):
    form_class = RegisterUser
    template_name = 'purpleleaf_app/signup.html'
    error_template = "purpleleaf_app/404.html"
    context = {}

    def get(self, request, *args, **kwargs):
        activationKey = kwargs.get('activation_key')
        try:
            appuserObj = User.objects.get(activation_key=activationKey)
        except (User.DoesNotExist, User.MultipleObjectsReturned):
            messages.add_message(request, messages.WARNING, "User does not exists.")
            return render(
                request,
                self.error_template
            )
            #return redirect('/error-404')
        self.context['form'] = self.form_class(instance=appuserObj)
        return render(request, self.template_name, self.context)

    def post(self, request, *args, **kwargs):
        activationKey = kwargs.get('activation_key')
        try:
            appuserObj = User.objects.get(activation_key=activationKey)
        except (User.DoesNotExist, User.MultipleObjectsReturned):
            messages.add_message(request, messages.WARNING, "User does not exists.")
            return render(
                request,
                self.error_template
            )
            #return redirect('/error-404')
        form = self.form_class(request.POST, instance=appuserObj)
        if form.is_valid():
            userObj = form.save(commit=False)
            userObj.set_password(form.cleaned_data.get('password'))
            salt = hashlib.sha1(str(random.random())).hexdigest()[:5]
            auth_key = hashlib.sha1(salt + activationKey).hexdigest()
            userObj.authentication_key = auth_key
            userObj.email_confirmed = True
            userObj.secret_key = pyotp.random_base32()
            totp = pyotp.totp.TOTP(userObj.secret_key).provisioning_uri("PurpleLeaf", issuer_name=userObj.email)
            userObj.qrcode = settings.CHART_API + totp
            userObj.save()
            return redirect('/verification/%s' % auth_key)

        self.context['form'] = form
        return render(request, self.template_name, self.context)


class VerifyAccount(View):
    template_name = 'purpleleaf_app/verification.html'
    error_template = "purpleleaf_app/404.html"
    context = dict()

    def get(self, request, *args, **kwargs):
        auth_key = kwargs.get('auth_key')
        try:
            userObj = User.objects.get(authentication_key=auth_key)
        except (User.DoesNotExist, KeyError, User.MultipleObjectsReturned):
            userObj = None
        if userObj and userObj.qrcode:
            self.context['qrcode'] = userObj.qrcode
            self.context['auth_key'] = auth_key
            return render(request, self.template_name, self.context)
        messages.add_message(request, messages.WARNING, "User does not exists.")
        return render(
            request,
            self.error_template
        )
        #return redirect('/error-404')


class VerifyGoogleAuthOtp(View):
    privateconf_model_class = PrivateConfiguration

    def post(self, request, *args, **kwargs):
        auth_key = kwargs.get('auth_key')
        try:
            userObj = User.objects.get(authentication_key=auth_key)
        except (User.DoesNotExist, KeyError):
            response = {
                'status': "User Not Found"
            }
            return JsonResponse(response, safe=False)
        otp = request.POST.get('otp')
        totp = pyotp.TOTP(userObj.secret_key)
        if totp.verify(otp):
            userObj.activation_key = None
            userObj.authentication_key = None
            userObj.twofa_type = "google_auth"
            userObj.key_expires = None
            userObj.authenticated = True
            userObj.save()
            login(request, userObj)
            request.session['twofa_status'] = True
            privateConfObj = self.privateconf_model_class.objects.first()
            if privateConfObj:
                headers = {'data-auth-key': privateConfObj.data_auth_key}
                post_url = "{}/private/registraion_mail/".format(privateConfObj.redtree_base_url)
                data = {
                    'username': userObj.name,
                    'user_email' : userObj.email
                }
                try:
                    status = requests.post(post_url, headers=headers, data=data)
                except:
                    status = None
            return JsonResponse(True, safe=False)
        return JsonResponse(False, safe=False)


class GenerateSmsOtp(View):

    def post(self, request, *args, **kwargs):
        phone_number = request.POST.get('phone_number')
        sending_response = send_confirmation_code(phone_number)
        if sending_response:
            request.session['verification_code'] = sending_response
            request.session['phone_number'] = phone_number
            response = {
                'status': True,
                'phone_number': phone_number
            }
            return JsonResponse(response, safe=False)
        else:
            response = {
                'status': False,
                'phone_number': phone_number
            }
            return JsonResponse(response, safe=False)


class VerifySmsOtp(View):
    privateconf_model_class = PrivateConfiguration

    def post(self, request, *args, **kwargs):
        auth_key = kwargs.get('auth_key')
        try:
            userObj = User.objects.get(authentication_key=auth_key)
        except (User.DoesNotExist, KeyError):
            # return redirect('/error-404')
            return JsonResponse(False, safe=False)
        otp = request.POST.get('otp')
        try:
            verification_code = request.session['verification_code']
        except:
            verification_code = ""
        if verification_code == otp:
            userObj.phone_number = request.session['phone_number']
            userObj.activation_key = ''
            userObj.authentication_key = ''
            userObj.twofa_type = "phone"
            userObj.key_expires = None
            userObj.authenticated = True
            userObj.save()
            login(request, userObj)
            request.session['twofa_status'] = True
            privateConfObj = self.privateconf_model_class.objects.first()
            if privateConfObj:
                headers = {'data-auth-key': privateConfObj.data_auth_key}
                post_url = "{}/private/registraion_mail/".format(privateConfObj.redtree_base_url)
                data = {
                    'username': userObj.name,
                    'user_email' : userObj.email
                }
                try:
                    status = requests.post(post_url, headers=headers, data=data)
                except:
                    status = None
            del request.session['verification_code']
            del request.session['phone_number']
            return JsonResponse(True, safe=False)
        return JsonResponse(False, safe=False)


class LoginView(View):
    form_class = LoginForm
    context = {
        'title': 'Login',
    }
    template_name = "purpleleaf_app/login.html"

    def get(self, request, *args, **kwargs):
        twofaKey = self.request.session.get('twofa_status')
        self.context['form'] = self.form_class()
        self.context['message'] = None
        response = render(request, self.template_name, self.context)
        if request.user.is_authenticated() and twofaKey:
            return HttpResponseRedirect(reverse('purpleleaf:dashboard'))
        elif request.user.is_authenticated() and not twofaKey:
            logout(request)
            return HttpResponseRedirect(reverse('account:signin'))
        elif request.user.is_anonymous and not twofaKey:
            return response
        return response

    def post(self, request, *args, **kwargs):
        if request.user.is_authenticated() and request.user.twofa_status:
            return HttpResponseRedirect(reverse('purpleleaf:dashboard'))

        form = self.form_class(request.POST)
        if form.is_valid():
            email = form.cleaned_data.get('email')
            password = form.cleaned_data.get('password')

            user = authenticate(
                email=email,
                password=password,
            )
            attempts = AccessAttempt.objects.filter(email=email)
            if attempts:
                prev_attmpts = attempts.count()
            else:
                prev_attmpts = 0
            if user:
                if user.is_active and prev_attmpts <= settings.MAX_ATTEMPTS:
                    login(request, user)
                    return HttpResponseRedirect(reverse('account:twofa'))

                elif prev_attmpts > settings.MAX_ATTEMPTS:
                    html_content = "Hi, <br><br>An account with email {0} is blocked due to too many invalid login attempts." \
                                   "<br><br>Thanks, <br><br>Team PurpleLeaf".format(email)
                    subject = "Account Activity."
                    reciever = "saas-admin@virtue.nyc"
                    send_mail(reciever, subject, html_content)
                    messages.warning(request, "You are locked out due to too many invalid login attempts")

                messages.warning(request, "You are not allowed to access this page")
            else:
                errors = form._errors.setdefault("password", ErrorList())
                errors.append(u"Invalid username or password")

        self.context['form'] = form
        return render(request, self.template_name, self.context)


class TwoFaLogin(LoginRequiredView):
    template_name = 'purpleleaf_app/twofa.html'
    context={}

    def get(self, request, *args, **kwargs):
        user = request.user
        twofaKey = request.session.get('twofa_status')
        if twofaKey:
            return HttpResponseRedirect(reverse('purpleleaf:dashboard'))
        user = request.user
        twofa_type = user.twofa_type
        phone_number = user.phone_number
        if twofa_type == "phone":
            sending_response = '123456' 
            # send_confirmation_code(phone_number)
            if sending_response:
                request.session['verification_code'] = sending_response
        self.context['twofa_type'] = twofa_type
        return render(request, self.template_name, self.context)


class VerfiyTwoFaLogin(LoginRequiredView):
    
    def post(self, request, *args, **kwargs):
        try:
            user = request.user
            request_ip = get_request_ip(request)
            if 'totp' in request.body:
                otp = request.POST.get('totp')
                totp = pyotp.TOTP(user.secret_key)
                if totp.verify(otp):
                    log_user_activity(request)
                    EventHistory.objects.create(event_type='login', time_stamp=datetime.datetime.now().strftime('%s'),
                                                data=user.email, username=user.email, ip=request_ip)
                    if AccessAttempt.objects.filter(email=user.email).exists():
                        AccessAttempt.objects.filter(email=user.email).delete()
                    user.twofa_status = True
                    user.save()
                    request.session['twofa_status'] = True
                    return JsonResponse(True, safe=False)
                else:
                    return JsonResponse(False, safe=False)
            elif 'otp' in request.body:
                otp = request.POST.get('otp')
                try:
                    verification_code = request.session['verification_code']
                except:
                    verification_code = None
                if verification_code == otp:
                    user.twofa_status = True
                    log_user_activity(request)
                    EventHistory.objects.create(event_type='login', time_stamp=datetime.datetime.now().strftime('%s'),
                                                data=user.email, username=user.email, ip=request_ip)
                    del request.session['verification_code']
                    user.save()
                    request.session['twofa_status'] = True
                    return JsonResponse(True, safe=False)
                return JsonResponse(False, safe=False)
            else:
                return JsonResponse(False, safe=False)
        except:
            sentry_client.captureException() # Sending sentry mail
            return JsonResponse('error', safe=False)


class UserLogoutView(View):
    next_page = 'account:signin'
    def get(self, request, *args, **kwargs):
        user = request.user
        try:
            twofa_status = request.session['twofa_status']
        except:
            twofa_status = None
        if user.is_authenticated and not twofa_status:
            return HttpResponseRedirect(reverse('account:twofa'))
        if not user.is_authenticated and not twofa_status:
            response = HttpResponseRedirect(reverse(self.next_page))
            for cookie_key in request.COOKIES.keys():
                if cookie_key != "csrftoken":
                    response.delete_cookie(cookie_key)
            return response
        user.twofa_status = False
        user.save()
        logout(request)
        response = HttpResponseRedirect(reverse(self.next_page))
        for cookie_key in request.COOKIES.keys():
            if cookie_key != "csrftoken":
                response.delete_cookie(cookie_key)
        return response


class PasswordResetNotified(View):
    template_name = "registration/password_reset_notified.html"

    def get(self, request, *args, **kwargs):

        if 'HTTP_REFERER' in request.META:
            return render(
                request,
                self.template_name,
                {}
            )
        else:
            return HttpResponseRedirect(reverse('account:signin'))


def PasswordReset(*args, **kwargs):
    """
        Overriding the Email Password Resert Forms(CustomPasswordResetForm) Save to be able to send custom HTML email
    """
    kwargs['password_reset_form'] = CustomPasswordResetForm
    return django_password_reset(*args, **kwargs)
