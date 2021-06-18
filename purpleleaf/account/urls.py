from django.conf.urls import url
from . import views
from django.contrib.auth import views as auth_views
from .views import (
    InviteConfirm,
    UserRegisteration,
    VerifyAccount,
    VerifyGoogleAuthOtp,
    GenerateSmsOtp,
    VerifySmsOtp,
    LoginView,
    UserLogoutView,
    TwoFaLogin,
    VerfiyTwoFaLogin,
    PasswordResetNotified,
    PasswordReset
)

urlpatterns = [
    url(r'^invite/(?P<activation_key>\w+)/$', InviteConfirm.as_view(), name='invite'),
    url(r'^register/(?P<activation_key>\w+)/$', UserRegisteration.as_view(), name='register'),
    url(r'^verification/(?P<auth_key>\w+)/$', VerifyAccount.as_view(), name='verification'),
    url(r'^verification/(?P<auth_key>\w+)/google-auth/otp/$', VerifyGoogleAuthOtp.as_view(), name='verification_gauth_otp'),
    url(r'^verification/(?P<auth_key>\w+)/generate-otp/$', GenerateSmsOtp.as_view(), name='generate_otp'),
    url(r'^verification/(?P<auth_key>\w+)/sms/otp/$', VerifySmsOtp.as_view(), name='verify_otp'),
    url(r'^signin/$', LoginView.as_view(), name='signin'),
    url(r'^2fa/$', TwoFaLogin.as_view(), name='twofa'),
    url(r'^verify-2fa/$', VerfiyTwoFaLogin.as_view(), name='verify_twofa'),
    url(r'^signout/$', UserLogoutView.as_view(), name='signout'),
    url(r'^password-reset/$', PasswordReset, {'post_reset_redirect' : 'account:password_reset_notified'}, name="password_reset"),
    url(r'^password-reset/done/$', auth_views.password_reset_done, name='password_reset_done'),
    url(r'^password_reset/$', PasswordResetNotified.as_view(), name='password_reset_notified'),
    url(r'^reset/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/$',
        auth_views.password_reset_confirm, name='password_reset_confirm'),
    url(r'^reset/done/$', auth_views.password_reset_complete, name='password_reset_complete'),
]