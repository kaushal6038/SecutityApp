from django.views import View
from django.utils.decorators import method_decorator
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.mixins import UserPassesTestMixin, LoginRequiredMixin
from django.core.urlresolvers import reverse, reverse_lazy
from django.http import HttpResponseRedirect
from django.contrib.auth import logout


class LoginRequiredView(View):
    @method_decorator(login_required)
    def dispatch(self, *args, **kwargs):
        return super(LoginRequiredView, self).dispatch(*args, **kwargs)


class TwoFaLoginRequiredView(LoginRequiredMixin, View):

	def dispatch(self, *args, **kwargs):

		twofaKey = self.request.session.get('twofa_status')
		if self.request.user.is_authenticated and twofaKey:
			return super(TwoFaLoginRequiredView, self).dispatch(*args, **kwargs)
		elif self.request.user.is_authenticated and not twofaKey:
			return HttpResponseRedirect(reverse('account:twofa'))
		return HttpResponseRedirect(reverse('account:signin'))
