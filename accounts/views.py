from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth import get_user_model
from django.views import View
from django.conf import settings
from django.core.mail import send_mail
from django.urls import reverse

from .forms import RegistrationForm, ResendActivationForm
from .models import ActivationToken

User = get_user_model()


class RegisterView(View):
    template_name = 'accounts/register.html'
    
    def get(self, request):
        form = RegistrationForm()
        return render(request, self.template_name, {'form': form})
    
    def post(self, request):
        form = RegistrationForm(request.POST)
        
        if form.is_valid():
            email = form.cleaned_data['email']
            password = form.cleaned_data['password']
            
            user = User.objects.create_user(email=email, password=password)
            raw_token, token = ActivationToken.create_token(user)
            
            self._send_activation_email(request, user, raw_token)
            
            messages.success(
                request, 
                'Registration successful! Please check your email to activate your account.'
            )
            return redirect('accounts:registration_success')
        
        return render(request, self.template_name, {'form': form})
    
    def _send_activation_email(self, request, user, raw_token):
        activation_url = request.build_absolute_uri(
            reverse('accounts:activate', kwargs={'token': raw_token})
        )
        
        subject = 'Activate Your Account'
        message = f"""Hello,

Please click the link below to activate your account:

{activation_url}

This link will expire in 24 hours.

If you did not register for this account, please ignore this email.
"""
        
        try:
            send_mail(
                subject=subject,
                message=message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[user.email],
                fail_silently=False,
            )
        except Exception as e:
            print(f"Failed to send activation email: {e}")


class RegistrationSuccessView(View):
    template_name = 'accounts/registration_success.html'
    
    def get(self, request):
        return render(request, self.template_name)


class ActivateAccountView(View):    
    def get(self, request, token):
        success, message, user = ActivationToken.verify_token(token)
        
        if success:
            user.is_active = True
            user.save()
            messages.success(request, message)
            return redirect('accounts:activation_success')
        else:
            context = {
                'error_message': message,
                'can_resend': user is not None and not user.is_active,
                'user_email': user.email if user else None,
            }
            return render(request, 'accounts/activation_failed.html', context)


class ActivationSuccessView(View):
    template_name = 'accounts/activation_success.html'
    
    def get(self, request):
        return render(request, self.template_name)


class ResendActivationView(View):
    template_name = 'accounts/resend_activation.html'
    
    def get(self, request):
        email = request.GET.get('email', '')
        form = ResendActivationForm(initial={'email': email})
        return render(request, self.template_name, {'form': form})
    
    def post(self, request):
        form = ResendActivationForm(request.POST)
        
        if form.is_valid():
            user = form.user
            
            raw_token, token = ActivationToken.create_token(user)
            
            self._send_activation_email(request, user, raw_token)
            
            messages.success(
                request,
                'A new activation link has been sent to your email.'
            )
            return redirect('accounts:registration_success')
        
        return render(request, self.template_name, {'form': form})
    
    def _send_activation_email(self, request, user, raw_token):
        activation_url = request.build_absolute_uri(
            reverse('accounts:activate', kwargs={'token': raw_token})
        )
        
        subject = 'Activate Your Account'
        message = f"""Hello,

Please click the link below to activate your account:

{activation_url}

This link will expire in 24 hours.

If you did not request this email, please ignore it.
"""
        
        try:
            send_mail(
                subject=subject,
                message=message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[user.email],
                fail_silently=False,
            )
        except Exception as e:
            print(f"Failed to send activation email: {e}")
