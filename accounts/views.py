from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth import get_user_model, login, logout
from django.views import View
from django.conf import settings
from django.core.mail import send_mail, EmailMessage
from django.urls import reverse
from django.contrib.auth.decorators import login_required
from django.utils.decorators import method_decorator
from django.views.decorators.http import require_http_methods
from django.utils import timezone
from django.core.cache import cache
from django.http import HttpResponse
from datetime import timedelta
from functools import wraps

from .forms import RegistrationForm, ResendActivationForm, LoginForm, PasswordResetRequestForm, PasswordResetForm
from .models import ActivationToken, PasswordResetToken, LoginAttempt, SecurityEvent

User = get_user_model()


def rate_limit(max_attempts=5, window_seconds=900):
    def decorator(func):
        @wraps(func)
        def wrapper(self, request, *args, **kwargs):
            # Get client IP
            x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
            if x_forwarded_for:
                client_ip = x_forwarded_for.split(',')[0]
            else:
                client_ip = request.META.get('REMOTE_ADDR', '0.0.0.0')
            
            cache_key = f'rate_limit:{func.__name__}:{client_ip}'
            
            attempts = cache.get(cache_key, 0)
            
            if attempts >= max_attempts:
                print(f"\n{'='*60}")
                print(f"RATE LIMIT EXCEEDED")
                print(f"{'='*60}")
                print(f"Endpoint: {func.__name__}")
                print(f"IP Address: {client_ip}")
                print(f"Attempts: {attempts}/{max_attempts}")
                print(f"Cache key: {cache_key}")
                print(f"{'='*60}\n")
                
                return HttpResponse(
                    'Too many login attempts. Please try again later.',
                    status=429,
                    content_type='text/plain'
                )
            
            cache.set(cache_key, attempts + 1, window_seconds)
            
            return func(self, request, *args, **kwargs)
        
        return wrapper
    return decorator


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
            print(f"\n{'='*60}")
            print(f"SENDING ACTIVATION EMAIL TO: {user.email}")
            print(f"{'='*60}")
            print(f"Raw token (for hashing): {raw_token}")
            print(f"Activation URL: {activation_url}")
            
            email = EmailMessage(
                subject=subject,
                body=message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                to=[user.email],
            )
            result = email.send(fail_silently=False)
            
            print(f"Email sent successfully. Messages sent: {result}")
            print(f"{'='*60}\n")
        except Exception as e:
            print(f"\n{'='*60}")
            print(f"ERROR: Failed to send activation email to {user.email}")
            print(f"Exception: {e}")
            print(f"{'='*60}\n")
            raise


class LoginView(View):
    template_name = 'accounts/login.html'
    
    def get(self, request):
        if request.user.is_authenticated:
            return redirect('accounts:dashboard')
        form = LoginForm()
        return render(request, self.template_name, {'form': form})
    
    @rate_limit(max_attempts=5, window_seconds=900)
    def post(self, request):
        form = LoginForm(request.POST)
        email = request.POST.get('email', '').lower().strip()
        ip_address = self._get_client_ip(request)
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        
        if form.is_valid():
            user = form.user
            
            LoginAttempt.objects.create(
                email=email,
                ip_address=ip_address,
                user_agent=user_agent,
                success=True
            )
            
            SecurityEvent.objects.create(
                user=user,
                event_type='login',
                ip_address=ip_address,
                user_agent=user_agent,
                details={'email': email}
            )
            
            # Update last_login
            user.last_login = timezone.now()
            user.save(update_fields=['last_login'])
            
            # Log in user (Django session)
            login(request, user, backend='django.contrib.auth.backends.ModelBackend')
            
            messages.success(request, 'Logged in successfully.')
            return redirect('accounts:dashboard')
        else:
            # Log failed login attempt
            LoginAttempt.objects.create(
                email=email,
                ip_address=ip_address,
                user_agent=user_agent,
                success=False
            )
            
            # Check if we should lock the account
            self._check_and_lock_account(email, ip_address)
        
        return render(request, self.template_name, {'form': form})
    
    def _get_client_ip(self, request):
        """Extract client IP address from request."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR', '0.0.0.0')
        return ip
    
    def _check_and_lock_account(self, email, ip_address):
        """Check failed login attempts and lock account if threshold exceeded."""
        # Check failed attempts in last 15 minutes
        fifteen_minutes_ago = timezone.now() - timedelta(minutes=15)
        failed_attempts = LoginAttempt.objects.filter(
            email=email,
            success=False,
            created_at__gte=fifteen_minutes_ago
        ).count()
        
        # Lock account after 5 failed attempts
        if failed_attempts >= 5:
            try:
                user = User.objects.get(email=email)
                user.is_locked = True
                user.locked_until = timezone.now() + timedelta(minutes=15)
                user.save(update_fields=['is_locked', 'locked_until'])
                
                # Create security event
                SecurityEvent.objects.create(
                    user=user,
                    event_type='account_locked',
                    ip_address=ip_address,
                    details={'reason': 'multiple_failed_attempts'}
                )
            except User.DoesNotExist:
                pass


class LogoutView(View):
    def get(self, request):
        if request.user.is_authenticated:
            # Create security event
            SecurityEvent.objects.create(
                user=request.user,
                event_type='logout',
                ip_address=self._get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )
        
        logout(request)
        messages.success(request, 'Logged out successfully.')
        return redirect('accounts:login')
    
    def _get_client_ip(self, request):
        """Extract client IP address from request."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR', '0.0.0.0')
        return ip


class DashboardView(View):
    template_name = 'accounts/dashboard.html'
    
    @method_decorator(login_required(login_url='accounts:login'))
    def get(self, request):
        context = {
            'user': request.user,
            'last_login': request.user.last_login,
        }
        return render(request, self.template_name, context)


class PasswordResetRequestView(View):
    template_name = 'accounts/password_reset_request.html'
    
    def get(self, request):
        form = PasswordResetRequestForm()
        return render(request, self.template_name, {'form': form})
    
    @rate_limit(max_attempts=3, window_seconds=3600)  # 3 attempts per hour per IP
    def post(self, request):
        form = PasswordResetRequestForm(request.POST)
        ip_address = self._get_client_ip(request)
        
        if form.is_valid():
            email = form.cleaned_data['email'].lower().strip()
            
            try:
                user = User.objects.get(email=email)
                raw_token, token = PasswordResetToken.create_token(user)
                
                self._send_password_reset_email(request, user, raw_token)
                
                # Create security event
                SecurityEvent.objects.create(
                    user=user,
                    event_type='password_reset',
                    ip_address=ip_address,
                    user_agent=request.META.get('HTTP_USER_AGENT', ''),
                    details={'action': 'reset_requested'}
                )
            except User.DoesNotExist:
                # Don't reveal if email exists (prevent enumeration)
                pass
            
            # Always show same message to prevent enumeration
            messages.success(
                request,
                'If an account exists with that email, a password reset link has been sent.'
            )
            return redirect('accounts:login')
        
        return render(request, self.template_name, {'form': form})
    
    def _get_client_ip(self, request):
        """Extract client IP address from request."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR', '0.0.0.0')
        return ip
    
    def _send_password_reset_email(self, request, user, raw_token):
        reset_url = request.build_absolute_uri(
            reverse('accounts:password_reset_confirm', kwargs={'token': raw_token})
        )
        
        subject = 'Password Reset Request'
        message = f"""Hello,

Please click the link below to reset your password:

{reset_url}

This link will expire in 1 hour.

If you did not request a password reset, please ignore this email.
"""
        
        try:
            print(f"\n{'='*60}")
            print(f"SENDING PASSWORD RESET EMAIL TO: {user.email}")
            print(f"{'='*60}")
            print(f"Password reset URL: {reset_url}")
            
            # Use EmailMessage to avoid quoted-printable encoding issues
            email = EmailMessage(
                subject=subject,
                body=message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                to=[user.email],
            )
            result = email.send(fail_silently=False)
            
            print(f"Email sent successfully. Messages sent: {result}")
            print(f"{'='*60}\n")
        except Exception as e:
            print(f"\n{'='*60}")
            print(f"ERROR: Failed to send password reset email to {user.email}")
            print(f"Exception: {e}")
            print(f"{'='*60}\n")
            raise


class PasswordResetConfirmView(View):
    template_name = 'accounts/password_reset_confirm.html'
    
    def get(self, request, token):
        # Just display the form with the token (don't verify yet)
        form = PasswordResetForm()
        context = {
            'form': form,
            'token': token,
        }
        return render(request, self.template_name, context)
    
    def post(self, request, token):
        form = PasswordResetForm(request.POST)
        
        if form.is_valid():
            password = form.cleaned_data['password']
            ip_address = self._get_client_ip(request)
            
            # Verify token
            success, message, user = PasswordResetToken.verify_token(token)
            
            if success and user:
                # Set new password
                user.set_password(password)
                user.save(update_fields=['password'])
                
                # Invalidate all sessions
                self._invalidate_all_sessions(user)
                
                # Create security event
                SecurityEvent.objects.create(
                    user=user,
                    event_type='password_change',
                    ip_address=ip_address,
                    user_agent=request.META.get('HTTP_USER_AGENT', ''),
                    details={'action': 'password_reset_completed'}
                )
                
                messages.success(
                    request,
                    'Password reset successful. Please log in with your new password.'
                )
                return redirect('accounts:login')
            else:
                # Token invalid or expired
                context = {
                    'error_message': message,
                    'token': token,
                }
                return render(request, 'accounts/password_reset_failed.html', context)
        
        context = {
            'form': form,
            'token': token,
        }
        return render(request, self.template_name, context)
    
    def _get_client_ip(self, request):
        """Extract client IP address from request."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR', '0.0.0.0')
        return ip
    
    def _invalidate_all_sessions(self, user):
        """Invalidate all sessions for a user."""
        # In Django, sessions are stored in the database or cache
        # We can use the session framework to clear all sessions for this user
        from django.contrib.sessions.models import Session
        import json
        
        for session in Session.objects.all():
            data = session.get_decoded()
            if data.get('_auth_user_id') == str(user.id):
                session.delete()


class RegistrationSuccessView(View):
    template_name = 'accounts/registration_success.html'
    
    def get(self, request):
        return render(request, self.template_name)


class ActivateAccountView(View):    
    def get(self, request, token):
        print(f"\n{'='*60}")
        print(f"ACTIVATION REQUEST RECEIVED")
        print(f"Token: {token[:20]}...")
        print(f"{'='*60}\n")
        
        success, message, user = ActivationToken.verify_token(token)
        
        print(f"\nVerification result: success={success}, message={message}, user={user.email if user else None}\n")
        
        if success:
            print(f"Setting user {user.email} as active")
            user.is_active = True
            user.save()
            print(f"User saved successfully\n")
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
            print(f"\n{'='*60}")
            print(f"SENDING ACTIVATION EMAIL TO: {user.email}")
            print(f"{'='*60}")
            result = send_mail(
                subject=subject,
                message=message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[user.email],
                fail_silently=False,
            )
            print(f"Email sent successfully. Messages sent: {result}")
            print(f"{'='*60}\n")
        except Exception as e:
            print(f"\n{'='*60}")
            print(f"ERROR: Failed to send activation email to {user.email}")
            print(f"Exception: {e}")
            print(f"{'='*60}\n")
            raise
