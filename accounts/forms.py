import re
from django import forms
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.contrib.auth.hashers import check_password

User = get_user_model()


class RegistrationForm(forms.Form):
    """Form for user registration with email and password."""
    
    email = forms.EmailField(
        max_length=255,
        widget=forms.EmailInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter your email',
            'autocomplete': 'email',
            'required': True,
        })
    )
    
    password = forms.CharField(
        min_length=8,
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter password',
            'autocomplete': 'new-password',
            'required': True,
        })
    )
    
    password_confirm = forms.CharField(
        min_length=8,
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Confirm password',
            'autocomplete': 'new-password',
            'required': True,
        })
    )
    
    def clean_email(self):
        email = self.cleaned_data.get('email', '').lower().strip()
        
        if User.objects.filter(email=email).exists():
            raise ValidationError('Unable to create account. Please check your input.')
        
        return email
    
    def clean_password(self):
        password = self.cleaned_data.get('password')
        
        try:
            validate_password(password)
        except ValidationError as e:
            raise ValidationError(list(e.messages))
        
        return password
    
    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get('password')
        password_confirm = cleaned_data.get('password_confirm')
        
        if password and password_confirm and password != password_confirm:
            raise ValidationError({'password_confirm': 'Passwords do not match.'})
        
        return cleaned_data


class ResendActivationForm(forms.Form):    
    email = forms.EmailField(
        max_length=255,
        widget=forms.EmailInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter your email',
            'autocomplete': 'email',
            'required': True,
        })
    )
    
    def clean_email(self):
        email = self.cleaned_data.get('email', '').lower().strip()
        
        try:
            user = User.objects.get(email=email)
            if user.is_active:
                raise ValidationError('If provided email was valid the activation email has been sent.')
            self.user = user
        except User.DoesNotExist:
            raise ValidationError('If provided email was valid the activation email has been sent.')
        
        return email


class LoginForm(forms.Form):
    """Form for user login with email and password."""
    
    email = forms.EmailField(
        max_length=255,
        widget=forms.EmailInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter your email',
            'autocomplete': 'email',
            'required': True,
        })
    )
    
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter password',
            'autocomplete': 'current-password',
            'required': True,
        })
    )
    
    def clean(self):
        cleaned_data = super().clean()
        email = cleaned_data.get('email', '').lower().strip()
        password = cleaned_data.get('password')
        
        if not email or not password:
            return cleaned_data
        
        # Attempt to authenticate user
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            # Generic error to prevent email enumeration
            raise ValidationError('Invalid email or password.')
        
        # Check if account is locked
        if user.is_account_locked:
            raise ValidationError('Account temporarily locked. Please try again later or reset your password.')
        
        # Verify password
        if not user.check_password(password):
            raise ValidationError('Invalid email or password.')
        
        # Check if account is active
        if not user.is_active:
            raise ValidationError('Account is not activated. Please check your email for activation link.')
        
        self.user = user
        return cleaned_data


class PasswordResetRequestForm(forms.Form):
    """Form to request a password reset via email."""
    
    email = forms.EmailField(
        max_length=255,
        widget=forms.EmailInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter your email',
            'autocomplete': 'email',
            'required': True,
        })
    )
    
    def clean_email(self):
        email = self.cleaned_data.get('email', '').lower().strip()
        # Don't reveal if email exists or not (prevent enumeration)
        # Just return the email; view will handle logic
        return email


class PasswordResetForm(forms.Form):
    """Form to set a new password after email verification."""
    
    password = forms.CharField(
        min_length=8,
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter new password',
            'autocomplete': 'new-password',
            'required': True,
        })
    )
    
    password_confirm = forms.CharField(
        min_length=8,
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Confirm new password',
            'autocomplete': 'new-password',
            'required': True,
        })
    )
    
    def clean_password(self):
        password = self.cleaned_data.get('password')
        
        try:
            validate_password(password)
        except ValidationError as e:
            raise ValidationError(list(e.messages))
        
        return password
    
    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get('password')
        password_confirm = cleaned_data.get('password_confirm')
        
        if password and password_confirm and password != password_confirm:
            raise ValidationError({'password_confirm': 'Passwords do not match.'})
        
        return cleaned_data
