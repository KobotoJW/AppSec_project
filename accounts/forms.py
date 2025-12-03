import re
from django import forms
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError

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
