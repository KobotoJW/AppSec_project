import uuid
import hashlib
import secrets
from datetime import timedelta

from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models
from django.utils import timezone


class CustomUserManager(BaseUserManager):    
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('Email is required')
        if not password:
            raise ValueError('Password is required')
        email = self.normalize_email(email)
        extra_fields.setdefault('is_active', False)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user
    
    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)
        return self.create_user(email, password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    ROLE_CHOICES = [
        ('user', 'Regular User'),
        ('admin', 'Administrator'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(unique=True, max_length=255)
    is_active = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='user')
    last_login = models.DateTimeField(null=True, blank=True)
    is_locked = models.BooleanField(default=False)
    locked_until = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    objects = CustomUserManager()
    
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []
    
    class Meta:
        db_table = 'users'
        verbose_name = 'user'
        verbose_name_plural = 'users'
    
    def __str__(self):
        return self.email
    
    @property
    def is_admin(self):
        """Check if user has admin role"""
        return self.role == 'admin' or self.is_superuser
    
    @property
    def is_account_locked(self):
        """Check if account is currently locked (lockout expired)."""
        if not self.is_locked:
            return False
        if self.locked_until and timezone.now() >= self.locked_until:
            self.is_locked = False
            self.locked_until = None
            self.save(update_fields=['is_locked', 'locked_until'])
            return False
        return True


class ActivationToken(models.Model):
    TOKEN_EXPIRY_HOURS = 24
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='activation_tokens')
    token_hash = models.CharField(max_length=64, unique=True)
    expires_at = models.DateTimeField()
    used = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'activation_tokens'
        verbose_name = 'activation token'
        verbose_name_plural = 'activation tokens'
    
    def __str__(self):
        return f"Token for {self.user.email}"
    
    @classmethod
    def create_token(cls, user):
        raw_token = secrets.token_hex(32)
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        expires_at = timezone.now() + timedelta(hours=cls.TOKEN_EXPIRY_HOURS)
        
        # Mark old tokens as used
        cls.objects.filter(user=user, used=False).update(used=True)
        
        token = cls.objects.create(
            user=user,
            token_hash=token_hash,
            expires_at=expires_at
        )
        
        return raw_token, token
    
    @classmethod
    def verify_token(cls, raw_token):
        """
        Verify activation token with constant-time checks to prevent timing attacks
        """
        import hmac
        
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        
        try:
            token = cls.objects.select_related('user').get(token_hash=token_hash)
            
            # Perform all checks before returning to prevent timing attacks
            is_valid = (
                not token.used and
                timezone.now() <= token.expires_at
            )
            
            if is_valid:
                # Mark token as used
                token.used = True
                token.save(update_fields=['used'])
                return True, 'Account activated successfully.', token.user
            
        except cls.DoesNotExist:
            pass  # Fall through to generic error
        
        # Always return same generic message to prevent timing attacks
        # Don't reveal if token exists, is used, or is expired
        return False, 'Invalid or expired activation link.', None
    
    @property
    def is_expired(self):
        return timezone.now() > self.expires_at


class PasswordResetToken(models.Model):
    TOKEN_EXPIRY_HOURS = 1
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='password_reset_tokens')
    token_hash = models.CharField(max_length=64, unique=True)
    expires_at = models.DateTimeField()
    used = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'password_reset_tokens'
        verbose_name = 'password reset token'
        verbose_name_plural = 'password reset tokens'
    
    def __str__(self):
        return f"Reset token for {self.user.email}"
    
    @classmethod
    def create_token(cls, user):
        """Create a password reset token for a user."""
        raw_token = secrets.token_hex(32)
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        expires_at = timezone.now() + timedelta(hours=cls.TOKEN_EXPIRY_HOURS)
        
        cls.objects.filter(user=user, used=False).update(used=True)
        token = cls.objects.create(
            user=user,
            token_hash=token_hash,
            expires_at=expires_at
        )
        
        return raw_token, token
    
    @classmethod
    def verify_token(cls, raw_token):
        """
        Verify password reset token with constant-time checks to prevent timing attacks
        """
        import hmac
        
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        
        try:
            token = cls.objects.select_related('user').get(token_hash=token_hash)
            
            # Perform all checks before returning to prevent timing attacks
            is_valid = (
                not token.used and
                timezone.now() <= token.expires_at
            )
            
            if is_valid:
                # Mark token as used
                token.used = True
                token.save(update_fields=['used'])
                return True, 'Password reset successful.', token.user
            
        except cls.DoesNotExist:
            pass  # Fall through to generic error
        
        # Always return same generic message to prevent timing attacks
        return False, 'Invalid or expired password reset link.', None
    
    @property
    def is_expired(self):
        return timezone.now() > self.expires_at


class LoginAttempt(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(max_length=255)
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField(blank=True)
    success = models.BooleanField()
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'login_attempts'
        verbose_name = 'login attempt'
        verbose_name_plural = 'login attempts'
        indexes = [
            models.Index(fields=['email', '-created_at']),
            models.Index(fields=['ip_address', '-created_at']),
        ]
    
    def __str__(self):
        status = 'Success' if self.success else 'Failed'
        return f"{status} login attempt for {self.email} from {self.ip_address}"


class SecurityEvent(models.Model):
    EVENT_TYPE_CHOICES = [
        ('login', 'Login'),
        ('logout', 'Logout'),
        ('password_change', 'Password Change'),
        ('password_reset', 'Password Reset'),
        ('account_locked', 'Account Locked'),
        ('account_unlocked', 'Account Unlocked'),
        ('activation', 'Account Activation'),
        ('failed_login', 'Failed Login'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='security_events', null=True, blank=True)
    event_type = models.CharField(max_length=50, choices=EVENT_TYPE_CHOICES)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    details = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'security_events'
        verbose_name = 'security event'
        verbose_name_plural = 'security events'
        indexes = [
            models.Index(fields=['user', '-created_at']),
            models.Index(fields=['event_type', '-created_at']),
        ]
    
    def __str__(self):
        user_str = self.user.email if self.user else 'Anonymous'
        return f"{self.get_event_type_display()} for {user_str} at {self.created_at}"