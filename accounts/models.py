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
        
        print(f"\n{'='*60}")
        print(f"CREATING ACTIVATION TOKEN FOR: {user.email}")
        print(f"{'='*60}")
        print(f"Raw token: {raw_token}")
        print(f"Token length: {len(raw_token)}")
        print(f"Token hash: {token_hash}")
        print(f"Expires at: {expires_at}")
        
        old_tokens = cls.objects.filter(user=user, used=False).update(used=True)
        print(f"Marked {old_tokens} old tokens as used")
        
        token = cls.objects.create(
            user=user,
            token_hash=token_hash,
            expires_at=expires_at
        )
        print(f"Token created successfully with hash: {token.token_hash[:20]}...")
        print(f"{'='*60}\n")
        
        return raw_token, token
    
    @classmethod
    @classmethod
    def verify_token(cls, raw_token):
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        
        print(f"\n{'='*60}")
        print(f"ACTIVATION TOKEN VERIFICATION")
        print(f"{'='*60}")
        print(f"Raw token (FULL): {raw_token}")
        print(f"Token length: {len(raw_token)}")
        print(f"Token hash: {token_hash}")
        
        all_tokens = cls.objects.filter(user__isnull=False)
        print(f"\nTokens in database: {all_tokens.count()}")
        for t in all_tokens[:5]:
            print(f"  - Hash: {t.token_hash[:30]}... (used={t.used})")
        
        try:
            token = cls.objects.select_related('user').get(token_hash=token_hash)
            print(f"✓ Token found for user: {token.user.email}")
        except cls.DoesNotExist:
            print(f"✗ Token NOT FOUND in database")
            print(f"{'='*60}\n")
            return False, 'Invalid activation token.', None
        
        if token.used:
            print(f"✗ Token already used")
            print(f"{'='*60}\n")
            return False, 'This activation link has already been used.', None
        
        if timezone.now() > token.expires_at:
            print(f"✗ Token expired at: {token.expires_at}")
            print(f"Current time: {timezone.now()}")
            print(f"{'='*60}\n")
            return False, 'This activation link has expired.', token.user
        
        print(f"✓ Token is valid, marking as used")
        token.used = True
        token.save()
        print(f"✓ User {token.user.email} account activated")
        print(f"{'='*60}\n")
        
        return True, 'Account activated successfully.', token.user
    
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
        """Verify and consume a password reset token."""
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        
        try:
            token = cls.objects.select_related('user').get(token_hash=token_hash)
        except cls.DoesNotExist:
            return False, 'Invalid password reset token.', None
        
        if token.used:
            return False, 'This password reset link has already been used.', None
        
        if timezone.now() > token.expires_at:
            return False, 'This password reset link has expired.', token.user
        
        token.used = True
        token.save()
        
        return True, 'Password reset successful.', token.user
    
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