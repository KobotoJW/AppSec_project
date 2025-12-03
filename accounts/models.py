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
        user.set_password(password)  # Uses Django's built-in hashing
        user.save(using=self._db)
        return user
    
    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)
        return self.create_user(email, password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(unique=True, max_length=255)
    is_active = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
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
        raw_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        expires_at = timezone.now() + timedelta(hours=cls.TOKEN_EXPIRY_HOURS)
        
        # If existing unused tokens, mark them as used
        cls.objects.filter(user=user, used=False).update(used=True)
        token = cls.objects.create(
            user=user,
            token_hash=token_hash,
            expires_at=expires_at
        )
        
        return raw_token, token
    
    @classmethod
    def verify_token(cls, raw_token):
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        
        try:
            token = cls.objects.select_related('user').get(token_hash=token_hash)
        except cls.DoesNotExist:
            return False, 'Invalid activation token.', None
        
        if token.used:
            return False, 'This activation link has already been used.', None
        
        if timezone.now() > token.expires_at:
            return False, 'This activation link has expired.', token.user
        
        token.used = True
        token.save()
        
        return True, 'Account activated successfully.', token.user
    
    @property
    def is_expired(self):
        return timezone.now() > self.expires_at
