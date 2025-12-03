from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import User, ActivationToken


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    list_display = ('email', 'is_active', 'is_staff', 'created_at')
    list_filter = ('is_active', 'is_staff')
    search_fields = ('email',)
    ordering = ('-created_at',)
    
    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        ('Permissions', {'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
        ('Timestamps', {'fields': ('created_at', 'updated_at', 'last_login')}),
    )
    readonly_fields = ('created_at', 'updated_at', 'last_login')
    
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'password1', 'password2', 'is_active', 'is_staff'),
        }),
    )


@admin.register(ActivationToken)
class ActivationTokenAdmin(admin.ModelAdmin):
    list_display = ('user', 'used', 'expires_at', 'created_at')
    list_filter = ('used',)
    search_fields = ('user__email',)
    readonly_fields = ('token_hash', 'created_at')
