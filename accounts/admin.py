from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.utils.html import format_html
from .models import User, ActivationToken, SecurityEvent, LoginAttempt


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


@admin.register(SecurityEvent)
class SecurityEventAdmin(admin.ModelAdmin):
    list_display = ('created_at', 'event_type_badge', 'user', 'ip_address', 'user_agent_short')
    list_filter = ('event_type', 'created_at')
    search_fields = ('user__email', 'ip_address')
    readonly_fields = ('id', 'user', 'event_type', 'ip_address', 'user_agent', 'details', 'created_at')
    ordering = ('-created_at',)
    
    def event_type_badge(self, obj):
        colors = {
            'login': '#28a745',
            'logout': '#6c757d',
            'password_change': '#ffc107',
            'password_reset': '#ffc107',
            'account_locked': '#dc3545',
            'account_unlocked': '#17a2b8',
            'activation': '#28a745',
            'failed_login': '#dc3545',
        }
        color = colors.get(obj.event_type, '#6c757d')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 8px; border-radius: 3px; font-weight: bold;">{}</span>',
            color,
            obj.event_type
        )
    event_type_badge.short_description = 'Event Type'
    
    def user_agent_short(self, obj):
        return obj.user_agent[:50] + '...' if len(obj.user_agent) > 50 else obj.user_agent
    user_agent_short.short_description = 'User Agent'
    
    def has_add_permission(self, request):
        return False
    
    def has_delete_permission(self, request, obj=None):
        return False
    
    def has_change_permission(self, request, obj=None):
        return False


@admin.register(LoginAttempt)
class LoginAttemptAdmin(admin.ModelAdmin):
    list_display = ('created_at', 'email', 'success_badge', 'ip_address', 'user_agent_short')
    list_filter = ('success', 'created_at')
    search_fields = ('email', 'ip_address')
    readonly_fields = ('email', 'ip_address', 'user_agent', 'success', 'created_at')
    ordering = ('-created_at',)
    
    def success_badge(self, obj):
        if obj.success:
            return format_html(
                '<span style="background-color: #28a745; color: white; padding: 3px 8px; border-radius: 3px; font-weight: bold;">✓ Success</span>'
            )
        else:
            return format_html(
                '<span style="background-color: #dc3545; color: white; padding: 3px 8px; border-radius: 3px; font-weight: bold;">✗ Failed</span>'
            )
    success_badge.short_description = 'Status'
    
    def user_agent_short(self, obj):
        return obj.user_agent[:50] + '...' if len(obj.user_agent) > 50 else obj.user_agent
    user_agent_short.short_description = 'User Agent'
    
    def has_add_permission(self, request):
        return False
    
    def has_delete_permission(self, request, obj=None):
        return False
    
    def has_change_permission(self, request, obj=None):
        return False
