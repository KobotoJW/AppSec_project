                                             

import django.db.models.deletion
import uuid
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='is_locked',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='user',
            name='locked_until',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='user',
            name='last_login',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.CreateModel(
            name='LoginAttempt',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('email', models.EmailField(max_length=255)),
                ('ip_address', models.GenericIPAddressField()),
                ('user_agent', models.TextField(blank=True)),
                ('success', models.BooleanField()),
                ('created_at', models.DateTimeField(auto_now_add=True)),
            ],
            options={
                'verbose_name': 'login attempt',
                'verbose_name_plural': 'login attempts',
                'db_table': 'login_attempts',
                'indexes': [models.Index(fields=['email', '-created_at'], name='login_attem_email_e3bad1_idx'), models.Index(fields=['ip_address', '-created_at'], name='login_attem_ip_addr_d06a3f_idx')],
            },
        ),
        migrations.CreateModel(
            name='PasswordResetToken',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('token_hash', models.CharField(max_length=64, unique=True)),
                ('expires_at', models.DateTimeField()),
                ('used', models.BooleanField(default=False)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='password_reset_tokens', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'password reset token',
                'verbose_name_plural': 'password reset tokens',
                'db_table': 'password_reset_tokens',
            },
        ),
        migrations.CreateModel(
            name='SecurityEvent',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('event_type', models.CharField(choices=[('login', 'Login'), ('logout', 'Logout'), ('password_change', 'Password Change'), ('password_reset', 'Password Reset'), ('account_locked', 'Account Locked'), ('account_unlocked', 'Account Unlocked'), ('activation', 'Account Activation'), ('failed_login', 'Failed Login')], max_length=50)),
                ('ip_address', models.GenericIPAddressField(blank=True, null=True)),
                ('user_agent', models.TextField(blank=True)),
                ('details', models.JSONField(blank=True, default=dict)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('user', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='security_events', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'security event',
                'verbose_name_plural': 'security events',
                'db_table': 'security_events',
                'indexes': [models.Index(fields=['user', '-created_at'], name='security_ev_user_id_c77a93_idx'), models.Index(fields=['event_type', '-created_at'], name='security_ev_event_t_33b3e5_idx')],
            },
        ),
    ]
