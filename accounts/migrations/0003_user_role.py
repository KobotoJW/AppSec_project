                                             

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0002_user_is_locked_user_locked_until_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='role',
            field=models.CharField(choices=[('user', 'Regular User'), ('admin', 'Administrator')], default='user', max_length=10),
        ),
    ]
