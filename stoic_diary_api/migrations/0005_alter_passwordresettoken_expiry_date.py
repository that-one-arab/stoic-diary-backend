# Generated by Django 3.2.15 on 2022-09-17 05:43

from django.db import migrations, models
import stoic_diary_api.models


class Migration(migrations.Migration):

    dependencies = [
        ('stoic_diary_api', '0004_alter_passwordresettoken_expiry_date'),
    ]

    operations = [
        migrations.AlterField(
            model_name='passwordresettoken',
            name='expiry_date',
            field=models.DateTimeField(default=stoic_diary_api.models.get_expiry_date),
        ),
    ]
