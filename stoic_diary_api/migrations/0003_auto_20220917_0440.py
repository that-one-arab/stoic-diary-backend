# Generated by Django 3.2.15 on 2022-09-17 04:40

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('stoic_diary_api', '0002_auto_20220916_1552'),
    ]

    operations = [
        migrations.AddField(
            model_name='passwordresettoken',
            name='expiry_date',
            field=models.DateField(default=datetime.datetime(2022, 9, 17, 4, 50, 45, 47560)),
        ),
        migrations.AlterField(
            model_name='passwordresettoken',
            name='is_valid',
            field=models.BooleanField(default=True),
        ),
    ]
