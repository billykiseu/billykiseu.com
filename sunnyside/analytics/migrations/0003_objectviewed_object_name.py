# Generated by Django 4.1.1 on 2022-10-03 11:17

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('analytics', '0002_usersession'),
    ]

    operations = [
        migrations.AddField(
            model_name='objectviewed',
            name='object_name',
            field=models.CharField(blank=True, max_length=120, null=True),
        ),
    ]
