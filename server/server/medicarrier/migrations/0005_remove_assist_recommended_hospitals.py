# Generated by Django 5.0.7 on 2024-07-29 06:05

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('medicarrier', '0004_hospital_hospital_latitude_and_more'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='assist',
            name='recommended_hospitals',
        ),
    ]
