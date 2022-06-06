# Generated by Django 3.2.13 on 2022-06-06 11:33

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='UserDetails',
            fields=[
                ('id', models.BigAutoField(auto_created=True,
                 primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=100)),
                ('email', models.EmailField(max_length=100)),
                ('zip_code', models.CharField(max_length=100)),
                ('floor_number', models.CharField(max_length=100)),
            ],
            options={
                'verbose_name_plural': 'User Details',
                'ordering': ['name'],
            },
        ),
    ]
