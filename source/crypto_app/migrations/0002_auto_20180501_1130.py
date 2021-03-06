# Generated by Django 2.0.4 on 2018-05-01 11:30

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('crypto_app', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='CPPCipher',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.TextField()),
                ('isReady', models.BooleanField(default=False)),
                ('programCode', models.TextField(blank=True)),
                ('author', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='crypto_app.Partipicant')),
            ],
        ),
        migrations.RemoveField(
            model_name='executablecipher',
            name='author',
        ),
        migrations.DeleteModel(
            name='ExecutableCipher',
        ),
    ]
