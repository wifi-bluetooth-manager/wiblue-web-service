from django.db import models
from django.core.validators import MinLengthValidator

class Network(models.Model):
    # id = models.BigAutoField(primary_key=True, null=False)
    ssid = models.CharField(max_length=300,validators=[MinLengthValidator(0)])
    bssid = models.CharField(max_length=300,validators=[MinLengthValidator(0)], unique=True)
    security = models.CharField(max_length=300,validators=[MinLengthValidator(0)])
    mode = models.CharField(max_length=300,validators=[MinLengthValidator(0)])
