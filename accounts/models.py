from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.core.validators import RegexValidator

from common.managers import CustomUserManager

# Create your models here.

PHONE_NUMBER_REGEX = RegexValidator(
    r"(254|0)(1|7)([0-9])([0-9])([0-9])([0-9])([0-9])([0-9])([0-9])([0-9])",
    "Phone number should be in the format 254712234345",
)


class User(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(unique=True)
    firstname = models.CharField(max_length=50)
    lastname = models.CharField(max_length=50)
    phonenumber = models.CharField(validators=[PHONE_NUMBER_REGEX], max_length=12)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=True)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []

    objects = CustomUserManager()
