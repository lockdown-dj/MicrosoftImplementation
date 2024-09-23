from django.db import models
from django.contrib.auth.models import BaseUserManager
from django.utils.translation import gettext_lazy as _
import uuid
from django.contrib.auth.models import AbstractUser

class UserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError(_('The Email field must be set'))
        email = self.normalize_email(email)
        extra_fields.setdefault('is_active', True)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError(_('Superuser must have is_staff=True.'))
        if extra_fields.get('is_superuser') is not True:
            raise ValueError(_('Superuser must have is_superuser=True.'))

        return self.create_user(email, password, **extra_fields)
    
# Create your models here.
class User(AbstractUser):
    USER_MODE_CHOICES = (
        ('normal', 'Normal'),
        ('receiver', 'Receiver'),
        ('observer', 'Observer'),
    )
    IMPORTED_FROM_CHOICES = (
        ('manual', 'manual'),
        ('azure', 'Azure'),
        ('google', 'Google'),
        ('servicenow', 'ServiceNow'),
    )
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    username = None
    first_name = None
    last_name = None
    full_name = models.CharField(max_length=155)
    email = models.EmailField(unique=True)
    user_mode = models.CharField(max_length=20, default='normal', null=True)
    monthly_refresh_points = models.PositiveIntegerField(default=0)
    points_available = models.IntegerField(default=200)
    points_received = models.IntegerField(default=0)
    points_redeemed = models.IntegerField(default=0)
    employee_id = models.CharField(max_length=155)
    mode = models.CharField(
        choices=USER_MODE_CHOICES, 
        max_length=55, 
        default='receiver'
    )
    # TODO: Need to send email to user after first time activation
    imported_from = models.CharField(
        choices=IMPORTED_FROM_CHOICES,
        max_length=55,
        default='manual'
    )
    email_sent = models.BooleanField(default=False)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['full_name']

    objects = UserManager()

    def __str__(self):
        return self.email
