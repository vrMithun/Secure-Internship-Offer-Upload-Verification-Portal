from django.contrib.auth.models import AbstractUser
from django.db import models

class User(AbstractUser):
    ROLE_CHOICES = [
        ('STUDENT', 'Student'),
        ('COMPANY', 'Company HR'),
        ('ADMIN', 'University Admin'),
    ]

    role = models.CharField(
        max_length=20,
        choices=ROLE_CHOICES
    )

    def __str__(self):
        return f"{self.username} ({self.role})"


from django.utils import timezone

class OTP(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    otp = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)

    def is_valid(self):
        expiry_time = self.created_at + timezone.timedelta(minutes=5)
        return timezone.now() <= expiry_time


class Offer(models.Model):
    is_verified = models.BooleanField(default=False)

    digital_signature = models.BinaryField(null=True, blank=True)
    company = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="uploaded_offers"
    )

    students = models.ManyToManyField(
        User,
        related_name="assigned_offers",
        blank=True
    )

    filename = models.CharField(max_length=255)

    encrypted_file = models.BinaryField()
    encrypted_aes_key = models.BinaryField()
    iv = models.BinaryField()

    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.filename} (by {self.company.username})"


