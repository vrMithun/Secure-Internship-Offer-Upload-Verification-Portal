from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone

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


class OTP(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    otp = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)

    def is_valid(self):
        expiry_time = self.created_at + timezone.timedelta(minutes=5)
        return timezone.now() <= expiry_time


class Offer(models.Model):
    STATUS_CHOICES = [
        ('PENDING', 'Pending Action'),
        ('ACCEPTED', 'Accepted by Student'),
        ('REJECTED', 'Rejected'),
    ]

    is_verified = models.BooleanField(default=False)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='PENDING')

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

    accepted_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="accepted_offers_legacy"
    )

    accepted_students = models.ManyToManyField(
        User,
        related_name="accepted_offers_set",
        blank=True
    )

    filename = models.CharField(max_length=255)

    encrypted_file = models.BinaryField()
    encrypted_aes_key = models.BinaryField()
    iv = models.BinaryField()

    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.filename} (by {self.company.username})"


class ActivityLog(models.Model):
    actor = models.ForeignKey(User, on_delete=models.CASCADE, related_name='activities')
    action = models.CharField(max_length=50) # e.g., "UPLOAD", "VERIFY", "DELETE", "ACCEPT"
    details = models.CharField(max_length=255) # e.g., "Uploaded offer letter.pdf"
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-timestamp']


class DeletionRequest(models.Model):
    offer = models.ForeignKey(Offer, on_delete=models.CASCADE)
    requested_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='deletion_requests_made')
    is_approved = models.BooleanField(default=False)
    approved_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='deletion_requests_approved')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Deletion request for {self.offer.filename} by {self.requested_by.username}"


class VerificationRequest(models.Model):
    offer = models.ForeignKey(Offer, on_delete=models.CASCADE)
    requested_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='verification_requests_made')
    is_approved = models.BooleanField(default=False)
    approved_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='verification_requests_approved')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Verification request for {self.offer.filename} by {self.requested_by.username}"


class Notification(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='notifications')
    message = models.TextField()
    link = models.CharField(max_length=255, null=True, blank=True)
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"Notification for {self.user.username}: {self.message[:20]}..."


class RolePermission(models.Model):
    role = models.CharField(max_length=20, choices=User.ROLE_CHOICES)
    permission_name = models.CharField(max_length=100)
    description = models.TextField(blank=True)

    def __str__(self):
        return f"{self.role} - {self.permission_name}"
