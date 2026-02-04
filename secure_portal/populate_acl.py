import os
import django

# Set up Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'secure_portal.settings')
django.setup()

from accounts.models import RolePermission

def populate_permissions():
    permissions = [
        # ADMIN
        ('ADMIN', 'verify_offer', 'Can verify the authenticity and integrity of uploaded offers.'),
        ('ADMIN', 'delete_offer', 'Can initiate a deletion request for any offer.'),
        ('ADMIN', 'approve_deletion', 'Can approve deletion requests from other admins.'),
        ('ADMIN', 'view_activity_log', 'Can view the audit trail of all system activities.'),
        
        # COMPANY
        ('COMPANY', 'upload_offer', 'Can securely sign and upload new internship offers.'),
        ('COMPANY', 'delete_own_offer', 'Can delete offers that they uploaded.'),
        
        # STUDENT
        ('STUDENT', 'view_offer', 'Can securely view and download assigned offers.'),
        ('STUDENT', 'accept_offer', 'Can formally accept a verified offer.'),
    ]

    for role, name, desc in permissions:
        obj, created = RolePermission.objects.get_or_create(
            role=role,
            permission_name=name,
            defaults={'description': desc}
        )
        if created:
            print(f"Created permission: {role} - {name}")
        else:
            print(f"Permission already exists: {role} - {name}")

if __name__ == "__main__":
    populate_permissions()
