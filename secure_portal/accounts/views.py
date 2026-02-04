from django.contrib.auth import authenticate, login, logout
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from .models import User
import random
from django.core.mail import send_mail
from .models import OTP
from .decorators import role_required
from .models import Offer, ActivityLog, DeletionRequest, Notification, VerificationRequest
from django.http import HttpResponse
from .crypto_utils import (
    aes_decrypt, 
    rsa_decrypt_key,
    aes_encrypt,
    rsa_encrypt_key,
    generate_and_store_rsa_keys,
    load_public_key,
    load_private_key,
    sign_data,
    verify_signature,
)

# --- Helper Function for Logging ---
def log_activity(user, action, details):
    """Creates an activity log entry."""
    ActivityLog.objects.create(actor=user, action=action, details=details)


def register(request):
    if request.method == "POST":
        username = request.POST.get("username")
        email = request.POST.get("email")
        password = request.POST.get("password")
        role = request.POST.get("role")

        if User.objects.filter(username=username).exists():
            messages.error(request, "Username already exists")
            return redirect("register")

        if User.objects.filter(email=email).exists():
            messages.error(request, "Email already exists")
            return redirect("register")

        user = User.objects.create_user(
            username=username,
            email=email,
            password=password,
            role=role
        )

        messages.success(request, "Registration successful")
        log_activity(user, "REGISTER", "User registered successfully") 
        return redirect("login")

    return render(request, "register.html")



def login_view(request):
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")

        user = authenticate(request, username=username, password=password)

        if user:
            otp_code = str(random.randint(100000, 999999))
            OTP.objects.create(user=user, otp=otp_code)

            send_mail(
                subject="Your OTP Code",
                message=f"Your OTP is {otp_code}",
                from_email="noreply@secureportal.com",
                recipient_list=[user.email],
            )

            request.session['otp_user_id'] = user.id
            return redirect("verify_otp")

        else:
            messages.error(request, "Invalid credentials")
            return redirect("login")

    return render(request, "login.html")



def dashboard(request):
    if not request.user.is_authenticated:
        return redirect("login")

    # Pass the last 5 logs for the dashboard if needed, or link to full log
    recent_activity = ActivityLog.objects.all()[:5]
    return render(request, "dashboard.html", {"recent_activity": recent_activity})


def verify_otp(request):
    if request.method == "POST":
        otp_input = request.POST.get("otp")
        user_id = request.session.get("otp_user_id")

        otp_obj = OTP.objects.filter(user_id=user_id).last()

        if otp_obj and otp_obj.otp == otp_input and otp_obj.is_valid():
            login(request, otp_obj.user)
            OTP.objects.filter(user=otp_obj.user).delete()
            log_activity(otp_obj.user, "LOGIN", "User logged in with OTP")
            return redirect("dashboard")

        messages.error(request, "Invalid or expired OTP")
        return redirect("verify_otp")

    return render(request, "verify_otp.html")

@role_required(['COMPANY'])
def upload_offer(request):
    if request.method == "POST":
        uploaded_file = request.FILES.get('offer')
        student_ids = request.POST.getlist('student_ids')

        if not uploaded_file or not student_ids:
            return render(request, "upload_offer.html", {
                "msg": "File and at least one student must be selected"
            })

        file_data = uploaded_file.read()

        generate_and_store_rsa_keys()
        public_key = load_public_key()

        encrypted_data, aes_key, iv = aes_encrypt(file_data)
        encrypted_aes_key = rsa_encrypt_key(aes_key, public_key)
        private_key = load_private_key()
        signature = sign_data(file_data, private_key)

        offer = Offer.objects.create(
            company=request.user,
            filename=uploaded_file.name,
            encrypted_file=encrypted_data,
            encrypted_aes_key=encrypted_aes_key,
            iv=iv,
            digital_signature=signature
        )


        students = User.objects.filter(id__in=student_ids, role='STUDENT')
        offer.students.set(students)
        
        log_activity(request.user, "UPLOAD", f"Uploaded offer: {offer.filename}")

        # Notify assigned students
        for student in students:
            Notification.objects.create(
                user=student,
                message=f"A new internship offer '{offer.filename}' has been assigned to you.",
                link=f"/offers/"
            )
        
        # Notify admins about new upload
        admins = User.objects.filter(role='ADMIN')
        for admin in admins:
            Notification.objects.create(
                user=admin,
                message=f"New offer '{offer.filename}' uploaded by {request.user.username} for verification.",
                link=f"/offers/"
            )

        return render(request, "upload_success.html")

    students = User.objects.filter(role='STUDENT')
    return render(request, "upload_offer.html", {"students": students})






@role_required(['ADMIN'])
def verify_offer(request, offer_id):
    offer = get_object_or_404(Offer, id=offer_id)

    # Multi-admin verification logic
    admins = User.objects.filter(role='ADMIN').exclude(id=request.user.id)
    
    if admins.exists():
        # Create a verification request instead of verifying immediately
        ver_req, created = VerificationRequest.objects.get_or_create(
            offer=offer,
            requested_by=request.user,
            is_approved=False
        )
        
        if created:
            # Notify other admins
            for admin in admins:
                Notification.objects.create(
                    user=admin,
                    message=f"Admin {request.user.username} requested to verify offer: {offer.filename}",
                    link=f"/offers/approve-verification/{ver_req.id}/"
                )
            messages.info(request, "Verification request sent to other admins for approval.")
        else:
            messages.warning(request, "A verification request for this offer is already pending.")
        return redirect('list_offers')

    # Single admin logic (immediate verification)
    private_key = load_private_key()
    aes_key = rsa_decrypt_key(offer.encrypted_aes_key, private_key)
    decrypted_data = aes_decrypt(offer.encrypted_file, aes_key, offer.iv)
    public_key = load_public_key()
    is_valid = verify_signature(decrypted_data, offer.digital_signature, public_key)

    if not is_valid:
        log_activity(request.user, "VERIFY_FAIL", f"Verification failed for: {offer.filename}")
        return render(request, "verify_result.html", {
            "success": False,
            "error_message": "Signature verification failed."
        })

    offer.is_verified = True
    offer.save()
    
    log_activity(request.user, "VERIFY_SUCCESS", f"Verified offer: {offer.filename}")
    # ... notifying company and students (already in my previous update, making sure it stays)
    Notification.objects.create(user=offer.company, message=f"Your offer '{offer.filename}' has been verified.")
    for student in offer.students.all():
        Notification.objects.create(user=student, message=f"Offer '{offer.filename}' has been verified.")

    return render(request, "verify_result.html", {"success": True})


@role_required(['ADMIN'])
def approve_verification(request, request_id):
    try:
        ver_req = VerificationRequest.objects.get(id=request_id)
    except VerificationRequest.DoesNotExist:
        messages.warning(request, "This verification request has already been processed or no longer exists.")
        return redirect('notifications')
    
    if ver_req.requested_by == request.user:
        messages.error(request, "You cannot approve your own verification request.")
        return redirect('notifications')

    if request.method == "POST":
        action = request.POST.get("action")
        offer = ver_req.offer
        
        if action == "approve":
            # Perform actual verification
            private_key = load_private_key()
            aes_key = rsa_decrypt_key(offer.encrypted_aes_key, private_key)
            decrypted_data = aes_decrypt(offer.encrypted_file, aes_key, offer.iv)
            public_key = load_public_key()
            is_valid = verify_signature(decrypted_data, offer.digital_signature, public_key)

            if is_valid:
                offer.is_verified = True
                offer.save()
                log_activity(request.user, "VERIFY_APPROVED", f"Approved verification of: {offer.filename}")
                
                # Notify requester
                Notification.objects.create(
                    user=ver_req.requested_by,
                    message=f"Your verification request for {offer.filename} was APPROVED by {request.user.username}."
                )
                # Notify company and students
                Notification.objects.create(user=offer.company, message=f"Offer '{offer.filename}' has been verified.")
                for student in offer.students.all():
                    Notification.objects.create(user=student, message=f"Offer '{offer.filename}' has been verified.")
                
                ver_req.delete()
                messages.success(request, f"Verification of '{offer.filename}' approved.")
            else:
                messages.error(request, "Verification failed during approval check.")
        
        elif action == "reject":
            log_activity(request.user, "VERIFY_REJECTED", f"Rejected verification of: {offer.filename}")
            Notification.objects.create(
                user=ver_req.requested_by,
                message=f"Your verification request for {offer.filename} was REJECTED by {request.user.username}."
            )
            ver_req.delete()
            messages.warning(request, f"Verification request for '{offer.filename}' rejected.")
            
        return redirect('notifications')

    return render(request, "approve_verification_confirm.html", {"ver_req": ver_req})


@role_required(['COMPANY', 'STUDENT', 'ADMIN'])
def view_offer(request, offer_id):
    offer = Offer.objects.get(id=offer_id)
    user = request.user

    # Authorization check
    if user.role == 'COMPANY' and offer.company != user:
        return HttpResponse("Unauthorized", status=403)

    if user.role == 'STUDENT' and user not in offer.students.all():
        return HttpResponse("Unauthorized", status=403)

    private_key = load_private_key()
    aes_key = rsa_decrypt_key(offer.encrypted_aes_key, private_key)

    decrypted_data = aes_decrypt(
        offer.encrypted_file,
        aes_key,
        offer.iv
    )
    public_key = load_public_key()
    is_valid = verify_signature(
        decrypted_data,
        offer.digital_signature,
        public_key
    )

    if not is_valid:
        print("DIGITAL SIGNATURE VERIFICATION FAILED")
        return HttpResponse(
            "⚠️ Offer integrity verification FAILED",
            status=400
        )

    print("DIGITAL SIGNATURE VERIFIED SUCCESSFULLY")

    response = HttpResponse(decrypted_data, content_type='application/pdf')
    response['Content-Disposition'] = f'inline; filename="{offer.filename}"'
    return response



@role_required(['COMPANY', 'STUDENT', 'ADMIN'])
def list_offers(request):
    user = request.user

    if user.role == 'COMPANY':
        offers = Offer.objects.filter(company=user)

    elif user.role == 'STUDENT':
        offers = Offer.objects.filter(
            students=user,
            is_verified=True
        )

    else:  # ADMIN
        offers = Offer.objects.all()

    return render(request, "offer_list.html", {"offers": offers})


def logout_view(request):
    # Log logout if user is authenticated before logging out
    if request.user.is_authenticated:
        log_activity(request.user, "LOGOUT", "User logged out")
    logout(request)
    messages.info(request, "You have been logged out successfully.")
    return redirect("login")

# --- New Views ---

@role_required(['ADMIN', 'COMPANY'])
def delete_offer(request, offer_id):
    offer = get_object_or_404(Offer, id=offer_id)

    # CRITICAL: Cannot delete offers already accepted by students
    if offer.accepted_students.exists():
        messages.error(request, "This offer has already been accepted by some student(s) and cannot be deleted.")
        return redirect('list_offers')
    
    # Check if company owns it
    if request.user.role == 'COMPANY':
        if offer.company != request.user:
            messages.error(request, "You are not authorized to delete this offer.")
            return redirect('list_offers')
        # Company can delete directly (or we can force approval for them too, but 
        # prompt specifically mentioned threat of insider attack as college admin)
        filename = offer.filename
        offer.delete()
        log_activity(request.user, "DELETE", f"Deleted offer: {filename}")
        messages.success(request, f"Offer '{filename}' has been deleted.")
        return redirect('list_offers')

    # Admin Deletion Logic (Multi-admin approval)
    admins = User.objects.filter(role='ADMIN').exclude(id=request.user.id)
    
    if admins.exists():
        # Create a deletion request instead of deleting immediately
        deletion_request, created = DeletionRequest.objects.get_or_create(
            offer=offer,
            requested_by=request.user,
            is_approved=False
        )
        
        if created:
            # Notify other admins
            for admin in admins:
                Notification.objects.create(
                    user=admin,
                    message=f"Admin {request.user.username} requested to delete offer: {offer.filename}",
                    link=f"/offers/approve-deletion/{deletion_request.id}/"
                )
            messages.info(request, "Deletion request sent to other admins for approval.")
        else:
            messages.warning(request, "A deletion request for this offer is already pending.")
    else:
        # Only one admin exists, allow immediate deletion
        filename = offer.filename
        offer.delete()
        log_activity(request.user, "DELETE", f"Deleted offer: {filename}")
        messages.success(request, f"Offer '{filename}' has been deleted (Single Admin).")
    
    return redirect('list_offers')


@role_required(['ADMIN'])
def approve_deletion(request, request_id):
    try:
        del_req = DeletionRequest.objects.get(id=request_id)
    except DeletionRequest.DoesNotExist:
        messages.warning(request, "This deletion request has already been processed or no longer exists.")
        return redirect('notifications')
    
    if del_req.requested_by == request.user:
        messages.error(request, "You cannot approve your own deletion request.")
        return redirect('notifications')

    if request.method == "POST":
        action = request.POST.get("action")
        offer_name = del_req.offer.filename
        
        if action == "approve":
            if del_req.offer.accepted_students.exists():
                messages.error(request, "This offer was accepted by a student while the request was pending. Deletion is now blocked.")
                del_req.delete()
                return redirect('notifications')

            del_req.offer.delete()
            log_activity(request.user, "DELETE_APPROVED", f"Approved deletion of: {offer_name}")
            Notification.objects.create(
                user=del_req.requested_by,
                message=f"Your deletion request for {offer_name} was APPROVED by {request.user.username}."
            )
            messages.success(request, f"Deletion of '{offer_name}' approved.")
        
        elif action == "reject":
            log_activity(request.user, "DELETE_REJECTED", f"Rejected deletion of: {offer_name}")
            Notification.objects.create(
                user=del_req.requested_by,
                message=f"Your deletion request for {offer_name} was REJECTED by {request.user.username}."
            )
            del_req.delete()
            messages.warning(request, f"Deletion request for '{offer_name}' rejected.")
            
        return redirect('notifications')

    return render(request, "approve_deletion_confirm.html", {"del_req": del_req})


@role_required(['ADMIN', 'COMPANY', 'STUDENT'])
def notifications(request):
    user_notifications = Notification.objects.filter(user=request.user)
    # Mark as read
    user_notifications.update(is_read=True)
    return render(request, "notifications.html", {"notifications": user_notifications})


@role_required(['STUDENT'])
def accept_offer(request, offer_id):
    offer = get_object_or_404(Offer, id=offer_id)
    
    if request.user not in offer.students.all():
        messages.error(request, "You do not have access to this offer.")
        return redirect('list_offers')

    # If student already accepted, just redirect (shouldn't happen with UI block)
    if request.user in offer.accepted_students.all():
        messages.info(request, "You have already accepted this offer.")
        return redirect('list_offers')

    offer.status = 'ACCEPTED'
    offer.accepted_students.add(request.user)
    offer.save()
    log_activity(request.user, "ACCEPT", f"Accepted offer: {offer.filename}")
    
    # Notify company
    Notification.objects.create(
        user=offer.company,
        message=f"Student {request.user.username} has accepted the offer: {offer.filename}",
        link=f"/offers/"
    )
    
    # Notify admins
    admins = User.objects.filter(role='ADMIN')
    for admin in admins:
        Notification.objects.create(
            user=admin,
            message=f"Offer '{offer.filename}' has been accepted by {request.user.username}.",
            link=f"/offers/"
        )

    messages.success(request, f"You have accepted the offer: {offer.filename}")
    return redirect('list_offers')

@role_required(['ADMIN', 'COMPANY', 'STUDENT'])
def activity_log(request):
    logs = ActivityLog.objects.all()
    return render(request, "activity_log.html", {"logs": logs})
