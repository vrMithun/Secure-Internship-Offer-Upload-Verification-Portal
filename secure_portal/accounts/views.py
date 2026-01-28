from django.contrib.auth import authenticate, login
from django.shortcuts import render, redirect
from django.contrib import messages
from .models import User
import random
from django.core.mail import send_mail
from .models import OTP
from .decorators import role_required
from .models import Offer
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

    return render(request, "dashboard.html")


def verify_otp(request):
    if request.method == "POST":
        otp_input = request.POST.get("otp")
        user_id = request.session.get("otp_user_id")

        otp_obj = OTP.objects.filter(user_id=user_id).last()

        if otp_obj and otp_obj.otp == otp_input and otp_obj.is_valid():
            login(request, otp_obj.user)
            OTP.objects.filter(user=otp_obj.user).delete()
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

        return render(request, "upload_offer.html", {
            "msg": "Offer uploaded and assigned successfully"
        })

    students = User.objects.filter(role='STUDENT')
    return render(request, "upload_offer.html", {"students": students})






@role_required(['ADMIN'])
def verify_offer(request, offer_id):
    offer = Offer.objects.get(id=offer_id)

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
        return HttpResponse(
            "❌ Verification failed: Signature invalid",
            status=400
        )

    offer.is_verified = True
    offer.save()

    return HttpResponse("✅ Offer verified and released to students")


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


