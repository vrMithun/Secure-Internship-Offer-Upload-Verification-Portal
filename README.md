# 🔐 Secure Internship Offer Upload & Verification Portal

A robust, role-based platform designed to combat internship fraud. This portal ensures the **authenticity, confidentiality, and integrity** of offer letters through advanced cryptography, multi-admin oversight, and a "First-Come, First-Served" multi-student acceptance model.

---

## 📌 Project Context
Developed for **23CSE313 – Foundations of Cyber Security**, this project demonstrates how industrial-grade security principles can solve real-world problems like fake internship documents.

## 🌟 Key Features

### 1. Hybrid Encryption (Digital Envelope)
The system uses a **Hybrid Cryptography** model:
- **AES-256-CFB**: Used for fast symmetric encryption of the document itself.
- **RSA-OAEP (2048-bit)**: Used for asymmetric "key wrapping." The random AES key for each document is encrypted using the Portal's Master Public Key.
- **Why?**: This combines the speed of symmetric encryption with the secure key management of asymmetric encryption.

### 2. Multi-Admin Approval Workflow
To prevent **Insider Threats**, critical actions are never immediate:
- **Deletion Requests**: When an admin wants to delete a file, it must be approved by *another* admin.
- **Verification Requests**: Offer verification follows the same "Four-Eyes Principle," requiring a second admin's confirmation.
- **Explicit Confirmation**: Approvals require a manual "Accept/Reject" choice, preventing accidental or automated clicks from notifications.

### 3. Smart Acceptance Model
- **Broadcast Offers**: Companies can assign one offer to multiple students.
- **Independent Acceptance**: Unlike the "First-Come" model, this system allows **multiple students** to accept the same offer independently.
- **Transparent Status**: The Offer List shows the names of all students who have accepted, and for pending offers, it shows who it is available for.

### 4. Zero-Trust Access Control
- **Students**: Can only view and accept offers specifically assigned to them.
- **Companies**: Can only manage offers they uploaded.
- **Admins**: Can perform verification and deletion through the multi-admin authorization flow.

---

## 🛡️ Security Implementation (Rubric Map)

### 1️⃣ Authentication (OTP Secured)
- **NIST-Compliant**: Passwords undergo salted hashing.
- **Email MFA**: A 6-digit OTP is required for every login, sent to the user's console/email.

### 2️⃣ Authorization (Access Control Matrix)
- Permissions are enforced via custom Django decorators and a dynamic `RolePermission` model.
- **Rule**: Deletion is strictly blocked once at least one student has accepted the offer.

### 3️⃣ Encryption Trace (Evaluation View)
The Admin panel includes a **Cryptographic Evaluation Trace** for every document:
- **Phase 1**: Shows AES details (IV, Ciphertext snippet).
- **Phase 2**: Shows RSA Key Wrapping (Digital Envelope).
- **Phase 3**: Simulates decryption to prove the "System Private Key" is required to read the data.

---

## 🚀 Quick Start Guide

### 1. Prerequisites
- Python 3.10+
- Virtual Environment

### 2. Installation
```bash
# Clone the repository
git clone <repo-url>
cd Secure-Internship-Offer-Upload-Verification-Portal

# Create and activate venv
python -m venv venv
source venv/bin/activate  # venv\Scripts\activate on Windows

# Install dependencies
pip install django cryptography
```

### 3. Database & System Setup
```bash
# Apply migrations
python manage.py migrate

# Initialize the ACL (Access Control List)
python populate_acl.py

# Create a Superuser
python manage.py createsuperuser
```

### 4. Run the Portal
```bash
python manage.py runserver
```
> **Note**: OTPs will be printed in the terminal for development.

---

## 📂 Project Structure
- `accounts/models.py`: Core models for Users, Offers, Requests, and Notifications.
- `accounts/crypto_utils.py`: The security engine (AES/RSA/Signatures).
- `accounts/views.py`: Business logic including the Multi-Admin approval flow.
- `templates/`: Modern, glassmorphism-inspired UI components.

---

## 📚 Course Information
**Course:** 23CSE313 – Foundations of Cyber Security  
**Institution:** Amrita Vishwa Vidyapeetham  
**Department:** Computer Science and Engineering
