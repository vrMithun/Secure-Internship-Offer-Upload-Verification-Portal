# 🔐 Secure Internship Offer Upload & Verification Portal

A secure, role-based web application designed to **prevent fake internship offer letters** by ensuring **authentication, authorization, encryption, hashing, digital signatures, and secure verification**.

This project is developed as part of **23CSE313 – Foundations of Cyber Security Lab Evaluation** at  
**Amrita Vishwa Vidyapeetham – Amrita School of Computing**.

---

## 📌 Problem Statement

Fake internship offer letters are increasingly used to scam students.  
There is no centralized and secure mechanism to:

- Upload internship offers securely
- Verify authenticity and integrity of offers
- Prevent unauthorized access or tampering
- Allow third-party verification without exposing sensitive data

---

## 🎯 Solution Overview

The **Secure Internship Offer Upload & Verification Portal** provides:

- Secure registration and login using **NIST-compliant authentication**
- Role-based access control for **Students, Companies, and University Admins**
- **Encrypted storage** of offer letters
- **Digital signatures** for authenticity and non-repudiation
- **QR / encoded verification** for third-party validation

---

## 👥 User Roles

### 1. Student
- Register and login securely
- View only their own internship offers
- Verify offer authenticity

### 2. Company (HR)
- Upload internship offer letters
- Digitally sign offers before submission
- View uploaded offers

### 3. University Admin
- Verify authenticity of uploaded offers
- Validate digital signatures
- Prevent fraudulent documents

---

## 🔐 Security Architecture

The application integrates **multiple security layers**:

| Layer | Purpose |
|------|--------|
| Authentication | Verify user identity |
| Authorization | Control access to resources |
| Encryption | Protect data confidentiality |
| Hashing | Secure credential storage |
| Digital Signature | Ensure integrity & authenticity |
| Encoding | Safe data transmission |

---

## 🛡️ Security Features (Mapped to Evaluation Rubric)

### 1️⃣ Authentication (3 Marks)

#### Single-Factor Authentication
- Username (Email) + Password
- Passwords stored using **salted hashing** (bcrypt / PBKDF2 / Argon2)

#### Multi-Factor Authentication
- Password + **Email-based OTP**
- Time-bound OTP validation
- Complies with **NIST SP 800-63-2 E-Authentication Model**

---

### 2️⃣ Authorization – Access Control (3 Marks)

**Access Control Model Used:** Access Control Matrix

| Subject / Object | Upload Offer | View Offer | Verify Offer |
|------------------|-------------|------------|-------------|
| Student | ❌ | ✅ (Own only) | ❌ |
| Company HR | ✅ | ✅ (Uploaded) | ❌ |
| University Admin | ❌ | ✅ (All) | ✅ |

- Permissions enforced programmatically using role-based middleware
- Unauthorized actions are blocked at backend level

---

### 3️⃣ Encryption (3 Marks)

#### Key Exchange Mechanism
- **Hybrid Cryptography**
  - AES for file encryption
  - RSA for secure AES key exchange

#### Encryption & Decryption
- Internship offer letters encrypted **before database storage**
- Decryption allowed only after authentication and authorization

---

### 4️⃣ Hashing & Digital Signature (3 Marks)

#### Hashing with Salt
- Passwords hashed using secure algorithms with salt
- Protects against rainbow table and brute-force attacks

#### Digital Signature using Hash
- Offer letter hash generated using **SHA-256**
- Hash signed using **company’s private key**
- Verification using corresponding public key ensures:
  - Integrity
  - Authenticity
  - Non-repudiation

---

### 5️⃣ Encoding Techniques (1 Mark)

- **Base64 Encoding**
  - Used for encrypted data and digital signatures
  - Enables safe transmission via APIs and JSON payloads

---

## ⚠️ Security Risks & Mitigations

| Threat | Mitigation |
|------|-----------|
| Password brute-force | Rate limiting + strong hashing |
| Unauthorized access | Role-based access control |
| Data tampering | Digital signatures |
| Replay attacks | OTP expiration |
| Data leakage | AES encryption at rest |

---

## 🧪 Technologies Used

- Backend: Secure API-based architecture
- Cryptography: AES, RSA, SHA-256
- Authentication: Password + OTP
- Encoding: Base64
- Database: Encrypted document storage

---

## **Why this project?**  
> Internship fraud is a real-world problem affecting students. This project demonstrates how foundational cybersecurity concepts can be applied cohesively to solve a practical security issue.

## **What makes it secure?**  
> Security is enforced at every layer — identity verification, access control, encryption, hashing, and integrity verification.

---

## ✅ Conclusion

This project successfully integrates all core cybersecurity concepts required by the syllabus into a **realistic, original, and secure application**, making it suitable for both **academic evaluation and real-world deployment**.

---

## 📚 Course Information

**Course Code:** 23CSE313  
**Course Name:** Foundations of Cyber Security  
**Institution:** Amrita Vishwa Vidyapeetham  
**Department:** Computer Science and Engineering

---

