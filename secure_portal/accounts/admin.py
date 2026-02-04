from django.contrib import admin
from .models import User, Offer, OTP, ActivityLog, DeletionRequest, VerificationRequest, Notification, RolePermission

class OfferAdmin(admin.ModelAdmin):
    list_display = ('filename', 'company', 'is_verified', 'accepted_count', 'uploaded_at')
    readonly_fields = ('company', 'students', 'accepted_students', 'filename', 'uploaded_at', 'crypto_details')
    exclude = ('encrypted_file', 'encrypted_aes_key', 'iv', 'digital_signature', 'accepted_by')

    def accepted_count(self, obj):
        return obj.accepted_students.count()
    accepted_count.short_description = "Acceptances"

    def crypto_details(self, obj):
        import binascii
        from .crypto_utils import rsa_decrypt_key, load_private_key
        
        try:
            private_key = load_private_key()
            decrypted_aes_key = rsa_decrypt_key(obj.encrypted_aes_key, private_key)
            decrypted_key_hex = binascii.hexlify(decrypted_aes_key).decode()
            decryption_status = "✅ Successfully Unwrapped"
        except Exception as e:
            decrypted_key_hex = "N/A"
            decryption_status = f"❌ Error (Private Key Missing): {str(e)}"

        details = f"""
        <div style="background: #111827; color: #e5e7eb; padding: 20px; border-radius: 12px; border: 1px solid #374151; font-family: 'Inter', system-ui, sans-serif; line-height: 1.6;">
            <h3 style="color: #60a5fa; border-bottom: 2px solid #3b82f6; padding-bottom: 10px; margin-top: 0; display: flex; align-items: center; gap: 10px;">
                🔐 Cryptographic Evaluation Trace
            </h3>
            
            <p style="font-size: 0.9em; color: #9ca3af; margin-bottom: 20px;">
                This trace demonstrates the <b>Hybrid Encryption</b> (Digital Envelope) process used to secure this document.
            </p>

            <div style="margin-bottom: 20px; background: #1f2937; padding: 15px; border-radius: 8px;">
                <strong style="color: #fbbf24; display: block; margin-bottom: 5px;">PHASE 1: SYMMETRIC ENCRYPTION (Data Layer)</strong>
                The file was encrypted using AES-256-CFB. This is fast and secure for large files.
                <div style="margin-top: 8px; font-family: monospace; font-size: 0.85em;">
                    <span style="color: #34d399;">● IV:</span> {binascii.hexlify(obj.iv).decode()}<br>
                    <span style="color: #34d399;">● File Ciphertext:</span> {binascii.hexlify(obj.encrypted_file[:32]).decode()}...
                </div>
            </div>

            <div style="margin-bottom: 20px; background: #1f2937; padding: 15px; border-radius: 8px;">
                <strong style="color: #fbbf24; display: block; margin-bottom: 5px;">PHASE 2: ASYMMETRIC WRAPPING (Key Layer)</strong>
                The AES key was "wrapped" using the <b>Portal's Master RSA Public Key</b>.
                <div style="margin-top: 8px; font-family: monospace; font-size: 0.85em;">
                    <span style="color: #60a5fa;">● Wrapped AES Key (In DB):</span> {binascii.hexlify(obj.encrypted_aes_key[:32]).decode()}...<br>
                    <span style="color: #60a5fa;">● Method:</span> RSA-OAEP (SHA-256)
                </div>
            </div>

            <div style="margin-bottom: 20px; background: #1f2937; padding: 15px; border-radius: 8px;">
                <strong style="color: #fbbf24; display: block; margin-bottom: 5px;">PHASE 3: DECRYPTION TRACE (Evaluation Only)</strong>
                Simulating the process an Admin or Student triggers when viewing the file.
                <div style="margin-top: 8px; font-family: monospace; font-size: 0.85em;">
                    <span style="color: #f87171;">● Decryption Status:</span> {decryption_status}<br>
                    <span style="color: #f87171;">● Unwrapped AES Key:</span> {decrypted_key_hex}
                </div>
                <p style="font-size: 0.8em; color: #9ca3af; margin-top: 5px; font-style: italic;">
                    Note: The unwrapped key is shown here for evaluation tracing purposes only.
                </p>
            </div>

            <div style="background: rgba(59, 130, 246, 0.1); padding: 15px; border-radius: 8px; border-left: 4px solid #3b82f6;">
                <strong style="color: #60a5fa;">SECURITY PROOF:</strong><br>
                Because the AES key is encrypted with the <b>Portal Private Key</b>, multi-admin access is possible because the server manages the key as a Trusted Entity. Even if the database is leaked, the "Wrapped AES Key" is useless without the server's private key.
            </div>
        </div>
        """
        from django.utils.safestring import mark_safe
        return mark_safe(details)
    
    crypto_details.short_description = "Security & Encryption Process"

class RolePermissionAdmin(admin.ModelAdmin):
    list_display = ('role', 'permission_name', 'description')
    list_filter = ('role',)
    search_fields = ('permission_name',)

admin.site.register(User)
admin.site.register(Offer, OfferAdmin)
admin.site.register(OTP)
admin.site.register(ActivityLog)
admin.site.register(DeletionRequest)
admin.site.register(VerificationRequest)
admin.site.register(Notification)
admin.site.register(RolePermission, RolePermissionAdmin)