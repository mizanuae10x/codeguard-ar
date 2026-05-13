---
description: إرشادات تشفير إضافية
languages:
- c
- go
- java
- javascript
- kotlin
- matlab
- php
- python
- ruby
- swift
- typescript
- xml
- yaml
tags:
- data-security
- secrets
- cryptography
- uae
alwaysApply: false
---

# التشفير الإضافي و TLS — Additional Cryptography & TLS

## نظرة عامة — Overview

طبق التشفير الحديث والمُدقَّق للبيانات في حالة السكون وأثناء النقل. أدر المفاتيح بأمان، اضبط TLS بشكل صحيح، انشر HSTS، وفكر في التثبيت فقط عندما يكون مناسباً.

Apply modern, vetted cryptography for data at rest and in transit. Manage keys safely, configure TLS correctly, deploy HSTS, and consider pinning only when appropriate.

---

## الخوارزميات والأنماط — Algorithms and Modes

**العربية:**
- المتماثل: AES-GCM أو ChaCha20-Poly1305 مفضل. تجنب ECB. CBC/CTR فقط مع encrypt-then-MAC.
- غير المتماثل: RSA ≥2048 أو ECC الحديث (Curve25519/Ed25519). استخدم OAEP لتشفير RSA.
- التجزئة: SHA-256+ للنزاهة؛ تجنب MD5/SHA-1.
- RNG: استخدم CSPRNG المناسب للمنصة. لا تستخدم أبداً RNGs غير تشفيرية.

**English:**
- Symmetric: AES-GCM or ChaCha20-Poly1305 preferred. Avoid ECB. CBC/CTR only with encrypt-then-MAC.
- Asymmetric: RSA ≥2048 or modern ECC (Curve25519/Ed25519). Use OAEP for RSA encryption.
- Hashing: SHA-256+ for integrity; avoid MD5/SHA-1.
- RNG: Use CSPRNG appropriate to platform. Never use non-crypto RNGs.

```python
# Python Modern Cryptography
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import hashes
import os

class UAEModernCrypto:
    """
    UAE-compliant modern cryptography
    """
    
    @staticmethod
    def encrypt_aes_gcm(plaintext: bytes, key: bytes = None) -> dict:
        """Encrypt with AES-256-GCM"""
        if key is None:
            key = AESGCM.generate_key(bit_length=256)
        
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)  # 96-bit nonce
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        
        return {
            'ciphertext': ciphertext,
            'nonce': nonce,
            'key': key
        }
    
    @staticmethod
    def encrypt_chacha20(plaintext: bytes, key: bytes = None) -> dict:
        """Encrypt with ChaCha20-Poly1305"""
        if key is None:
            key = os.urandom(32)
        
        chacha = ChaCha20Poly1305(key)
        nonce = os.urandom(12)
        ciphertext = chacha.encrypt(nonce, plaintext, None)
        
        return {
            'ciphertext': ciphertext,
            'nonce': nonce,
            'key': key
        }
    
    @staticmethod
    def generate_rsa_keypair(key_size: int = 4096):
        """Generate RSA key pair (minimum 2048, recommended 4096)"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size
        )
        return private_key, private_key.public_key()
    
    @staticmethod
    def generate_ecc_keypair(curve=ec.SECP256R1()):
        """Generate ECC key pair"""
        private_key = ec.generate_private_key(curve)
        return private_key, private_key.public_key()
    
    @staticmethod
    def hash_sha256(data: bytes) -> bytes:
        """SHA-256 hash"""
        digest = hashes.Hash(hashes.SHA256())
        digest.update(data)
        return digest.finalize()
    
    @staticmethod
    def secure_random(length: int) -> bytes:
        """Cryptographically secure random bytes"""
        return os.urandom(length)
```

---

## إدارة المفاتيح — Key Management

**العربية:**
- أنشئ المفاتيح داخل وحدات مُتحقَّقة (HSM/KMS) وليس من كلمات مرور أو مدخلات متوقعة.
- افصل المفاتيح حسب الغرض (تشفير، توقيع، تغليف). دوّر عند الاختراق أو فترة التشفير أو السياسة.
- خزن المفاتيح في KMS/HSM أو خزنة؛ لا تُضمن أبداً؛ تجنب متغيرات البيئة الصريحة.

**English:**
- Generate keys within validated modules (HSM/KMS) and never from passwords or predictable inputs.
- Separate keys by purpose (encryption, signing, wrapping). Rotate on compromise, cryptoperiod, or policy.
- Store keys in KMS/HSM or vault; never hardcode; avoid plain env vars. Use KEK to wrap DEKs; store separately.

```python
# Python Key Management with AWS KMS
import boto3
from cryptography.fernet import Fernet

class UAEKeyManager:
    """
    UAE-compliant key management
    """
    
    def __init__(self, region='me-central-1'):
        self.kms_client = boto3.client('kms', region_name=region)
    
    def create_data_key(self, key_id: str) -> dict:
        """Generate data key encrypted with KMS"""
        response = self.kms_client.generate_data_key(
            KeyId=key_id,
            KeySpec='AES_256'
        )
        
        return {
            'plaintext': response['Plaintext'],  # Use for encryption, then discard
            'ciphertext': response['CiphertextBlob']  # Store this
        }
    
    def decrypt_data_key(self, encrypted_key: bytes) -> bytes:
        """Decrypt data key with KMS"""
        response = self.kms_client.decrypt(
            CiphertextBlob=encrypted_key
        )
        return response['Plaintext']
    
    def rotate_key(self, key_id: str) -> str:
        """Rotate KMS key"""
        response = self.kms_client.enable_key_rotation(
            KeyId=key_id
        )
        return key_id
```

---

## البيانات في حالة السكون — Data at Rest

**العربية:**
- شفر البيانات الحساسة؛ قلل من الأسرار المخزنة؛ استبدل بالرموز حيثما أمكن.
- استخدم التشفير المصادق؛ أدر nonces/IVs بشكل صحيح؛ حافظ على أملاح فريدة لكل عنصر.
- حماية النسخ الاحتياطية: شفر، قصر الوصول، اختبر الاستعادة، أدر الاحتفاظ.

**English:**
- Encrypt sensitive data; minimize stored secrets; tokenize where possible.
- Use authenticated encryption; manage nonces/IVs properly; keep salts unique per item.
- Protect backups: encrypt, restrict access, test restores, manage retention.

```python
# Python Data at Rest Encryption
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import hashlib
import os

class UAEDataAtRest:
    """
    Encrypt data at rest for UAE compliance
    """
    
    @staticmethod
    def encrypt_sensitive_data(data: bytes, key: bytes) -> dict:
        """Encrypt sensitive data with unique nonce"""
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, data, None)
        
        return {
            'ciphertext': ciphertext,
            'nonce': nonce
        }
    
    @staticmethod
    def derive_key_from_password(password: str, salt: bytes = None) -> tuple:
        """Derive encryption key from password (for user data)"""
        if salt is None:
            salt = os.urandom(16)
        
        # Use PBKDF2 with high iteration count
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
        from cryptography.hazmat.primitives import hashes
        
        kdf = PBKDF2(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=600000  # NIST recommendation
        )
        key = kdf.derive(password.encode())
        
        return key, salt
```

---

## تكوين TLS — TLS Configuration

**العربية:**
- البروتوكولات: TLS 1.3 مفضل؛ اسمح بـ TLS 1.2 فقط للتوافقية القديمة؛ عطل TLS 1.0/1.1 وSSL.
- التشفيرات: فضّل مجموعات AEAD؛ عطل NULL/EXPORT/anon.
- مجموعات تبادل المفاتيح: فضّل x25519/secp256r1.
- الشهادات: مفاتيح 2048-bit+، SHA-256، CN/SAN صحيحة.

**English:**
- Protocols: TLS 1.3 preferred; allow TLS 1.2 only for legacy compatibility; disable TLS 1.0/1.1 and SSL.
- Ciphers: prefer AEAD suites; disable NULL/EXPORT/anon.
- Key exchange groups: prefer x25519/secp256r1.
- Certificates: 2048-bit+ keys, SHA-256, correct CN/SAN.

```python
# Python TLS Configuration (for servers)
import ssl

class UAETLSConfig:
    """
    UAE-compliant TLS configuration
    """
    
    @staticmethod
    def create_secure_context() -> ssl.SSLContext:
        """Create secure SSL context"""
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        
        # Minimum TLS 1.2
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        
        # Prefer TLS 1.3
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        
        # Strong cipher suites
        context.set_ciphers(
            'ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS'
        )
        
        # Disable compression
        context.options |= ssl.OP_NO_COMPRESSION
        
        # Enable OCSP stapling
        context.ocsp_response_cb = lambda conn, ocsp_response, ocsp_response_context: True
        
        return context
```

---

## HSTS — HTTP Strict Transport Security

**العربية:**
- أرسل Strict-Transport-Security فقط عبر HTTPS.
- مرحلة الاختبار: max-age قصير (مثلاً، 86400) مع includeSubDomains.
- الإنتاج: max-age ≥1 سنة؛ includeSubDomains عندما يكون آمناً.
- preload اختياري بمجرد النضج؛ افهم الد permanence وتأثير النطاق الفرعي.

**English:**
- Send Strict-Transport-Security only over HTTPS.
- Test: short max-age (e.g., 86400) with includeSubDomains.
- Prod: ≥1 year max-age; includeSubDomains when safe.
- Optional preload once mature; understand permanence and subdomain impact.

```python
# Python HSTS Header
from flask import Flask, Response

app = Flask(__name__)

@app.after_request
def set_hsts(response: Response):
    """Set HSTS header"""
    # Production: 1 year with preload
    response.headers['Strict-Transport-Security'] = (
        'max-age=31536000; '
        'includeSubDomains; '
        'preload'
    )
    return response
```

---

## التثبيت — Pinning

**العربية:**
- تجنب HPKP في المتصفح. فكر في التثبيت فقط للعملاء المُتحكم بهم (مثلاً، الجوال) وعندما تملك كلا الطرفين.
- فضّل تثبيت SPKI مع دبابيس احتياطية؛ خطط لقنوات تحديث آمنة؛ لا تسمح أبداً بتجاوز المستخدم.

**English:**
- Avoid browser HPKP. Consider pinning only for controlled clients (e.g., mobile) and when you own both ends.
- Prefer SPKI pinning with backup pins; plan secure update channels; never allow user bypass.

---

## قائمة التحقق — Implementation Checklist

- [ ] AEAD في كل مكان؛ مكتبات مُدقَّقة فقط؛ لا تشفير مخصص.
- [ ] المفاتيح مُنشأة ومخزنة في KMS/HSM؛ ذات نطاق غرض؛ التدوير موثق.
- [ ] TLS 1.3/1.2 مع تشفيرات قوية؛ الضغط معطل؛ OCSP stapling مفعل.
- [ ] HSTS منشور حسب خطة مرحلية؛ المحتوى المختلط مُزال.
- [ ] التثبيت مستخدم فقط حيثما يكون مبرراً، مع دبابيس احتياطية ومسار تحديث.

---

## خطة الاختبار — Test Plan

- [ ] فحوصات تكوين آلية (SSL Labs، testssl.sh) للبروتوكول/التشفير/HSTS.
- [ ] مراجعة الكود لسوء استخدام واجهة برمجة التشفير؛ اختبارات لتدوير المفاتيح والنسخ الاحتياطي/الاستعادة.
- [ ] محاكاة التثبيت للتدوير/الفشل إذا كان منشوراً.

---

## مراجع — References

- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [OWASP Transport Layer Protection Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)
- [NIST SP 800-57 - Key Management](https://csrc.nist.gov/publications/detail/sp/800-57/final)
- [Mozilla SSL Configuration Generator](https://ssl-config.mozilla.org/)
- [UAE Information Assurance Framework](https://www.tra.gov.ae/)
