---
description: الخصوصية وحماية البيانات (التصغير، التصنيف، التشفير، الحقوق، الشفافية)
languages:
- javascript
- matlab
- yaml
- python
- java
tags:
- privacy
- data-protection
- uae
- gdpr
- pdpl
alwaysApply: false
---

# الخصوصية وحماية البيانات — Privacy & Data Protection

## نظرة عامة — Overview

نفذ تشفيراً قوياً، وفرض HTTPS مع HSTS، وفعّل تثبيت الشهادات، وقدم ميزات خصوصية المستخدم لحماية البيانات والخصوصية.

Implement strong cryptography, enforce HTTPS with HSTS, enable certificate pinning, and provide user privacy features to protect data and anonymity.

---

## التشفير القوي — Strong Cryptography

**العربية:**
- استخدم خوارزميات تشفير قوية ومحدثة للبيانات في النقل والسكون
- تجزئة كلمات المرور بأمان باستخدام مكتبات معتمدة
- Argon2id كخيار مفضل لتخزين كلمات المرور
- AES-256-GCM للتشفير المتماثل
- RSA-4096 أو ECC P-384 للتشفير غير المتماثل

**English:**
- Use strong, up-to-date cryptographic algorithms for data in transit and at rest
- Securely hash passwords with established libraries
- Argon2id preferred for password storage
- AES-256-GCM for symmetric encryption
- RSA-4096 or ECC P-384 for asymmetric encryption

```python
# Python Data Encryption for UAE
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import base64

class UAEDataEncryption:
    """
    UAE-compliant data encryption service
    """
    
    def __init__(self, master_key: bytes = None):
        """Initialize with master key from secure storage"""
        if master_key is None:
            master_key = os.urandom(32)
        self.master_key = master_key
    
    def encrypt_sensitive_data(self, data: str, context: str = None) -> dict:
        """
        Encrypt sensitive data with AEAD
        """
        # Generate random nonce
        nonce = os.urandom(12)
        
        # Create AES-GCM cipher
        aesgcm = AESGCM(self.master_key)
        
        # Associated data for context binding
        associated_data = context.encode() if context else b''
        
        # Encrypt
        ciphertext = aesgcm.encrypt(
            nonce,
            data.encode('utf-8'),
            associated_data
        )
        
        return {
            'ciphertext': base64.b64encode(ciphertext).decode('ascii'),
            'nonce': base64.b64encode(nonce).decode('ascii'),
            'context': context,
            'algorithm': 'AES-256-GCM',
        }
    
    def decrypt_sensitive_data(self, encrypted_data: dict) -> str:
        """
        Decrypt sensitive data
        """
        ciphertext = base64.b64decode(encrypted_data['ciphertext'])
        nonce = base64.b64decode(encrypted_data['nonce'])
        context = encrypted_data.get('context', '')
        associated_data = context.encode() if context else b''
        
        aesgcm = AESGCM(self.master_key)
        
        plaintext = aesgcm.decrypt(
            nonce,
            ciphertext,
            associated_data
        )
        
        return plaintext.decode('utf-8')
    
    def hash_pii(self, pii_value: str) -> str:
        """
        Hash PII for pseudonymization
        """
        import hashlib
        import hmac
        
        # Use HMAC with secret key for one-way hashing
        return hmac.new(
            self.master_key,
            pii_value.encode(),
            hashlib.sha256
        ).hexdigest()

# Usage example
encryption_service = UAEDataEncryption()

# Encrypt Emirates ID
encrypted = encryption_service.encrypt_sensitive_data(
    data="784-1234-5678901-2",
    context="citizen_record"
)

# Hash for pseudonymization
hashed_id = encryption_service.hash_pii("784-1234-5678901-2")
```

---

## تصنيف البيانات — Data Classification

**العربية:**
- صنف جميع البيانات حسب الحساسية
- طبق ضوابط مختلفة لكل فئة
- وثّق تصنيف البيانات
- راجع التصنيف بانتظام

**English:**
- Classify all data by sensitivity
- Apply different controls per classification
- Document data classification
- Review classification regularly

| الفئة | الوصف | الأمثلة | الضوابط |
|-------|-------|---------|---------|
| **حرج** | بيانات سرية للغاية | مفاتيح تشفير، بيانات عسكرية | HSM، وصول محدود جداً، تسجيل كامل |
| **سري** | بيانات حساسة | Emirates ID، بيانات مالية | تشفير، RBAC، تدقيق |
| **داخلي** | بيانات داخلية | تقارير، وثائق | وصول مصادق، تسجيل |
| **عام** | بيانات عامة | معلومات الموقع | لا ضوابط خاصة |

```python
# Python Data Classification
from enum import Enum
from dataclasses import dataclass
from typing import Optional

class DataClassification(Enum):
    CRITICAL = "CRITICAL"      # أحمر
    SECRET = "SECRET"          # برتقالي
    INTERNAL = "INTERNAL"      # أصفر
    PUBLIC = "PUBLIC"          # أخضر

@dataclass
class ClassifiedData:
    """Data with classification label"""
    data: str
    classification: DataClassification
    owner: str
    created_at: str
    retention_days: int
    
    def can_access(self, user_clearance: str) -> bool:
        """Check if user can access this data"""
        clearance_levels = {
            'CRITICAL': 4,
            'SECRET': 3,
            'INTERNAL': 2,
            'PUBLIC': 1,
        }
        
        data_level = clearance_levels.get(self.classification.value, 0)
        user_level = clearance_levels.get(user_clearance, 0)
        
        return user_level >= data_level
    
    def get_encryption_required(self) -> bool:
        """Check if encryption is required"""
        return self.classification in [
            DataClassification.CRITICAL,
            DataClassification.SECRET
        ]
    
    def get_retention_period(self) -> int:
        """Get retention period in days"""
        return self.retention_days
```

---

## HTTPS و HSTS — HTTPS and HSTS

**العربية:**
- فرض HTTPS حصرياً
- نفذ HTTP Strict Transport Security (HSTS)
- تثبيت الشهادات لمنع هجمات الوسيط
- تجديد الشهادات قبل انتهاء الصلاحية

**English:**
- Enforce HTTPS exclusively
- Implement HTTP Strict Transport Security (HSTS)
- Certificate pinning to prevent man-in-the-middle attacks
- Renew certificates before expiry

```python
# Python HTTPS Enforcement
from flask import Flask, request, redirect

app = Flask(__name__)

@app.before_request
def enforce_https():
    """Redirect HTTP to HTTPS"""
    if not request.is_secure and not app.debug:
        url = request.url.replace('http://', 'https://', 1)
        return redirect(url, code=301)

@app.after_request
def set_hsts_header(response):
    """Set HSTS header"""
    response.headers['Strict-Transport-Security'] = (
        'max-age=31536000; '  # 1 year
        'includeSubDomains; '  # All subdomains
        'preload'  # Browser preload list
    )
    return response

# Certificate pinning (for API clients)
import ssl
import certifi

class PinnedHTTPSAdapter:
    """HTTPS adapter with certificate pinning"""
    
    def __init__(self, expected_fingerprint: str):
        self.expected_fingerprint = expected_fingerprint
    
    def verify_certificate(self, cert_der: bytes):
        """Verify certificate fingerprint"""
        import hashlib
        fingerprint = hashlib.sha256(cert_der).hexdigest()
        
        if fingerprint != self.expected_fingerprint:
            raise ssl.SSLError(
                f"Certificate fingerprint mismatch. "
                f"Expected: {self.expected_fingerprint}, "
                f"Got: {fingerprint}"
            )
```

---

## حقوق البيانات — Data Rights

**العربية:**
- حق الوصول: السماح للمستخدمين بالوصول إلى بياناتهم
- حق التصحيح: السماح بتصحيح البيانات غير الدقيقة
- حق الحذف: السماح بحذف البيانات (الحق في النسيان)
- حق النقل: توفير تصدير البيانات
- حق الاعتراض: السماح بالاعتراض على المعالجة

**English:**
- Right to access: Allow users to access their data
- Right to rectification: Allow correction of inaccurate data
- Right to erasure: Allow deletion of data (right to be forgotten)
- Right to portability: Provide data export
- Right to object: Allow objection to processing

```python
# Python Data Rights Implementation
from datetime import datetime
from typing import List, Dict, Any

class UAEDataRights:
    """
    Implement UAE/PDPL data subject rights
    """
    
    def __init__(self, data_store, audit_logger):
        self.store = data_store
        self.audit = audit_logger
    
    def access_request(self, user_id: str) -> Dict[str, Any]:
        """
        Handle data access request (Right to Access)
        """
        # Retrieve all user data
        user_data = self.store.get_user_data(user_id)
        
        # Log the request
        self.audit.log_event(
            event_type="DATA_ACCESS_REQUEST",
            user_id=user_id,
            details={"data_categories": list(user_data.keys())}
        )
        
        return {
            "request_id": generate_id(),
            "timestamp": datetime.utcnow().isoformat(),
            "user_id": user_id,
            "data": user_data,
            "format": "JSON"
        }
    
    def rectification_request(self, user_id: str, corrections: Dict[str, Any]) -> bool:
        """
        Handle data rectification request (Right to Rectification)
        """
        # Validate corrections
        for field, value in corrections.items():
            if not self._validate_field(field, value):
                raise ValueError(f"Invalid value for field: {field}")
        
        # Apply corrections
        old_data = self.store.get_user_data(user_id)
        self.store.update_user_data(user_id, corrections)
        
        # Log the change
        self.audit.log_event(
            event_type="DATA_RECTIFICATION",
            user_id=user_id,
            details={
                "fields_changed": list(corrections.keys()),
                "old_values": {k: old_data.get(k) for k in corrections.keys()}
            }
        )
        
        return True
    
    def erasure_request(self, user_id: str, reason: str) -> bool:
        """
        Handle data erasure request (Right to Erasure)
        """
        # Check if erasure is allowed
        if not self._can_erase(user_id):
            raise ValueError("Data cannot be erased due to legal obligations")
        
        # Get data before deletion for audit
        user_data = self.store.get_user_data(user_id)
        
        # Delete user data
        self.store.delete_user_data(user_id)
        
        # Delete related logs
        self.audit.delete_user_logs(user_id)
        
        # Log the erasure
        self.audit.log_event(
            event_type="DATA_ERASURE",
            user_id=user_id,
            details={
                "reason": reason,
                "data_categories_deleted": list(user_data.keys())
            }
        )
        
        return True
    
    def portability_request(self, user_id: str, format: str = "JSON") -> Dict[str, Any]:
        """
        Handle data portability request (Right to Portability)
        """
        user_data = self.store.get_user_data(user_id)
        
        # Format data for export
        if format == "JSON":
            export_data = json.dumps(user_data, indent=2)
        elif format == "CSV":
            export_data = self._convert_to_csv(user_data)
        else:
            raise ValueError(f"Unsupported format: {format}")
        
        # Log the request
        self.audit.log_event(
            event_type="DATA_PORTABILITY_REQUEST",
            user_id=user_id,
            details={"format": format}
        )
        
        return {
            "request_id": generate_id(),
            "timestamp": datetime.utcnow().isoformat(),
            "user_id": user_id,
            "format": format,
            "data": export_data
        }
    
    def _validate_field(self, field: str, value: Any) -> bool:
        """Validate field value"""
        validators = {
            'email': lambda v: '@' in v,
            'phone': lambda v: v.startswith('+971'),
            'emirates_id': lambda v: len(v) == 18,
        }
        
        validator = validators.get(field)
        if validator:
            return validator(value)
        
        return True
    
    def _can_erase(self, user_id: str) -> bool:
        """Check if user data can be erased"""
        # Check for legal holds
        legal_holds = self.store.get_legal_holds(user_id)
        
        # Check for active transactions
        active_transactions = self.store.get_active_transactions(user_id)
        
        return len(legal_holds) == 0 and len(active_transactions) == 0
```

---

## الشفافية — Transparency

**العربية:**
- أبلغ المستخدمين عن سياسات الخصوصية
- وضح كيفية استخدام البيانات
- قدم إشعارات واضحة للموافقة
- سجل الموافقات
- اسمح للمستخدمين بسحب الموافقة

**English:**
- Inform users about privacy policies
- Clarify how data is used
- Provide clear consent notifications
- Record consents
- Allow users to withdraw consent

```python
# Python Consent Management
from datetime import datetime
from enum import Enum

class ConsentType(Enum):
    MARKETING = "MARKETING"
    ANALYTICS = "ANALYTICS"
    THIRD_PARTY = "THIRD_PARTY"
    ESSENTIAL = "ESSENTIAL"

class UAEConsentManager:
    """
    Manage user consent for UAE/PDPL compliance
    """
    
    def __init__(self, consent_store):
        self.store = consent_store
    
    def record_consent(
        self,
        user_id: str,
        consent_type: ConsentType,
        granted: bool,
        method: str,  # e.g., "checkbox", "signature"
        version: str
    ):
        """Record user consent"""
        consent_record = {
            "user_id": user_id,
            "consent_type": consent_type.value,
            "granted": granted,
            "timestamp": datetime.utcnow().isoformat(),
            "method": method,
            "version": version,
            "ip_address": request.remote_addr,
            "user_agent": request.user_agent.string,
        }
        
        self.store.save_consent(consent_record)
        
        # Log consent change
        audit_logger.log_event(
            event_type="CONSENT_RECORDED",
            user_id=user_id,
            details={
                "consent_type": consent_type.value,
                "granted": granted,
                "version": version
            }
        )
    
    def withdraw_consent(self, user_id: str, consent_type: ConsentType):
        """Withdraw user consent"""
        # Update consent record
        self.store.update_consent(
            user_id=user_id,
            consent_type=consent_type.value,
            granted=False,
            withdrawn_at=datetime.utcnow().isoformat()
        )
        
        # Stop processing based on this consent
        self._stop_processing(user_id, consent_type)
        
        # Log withdrawal
        audit_logger.log_event(
            event_type="CONSENT_WITHDRAWN",
            user_id=user_id,
            details={"consent_type": consent_type.value}
        )
    
    def has_consent(self, user_id: str, consent_type: ConsentType) -> bool:
        """Check if user has given consent"""
        consent = self.store.get_latest_consent(user_id, consent_type.value)
        
        if not consent:
            return False
        
        return consent.get("granted", False)
    
    def _stop_processing(self, user_id: str, consent_type: ConsentType):
        """Stop processing based on withdrawn consent"""
        if consent_type == ConsentType.MARKETING:
            # Remove from marketing lists
            marketing_service.unsubscribe(user_id)
        elif consent_type == ConsentType.ANALYTICS:
            # Disable analytics tracking
            analytics_service.opt_out(user_id)
        elif consent_type == ConsentType.THIRD_PARTY:
            # Stop sharing with third parties
            data_sharing_service.revoke_access(user_id)
```

---

## تقليل تسرب IP — Minimize IP Address Leakage

**العربية:**
- احجب تحميل المحتوى الخارجي من طرف ثالث حيثما أمكن
- استخدم بروكسي للمحتوى الخارجي
- قصر الاتصالات على النطاقات الموثوقة
- راقب طلبات الشبكة

**English:**
- Block third-party external content loading where feasible
- Use proxy for external content
- Restrict connections to trusted domains
- Monitor network requests

```python
# Python Content Security Policy
from flask import Flask, Response

app = Flask(__name__)

@app.after_request
def set_csp_header(response: Response):
    """Set Content Security Policy to prevent external content"""
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "  # Only same origin
        "script-src 'self'; "   # No external scripts
        "style-src 'self'; "    # No external styles
        "img-src 'self' data:; "  # Images from same origin or data URIs
        "connect-src 'self'; "  # No external API calls
        "font-src 'self'; "     # No external fonts
        "frame-ancestors 'none'; "  # No framing
        "form-action 'self'; "  # Forms only to same origin
    )
    return response
```

---

## قائمة التحقق — Implementation Checklist

- [ ] التشفير القوي مُطبَّق للبيانات في النقل والسكون
- [ ] Argon2id لتخزين كلمات المرور
- [ ] HTTPS مفروض حصرياً
- [ ] HSTS مُفعَّل
- [ ] تثبيت الشهادات مُطبَّق
- [ ] تصنيف البيانات مُوثَّق
- [ ] ضوابط مختلفة لكل فئة
- [ ] حقوق البيانات مُنفذة (وصول، تصحيح، حذف، نقل)
- [ ] إدارة الموافقة مُنفذة
- [ ] سجلات الموافقة محفوظة
- [ ] سحب الموافقة ممكن
- [ ] تقليل تسرب IP
- [ ] CSP مُطبَّق
- [ ] سياسة الخصوصية واضحة
- [ ] إشعارات الموافقة واضحة
- [ ] تدقيق الخصوصية مُنفذ

---

## خطة الاختبار — Test Plan

- [ ] اختبار التشفير
- [ ] اختبار HTTPS enforcement
- [ ] اختبار HSTS
- [ ] اختبار تثبيت الشهادات
- [ ] اختبار حق الوصول
- [ ] اختبار التصحيح
- [ ] اختبار الحذف
- [ ] اختبار النقل
- [ ] اختبار الموافقة
- [ ] اختبار سحب الموافقة
- [ ] اختبار CSP
- [ ] اختبار تسرب IP

---

## مراجع — References

- [OWASP Privacy Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Protecting_Data_Cheat_Sheet.html)
- [GDPR Guidelines](https://gdpr.eu/)
- [UAE PDPL (Federal Decree Law No. 45 of 2021)](https://u.ae/)
- [NIST SP 800-122 - Guide to Protecting the Confidentiality of PII](https://csrc.nist.gov/publications/detail/sp/800-122/final)
