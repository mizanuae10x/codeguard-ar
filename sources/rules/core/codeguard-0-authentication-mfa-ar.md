---
description: المصادقة و MFA - أفضل الممارسات (كلمات المرور، MFA، OAuth/OIDC، SAML، الاسترداد، الرموز)
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
tags:
- authentication
- web
- uae
alwaysApply: false
---

# المصادقة و MFA — Authentication & MFA

## نظرة عامة — Overview

ابنِ نظام مصادقة مرن وسهل الاستخدام يقاوم هجمات الاعتمادات، ويحمي الأسرار، ويدعم MFA قوياً ومقاوماً للتصيد، واسترداداً آمناً.

Build a resilient, user-friendly authentication system that resists credential attacks, protects secrets, and supports strong, phishing-resistant MFA and secure recovery.

---

## معرفات الحساب وتجربة المستخدم — Account Identifiers and UX

**العربية:**
- استخدم معرفات داخلية غير عامة وعشوائية وفريدة
- اسمح بتسجيل الدخول عبر البريد الإلكتروني المُحقق أو اسم المستخدم
- أعد دائماً رسائل خطأ عامة (مثال: "اسم المستخدم أو كلمة المرور غير صحيحة")
- حافظ على توقيت متسق لمنع تعداد الحسابات
- ادعم مديري كلمات المرور: `<input type="password">`، اسمح باللصق، لا تحظر JS

**English:**
- Use non-public, random, and unique internal user identifiers
- Allow login via verified email or username
- Always return generic error messages (e.g., "Invalid username or password")
- Keep timing consistent to prevent account enumeration
- Support password managers: `<input type="password">`, allow paste, no JS blocks

---

## سياسة كلمات المرور — Password Policy

**العربية:**
- اقبل عبارات المرور (passphrases) و Unicode الكامل
- الحد الأدنى 8 أحرف
- تجنب قواعد التركيب (composition rules)
- حد أقصى معقول فقط (64+)
- تحقق من كلمات المرور الجديدة ضد قواعد البيانات المخترقة

**English:**
- Accept passphrases and full Unicode
- Minimum 8 characters
- Avoid composition rules
- Set only a reasonable maximum length (64+)
- Check new passwords against breach corpora

```python
# Python Password Validation for UAE
import re
import requests
import hashlib

class UAEPasswordPolicy:
    """
    UAE-compliant password policy
    """
    
    MIN_LENGTH = 8
    MAX_LENGTH = 128
    
    @classmethod
    def validate_password(cls, password: str) -> tuple[bool, list[str]]:
        """
        Validate password against UAE standards
        Returns: (is_valid, list_of_errors)
        """
        errors = []
        
        # Length check
        if len(password) < cls.MIN_LENGTH:
            errors.append(f"Password must be at least {cls.MIN_LENGTH} characters")
        if len(password) > cls.MAX_LENGTH:
            errors.append(f"Password must not exceed {cls.MAX_LENGTH} characters")
        
        # Check against breach database (using k-anonymity)
        if cls.is_breached(password):
            errors.append("This password has appeared in data breaches. Please choose a different one.")
        
        # Check for common patterns
        if cls.is_common_pattern(password):
            errors.append("Password is too common or predictable")
        
        return len(errors) == 0, errors
    
    @classmethod
    def is_breached(cls, password: str) -> bool:
        """Check if password exists in breach database using k-anonymity"""
        sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix = sha1[:5]
        suffix = sha1[5:]
        
        try:
            response = requests.get(
                f"https://api.pwnedpasswords.com/range/{prefix}",
                timeout=5
            )
            if response.status_code == 200:
                return suffix in response.text
        except:
            pass
        
        return False
    
    @classmethod
    def is_common_pattern(cls, password: str) -> bool:
        """Check for common weak patterns"""
        common_patterns = [
            r'^(password|pass|123456|qwerty|abc123)',
            r'^(uae|dubai|abudhabi|emirates)\d*',
            r'^(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)\d{4}',
        ]
        
        return any(re.match(pattern, password.lower()) for pattern in common_patterns)
```

---

## تخزين كلمات المرور (التجزئة) — Password Storage (Hashing)

**العربية:**
- استخدم التجزئة، لا التشفير
- استخدم خوارزميات بطيئة وصعبة الذاكرة (memory-hard)
- ملح فريد لكل مستخدم (per-user salt)
- مقارنة بوقت ثابت (constant-time comparison)

**English:**
- Hash, do not encrypt
- Use slow, memory-hard algorithms
- Unique per-user salts
- Constant-time comparison

### تفضيل الخوارزميات — Preferred Algorithms

| الخوارزمية | المعاملات | الاستخدام |
|-----------|-----------|----------|
| **Argon2id** | m=19-46 MiB, t=2, p=1 | المفضل |
| **scrypt** | N=2^17, r=8, p=1 | بديل |
| **bcrypt** | cost ≥10 | تراثي فقط |
| **PBKDF2** | ≥600k iterations (SHA-256) | FIPS |

```python
# Python Password Hashing with Argon2
from argon2 import PasswordHasher
from argon2.low_level import Type

class UAEPasswordHasher:
    """
    UAE-compliant password hasher using Argon2id
    """
    
    def __init__(self):
        self.ph = PasswordHasher(
            time_cost=3,          # Iterations
            memory_cost=65536,    # 64 MB
            parallelism=1,        # Parallel threads
            hash_len=32,          # Hash length
            salt_len=16,          # Salt length
            type=Type.ID          # Argon2id
        )
    
    def hash_password(self, password: str) -> str:
        """Hash a password"""
        return self.ph.hash(password)
    
    def verify_password(self, password: str, hash_string: str) -> bool:
        """Verify a password against a hash"""
        try:
            self.ph.verify(hash_string, password)
            # Check if rehash is needed (parameters changed)
            if self.ph.check_needs_rehash(hash_string):
                # Trigger async rehash
                pass
            return True
        except:
            return False
```

---

## تصلب تدفق المصادقة — Authentication Flow Hardening

**العربية:**
- فرض TLS لجميع نقاط نهاية المصادقة ونقل الرموز
- تفعيل HSTS
- تنفيذ حدود المعدل لكل IP وحساب وعالمياً
- إضافة proof-of-work أو CAPTCHA كملاذ أخير فقط
- قفل/خنق: تراجع تدريجي؛ تجنب القفل الدائم

**English:**
- Enforce TLS for all auth endpoints and token transport
- Enable HSTS
- Implement rate limits per IP, account, and globally
- Add proof-of-work or CAPTCHA only as last resort
- Lockouts/throttling: progressive backoff; avoid permanent lockout

---

## المصادقة متعددة العوامل (MFA) — Multi-Factor Authentication

**العربية:**
- اعتماد عوامل مقاومة للتصيد افتراضياً للحسابات الحساسة
- passkeys/WebAuthn (FIDO2) أو U2F
- مقبول: TOTP (تطبيق)
- تجنب للاستخدام الحساس: SMS/صوت، رموز البريد
- لا تعتمد أبداً على أسئلة الأمان

**English:**
- Adopt phishing-resistant factors by default for sensitive accounts
- passkeys/WebAuthn (FIDO2) or hardware U2F
- Acceptable: TOTP (app-based)
- Avoid for sensitive use: SMS/voice, email codes
- Never rely on security questions

### متى تتطلب MFA — When to Require MFA

| السيناريو | MFA مطلوب |
|-----------|----------|
| تسجيل الدخول | ✅ |
| تغيير كلمة المرور/البريد | ✅ |
| تعطيل MFA | ✅ |
| رفع الامتيازات | ✅ |
| معاملات عالية القيمة | ✅ |
| أجهزة/مواقع جديدة | ✅ |

```javascript
// Node.js MFA Implementation with WebAuthn
const { Fido2Lib } = require('fido2-lib');

class UAEMFAService {
    constructor() {
        this.fido2 = new Fido2Lib({
            timeout: 60000,
            rpId: "uae-government.ae",
            rpName: "UAE Government Services",
            challengeSize: 128,
            attestation: "direct",
            cryptoParams: [-7, -257],  // ES256, RS256
        });
    }
    
    async registerDevice(userId, deviceName) {
        const registrationOptions = await this.fido2.attestationOptions();
        
        // Store challenge for verification
        await this.storeChallenge(userId, registrationOptions.challenge);
        
        return {
            ...registrationOptions,
            user: {
                id: Buffer.from(userId).toString('base64'),
                name: `user-${userId}`,
                displayName: `UAE User ${userId}`,
            },
            authenticatorSelection: {
                authenticatorAttachment: "platform",
                userVerification: "required",
                residentKey: "preferred",
            },
        };
    }
    
    async verifyRegistration(userId, attestationResponse) {
        const challenge = await this.getChallenge(userId);
        
        const attestationExpectations = {
            challenge: challenge,
            origin: "https://uae-government.ae",
            factor: "either",
        };
        
        const regResult = await this.fido2.attestationResult(
            attestationResponse,
            attestationExpectations
        );
        
        // Store credential
        await this.storeCredential(userId, {
            credId: regResult.authnrData.get('credId'),
            publicKey: regResult.authnrData.get('credentialPublicKeyPem'),
            counter: regResult.authnrData.get('counter'),
            deviceName: attestationResponse.deviceName,
        });
        
        return { success: true };
    }
}
```

---

## الاتحاد والبروتوكولات — Federation and Protocols

### OAuth 2.0 / OIDC

**العربية:**
- استخدم البروتوكولات القياسية فقط؛ لا تبنِ خاصتك
- تفضل Authorization Code مع PKCE للتطبيقات العامة/الأصلية
- تجنب Implicit و ROPC
- تحقق من state و nonce
- استخدم مطابقة دقيقة لـ redirect URI
- منع إعادة التوجيه المفتوحة

**English:**
- Use standard protocols only; do not build your own
- Prefer Authorization Code with PKCE for public/native apps
- Avoid Implicit and ROPC
- Validate state and nonce
- Use exact redirect URI matching
- Prevent open redirects

### SAML

**العربية:**
- TLS 1.2+
- توقيع الاستجابات/الادعاءات
- تشفير الادعاءات الحساسة
- التحقق من المصدرين والطوابع الزمنية
- منع XML signature wrapping

**English:**
- TLS 1.2+
- Sign responses/assertions
- Encrypt sensitive assertions
- Validate issuers and timestamps
- Prevent XML signature wrapping

```python
# Python OAuth2/OIDC Configuration
from authlib.integrations.flask_client import OAuth

oauth = OAuth()

# UAE Government OAuth Provider
uae_gov = oauth.register(
    name='uae_gov',
    client_id='your-client-id',
    client_secret='your-client-secret',
    server_metadata_url='https://auth.uae.gov.ae/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid email profile uae_id',
        'code_challenge_method': 'S256',  # PKCE
    },
)

# Secure callback handler
@app.route('/auth/callback')
def auth_callback():
    token = uae_gov.authorize_access_token(
        verify=True,
        # Strict redirect URI validation
        redirect_uri='https://your-app.uae.gov.ae/auth/callback'
    )
    
    # Validate token claims
    user_info = token.get('userinfo')
    if not validate_uae_claims(user_info):
        raise SecurityError('Invalid UAE government claims')
    
    # Bind to session context
    session['user_id'] = user_info['sub']
    session['emirates_id'] = user_info.get('uae_id')
    
    return redirect('/dashboard')
```

---

## الرموز (JWT و Opaque) — Tokens

**العربية:**
- فضّل الرموز المُدارَة من الخادم (opaque) للبساطة والإبطال
- إذا استخدمت JWT:
  - ثبت الخوارزميات صراحةً
  - ارفض "none"
  - تحقق من iss/aud/exp/iat/nbf
  - أوقات حياة قصيرة وتدوير

**English:**
- Prefer opaque server-managed tokens for simplicity and revocation
- If using JWTs:
  - Explicitly pin algorithms
  - Reject "none"
  - Validate iss/aud/exp/iat/nbf
  - Short lifetimes and rotation

```python
# Python JWT with UAE-Specific Claims
import jwt
from datetime import datetime, timedelta

class UAEJWTManager:
    """
    JWT manager with UAE government-specific claims
    """
    
    def __init__(self, private_key, public_key):
        self.private_key = private_key
        self.public_key = public_key
        self.algorithm = 'RS256'
    
    def create_token(self, user_id, emirates_id, clearance_level):
        """Create UAE-compliant JWT"""
        now = datetime.utcnow()
        
        payload = {
            # Standard claims
            'iss': 'https://auth.uae.gov.ae',
            'aud': 'uae-government-services',
            'iat': now,
            'exp': now + timedelta(hours=1),  # Short lifetime
            'jti': generate_unique_id(),  # For revocation
            
            # UAE-specific claims
            'sub': user_id,
            'uae_id': emirates_id,
            'clearance': clearance_level,
            'department': get_user_department(user_id),
            'mfa_verified': True,
            'auth_time': now,
        }
        
        return jwt.encode(payload, self.private_key, algorithm=self.algorithm)
    
    def validate_token(self, token):
        """Validate UAE JWT with all checks"""
        try:
            payload = jwt.decode(
                token,
                self.public_key,
                algorithms=[self.algorithm],
                audience='uae-government-services',
                issuer='https://auth.uae.gov.ae',
                options={
                    'require': ['exp', 'iat', 'iss', 'aud', 'sub'],
                }
            )
            
            # Check revocation
            if self.is_revoked(payload['jti']):
                raise jwt.InvalidTokenError('Token has been revoked')
            
            # Verify MFA was completed
            if not payload.get('mfa_verified'):
                raise jwt.InvalidTokenError('MFA not verified')
            
            return payload
            
        except jwt.ExpiredSignatureError:
            raise SecurityError('Token expired')
        except jwt.InvalidTokenError as e:
            raise SecurityError(f'Invalid token: {str(e)}')
```

---

## الاسترداد وإعادة الضبط — Recovery and Reset

**العربية:**
- أعد نفس الاستجابة للحسابات الموجودة وغير الموجودة
- طبيعة التوقيت
- أنشئ رموز 32+ بايت من CSPRNG
- استخدام واحد، مخزنة كتجزئة، صلاحية قصيرة
- روابط HTTPS لنطاقات موثوقة
- بعد إعادة الضبط: تتطلب إعادة المصادقة، تدوير الجلسات

**English:**
- Return same response for existing and non-existing accounts
- Normalize timing
- Generate 32+ byte CSPRNG tokens
- Single-use, stored as hashes, short expiry
- HTTPS reset links to trusted domains
- After reset: require re-authentication, rotate sessions

```python
# Python Secure Password Reset
import secrets
import hashlib
from datetime import datetime, timedelta

class UAEPasswordReset:
    """
    UAE-compliant password reset service
    """
    
    TOKEN_EXPIRY_HOURS = 1
    
    def generate_reset_token(self, user_id: str) -> str:
        """Generate secure reset token"""
        token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        
        # Store hash with expiry
        self.store_reset_token(
            user_id=user_id,
            token_hash=token_hash,
            expires_at=datetime.utcnow() + timedelta(hours=self.TOKEN_EXPIRY_HOURS)
        )
        
        return token
    
    def validate_reset_token(self, token: str) -> str:
        """Validate reset token and return user_id"""
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        
        stored = self.get_stored_token(token_hash)
        if not stored:
            # Return generic error - don't reveal if token exists
            raise SecurityError('Invalid or expired reset token')
        
        if stored['expires_at'] < datetime.utcnow():
            self.delete_token(token_hash)
            raise SecurityError('Invalid or expired reset token')
        
        # Mark as used (single-use)
        self.delete_token(token_hash)
        
        return stored['user_id']
    
    def send_reset_email(self, email: str, token: str):
        """Send reset email with secure link"""
        reset_url = f"https://uae-government.ae/reset?token={token}"
        
        # Send email with no-referrer policy
        send_email(
            to=email,
            subject="Password Reset - UAE Government Services",
            body=f"""
            Click the link below to reset your password:
            {reset_url}
            
            This link expires in {self.TOKEN_EXPIRY_HOURS} hour.
            If you didn't request this, please ignore this email.
            """,
            headers={
                'Referrer-Policy': 'no-referrer',
                'X-Content-Type-Options': 'nosniff',
            }
        )
```

---

## الحسابات الإدارية والداخلية — Administrative and Internal Accounts

**العربية:**
- افصل تسجيل دخول المسؤول عن النماذج العامة
- فرض MFA أقوى
- فحوصات وضع الجهاز
- قوائم IP المسموح بها
- مصادقة step-up
- سياقات جلسات منفصلة مع مهلات أقصر

**English:**
- Separate admin login from public forms
- Enforce stronger MFA
- Device posture checks
- IP allowlists
- Step-up auth
- Distinct session contexts with stricter timeouts

---

## المراقبة والإشارات — Monitoring and Signals

**العربية:**
- سجل أحداث المصادقة (الفشل/النجاح، MFA، إعادة الضبط)
- حقول مستقرة ومعرفات ارتباط
- لا تسجل الأسرار أو الرموز الخام
- اكتشف حشو الاعتمادات
- أخطِر المستخدمين بتسجيلات الدخول من أجهزة جديدة

**English:**
- Log auth events (failures/successes, MFA, resets)
- Stable fields and correlation IDs
- Never log secrets or raw tokens
- Detect credential stuffing
- Notify users of new device logins

```python
# Python Auth Event Logging
import logging
import json
from datetime import datetime

class UAEAuthLogger:
    """
    UAE-compliant authentication event logger
    """
    
    def __init__(self):
        self.logger = logging.getLogger('uae.auth')
    
    def log_auth_event(self, event_type, user_id, success, **kwargs):
        """Log authentication event"""
        event = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'event_type': event_type,
            'user_id_hash': hash_user_id(user_id),  # Hashed for privacy
            'success': success,
            'source_ip': kwargs.get('source_ip'),
            'user_agent_hash': hash_user_agent(kwargs.get('user_agent')),
            'mfa_used': kwargs.get('mfa_used'),
            'mfa_method': kwargs.get('mfa_method'),
            'correlation_id': kwargs.get('correlation_id'),
            'risk_score': kwargs.get('risk_score'),
        }
        
        # Remove None values
        event = {k: v for k, v in event.items() if v is not None}
        
        if success:
            self.logger.info(json.dumps(event))
        else:
            self.logger.warning(json.dumps(event))
    
    def detect_credential_stuffing(self, events):
        """Detect potential credential stuffing attack"""
        # Check for high failure rates from multiple IPs
        recent_failures = [e for e in events 
                          if not e['success'] 
                          and e['timestamp'] > datetime.utcnow() - timedelta(minutes=5)]
        
        unique_ips = len(set(e['source_ip'] for e in recent_failures))
        
        if len(recent_failures) > 100 and unique_ips > 10:
            self.logger.critical(json.dumps({
                'alert_type': 'credential_stuffing_detected',
                'failure_count': len(recent_failures),
                'unique_ips': unique_ips,
                'action': 'blocking_ips',
            }))
            
            return True
        
        return False
```

---

## قائمة التحقق — Implementation Checklist

- [ ] كلمات المرور: Argon2id مع ملح فريد لكل مستخدم، مقارنة بوقت ثابت
- [ ] فحص كلمات المرور المخترقة عند التغيير/الإعداد
- [ ] MFA: WebAuthn/passkeys أو رموز مادية للمخاطر العالية
- [ ] TOTP كاحتياطي
- [ ] استرداد آمن مع رموز احتياطية
- [ ] الاتحاد: Authorization Code + PKCE
- [ ] مطابقة صارمة لـ redirect URI
- [ ] فرض audience/scope
- [ ] تدوير الرموز
- [ ] الرموز: قصيرة العمر، مقيدة بالمرسل
- [ ] تنفيذ الإبطال
- [ ] الأسرار في KMS/HSM
- [ ] الاسترداد: استخدام واحد، تجزئة، محدد بوقت
- [ ] استجابات متسقة
- [ ] إعادة المصادقة مطلوبة بعد إعادة الضبط
- [ ] تدوير الجلسات
- [ ] الاعتداء: حدود المعدل، الخنق، الكشف عن الشذوذ
- [ ] معالجة خطأ موحدة
- [ ] المسؤول: تدفقات معزولة مع سياسات أشد

---

## خطة الاختبار — Test Plan

- [ ] اختبارات الوحدة/التكامل لتسجيل الدخول و MFA والإعادة
- [ ] اختبارات البروتوكول: PKCE و state/nonce و redirect URI
- [ ] اختبارات ديناميكية لمقاومة حشو الاعتمادات
- [ ] التحقق من الإبطال بعد تسجيل الخروج وتغيير الدور
- [ ] اختبارات توقيت موحدة
- [ ] اختبارات قوة MFA ضد التصيد

---

## مراجع — References

- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [NIST SP 800-63B - Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [FIDO2/WebAuthn Specification](https://fidoalliance.org/fido2/)
- [UAE Information Assurance Framework](https://www.tra.gov.ae/)
