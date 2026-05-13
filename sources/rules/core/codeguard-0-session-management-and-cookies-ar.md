---
description: إدارة الجلسات وملفات تعريف الارتباط الآمنة (التدوير، الثبات، المهلات، كشف السرقة)
languages:
- c
- go
- html
- java
- javascript
- php
- python
- ruby
- typescript
tags:
- authentication
- web
- session
- uae
alwaysApply: false
---

# إدارة الجلسات وملفات تعريف الارتباط — Session Management & Cookies

## نظرة عامة — Overview

نفذ معالجة جلسات قوية ومقاومة للهجمات تمنع الثبات والاختطاف والسرقة مع الحفاظ على سهولة الاستخدام.

Implement robust, attack-resistant session handling that prevents fixation, hijacking, and theft while maintaining usability.

---

## توليد معرف الجلسة وخصائصها — Session ID Generation and Properties

**العربية:**
- أنشئ معرفات الجلسة باستخدام مولد أرقام عشوائية آمن (CSPRNG)
- ≥64 بت من العشوائية (يفضل 128+)
- معتم (opaque)، غير قابل للتخمين، وخالٍ من المعنى
- استخدم أسماء ملفات تعريف ارتباط عامة (مثال: `id`) بدلاً من الأسماء الافتراضية للإطار
- ارفض أي معرف وارد لم يتم إنشاؤه بواسطة الخادم

**English:**
- Generate session IDs with a CSPRNG; ≥64 bits of entropy (prefer 128+)
- Opaque, unguessable, and free of meaning
- Use generic cookie names (e.g., `id`) rather than framework defaults
- Reject any incoming ID not created by the server

```python
# Python Secure Session ID Generation
import secrets
import hashlib
import base64

class UAESessionManager:
    """
    UAE-compliant secure session management
    """
    
    SESSION_ID_BYTES = 32  # 256 bits of entropy
    
    @classmethod
    def generate_session_id(cls) -> str:
        """Generate cryptographically secure session ID"""
        # Use secrets module (CSPRNG)
        random_bytes = secrets.token_bytes(cls.SESSION_ID_BYTES)
        
        # Encode as URL-safe base64
        session_id = base64.urlsafe_b64encode(random_bytes).decode('ascii').rstrip('=')
        
        return session_id
    
    @classmethod
    def hash_session_id(cls, session_id: str) -> str:
        """Hash session ID for storage/logging"""
        # Use HMAC with server secret for additional security
        return hashlib.sha256(
            f"{session_id}:{cls._get_server_secret()}".encode()
        ).hexdigest()
    
    @staticmethod
    def _get_server_secret() -> str:
        """Get server secret from secure storage"""
        return os.getenv('SESSION_SECRET', '')
```

---

## تكوين أمان ملف تعريف الارتباط — Cookie Security Configuration

**العربية:**
- اضبط `Secure` و`HttpOnly` و`SameSite=Strict` (أو `Lax` إذا لزم الأمر)
- نطاق ملفات تعريف الارتباط ضيق بـ `Path` و`Domain`
- تجنب التعرض عبر النطاقات الفرعية
- فضّل ملفات تعريف الارتباط غير المستمرة (بدون Expires/Max-Age)
- اشترط HTTPS بالكامل؛ فعّل HSTS

**English:**
- Set `Secure`, `HttpOnly`, `SameSite=Strict` (or `Lax` if necessary)
- Scope cookies narrowly with `Path` and `Domain`
- Avoid cross-subdomain exposure
- Prefer non-persistent session cookies (no Expires/Max-Age)
- Require full HTTPS; enable HSTS site-wide

```python
# Python Flask Cookie Configuration
from flask import Flask, session
from datetime import timedelta

app = Flask(__name__)

# Session configuration
app.config.update(
    SESSION_COOKIE_NAME='id',  # Generic name
    SESSION_COOKIE_SECURE=True,  # HTTPS only
    SESSION_COOKIE_HTTPONLY=True,  # No JavaScript access
    SESSION_COOKIE_SAMESITE='Strict',  # CSRF protection
    SESSION_COOKIE_PATH='/',  # Scope
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),  # Absolute timeout
)

# Set additional security headers
@app.after_request
def set_security_headers(response):
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, private'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response
```

---

## دورة حياة الجلسة والتدوير — Session Lifecycle and Rotation

**العربية:**
- أنشئ الجلسات من جانب الخادم فقط
- عامل المعرفات المقدمة كمدخلات غير موثوقة
- أعد توليد معرف الجلسة عند المصادقة وتغيير كلمة المرور ورفع الامتيازات
- أبطل المعرف السابق

**English:**
- Create sessions only server-side
- Treat provided IDs as untrusted input
- Regenerate session ID on authentication, password changes, and privilege elevation
- Invalidate the prior ID

```python
# Python Session Rotation
class UAESessionHandler:
    """
    Handle session lifecycle with UAE security requirements
    """
    
    def __init__(self, session_store):
        self.store = session_store
    
    def create_session(self, user_id: str, user_data: dict) -> str:
        """Create new secure session"""
        session_id = UAESessionManager.generate_session_id()
        
        session_data = {
            'user_id': user_id,
            'created_at': datetime.utcnow().isoformat(),
            'last_accessed': datetime.utcnow().isoformat(),
            'ip_address': request.remote_addr,
            'user_agent': request.user_agent.string,
            'clearance_level': user_data.get('clearance_level'),
            'department': user_data.get('department'),
        }
        
        # Store server-side
        self.store.set(
            f"session:{session_id}",
            json.dumps(session_data),
            ex=timedelta(hours=8)  # Absolute timeout
        )
        
        return session_id
    
    def rotate_session(self, old_session_id: str) -> str:
        """Rotate session ID (post-auth, privilege change)"""
        # Get old session data
        old_data = self.store.get(f"session:{old_session_id}")
        if not old_data:
            raise SecurityError("Invalid session")
        
        # Create new session
        new_session_id = UAESessionManager.generate_session_id()
        session_data = json.loads(old_data)
        session_data['rotated_at'] = datetime.utcnow().isoformat()
        session_data['rotation_count'] = session_data.get('rotation_count', 0) + 1
        
        # Store new session
        self.store.set(
            f"session:{new_session_id}",
            json.dumps(session_data),
            ex=timedelta(hours=8)
        )
        
        # Invalidate old session
        self.store.delete(f"session:{old_session_id}")
        
        # Log rotation
        audit_logger.log_session_rotation(
            old_hash=UAESessionManager.hash_session_id(old_session_id),
            new_hash=UAESessionManager.hash_session_id(new_session_id),
            user_id=session_data['user_id']
        )
        
        return new_session_id
    
    def invalidate_session(self, session_id: str):
        """Fully invalidate session"""
        self.store.delete(f"session:{session_id}")
        
        # Clear cookie client-side
        response.delete_cookie('id')
```

---

## انتهاء الصلاحية وتسجيل الخروج — Expiration and Logout

**العربية:**
- مهلة الخمول: 2-5 دقائق للقيمة العالية، 15-30 دقيقة للمخاطر الأقل
- مهلة مطلقة: 4-8 ساعات
- فرض المهلات من جانب الخادم
- زر تسجيل خروج مرئي يبطل الجلسة بالكامل

**English:**
- Idle timeout: 2–5 minutes for high-value, 15–30 minutes for lower risk
- Absolute timeout: 4–8 hours
- Enforce timeouts server-side
- Visible logout button that fully invalidates the server session

```python
# Python Session Timeout Enforcement
class UAESessionTimeout:
    """
    Enforce session timeouts with UAE requirements
    """
    
    # Timeout configurations by clearance level
    TIMEOUTS = {
        'STANDARD': {'idle': 30, 'absolute': 480},  # 30 min idle, 8 hours absolute
        'SENSITIVE': {'idle': 15, 'absolute': 240},  # 15 min idle, 4 hours absolute
        'HIGHLY_CLASSIFIED': {'idle': 5, 'absolute': 120},  # 5 min idle, 2 hours absolute
    }
    
    @classmethod
    def check_timeout(cls, session_data: dict) -> tuple[bool, Optional[str]]:
        """Check if session has timed out"""
        clearance = session_data.get('clearance_level', 'STANDARD')
        timeouts = cls.TIMEOUTS.get(clearance, cls.TIMEOUTS['STANDARD'])
        
        now = datetime.utcnow()
        created = datetime.fromisoformat(session_data['created_at'])
        last_accessed = datetime.fromisoformat(session_data['last_accessed'])
        
        # Check absolute timeout
        absolute_limit = created + timedelta(minutes=timeouts['absolute'])
        if now > absolute_limit:
            return False, "Session expired (absolute timeout)"
        
        # Check idle timeout
        idle_limit = last_accessed + timedelta(minutes=timeouts['idle'])
        if now > idle_limit:
            return False, "Session expired (idle timeout)"
        
        return True, None
    
    @classmethod
    def update_last_accessed(cls, session_id: str, session_data: dict):
        """Update last accessed timestamp"""
        session_data['last_accessed'] = datetime.utcnow().isoformat()
        # Update in store with same TTL
```

---

## كشف سرقة ملف تعريف الارتباط والاستجابة — Cookie Theft Detection and Response

**العربية:**
- بصمة سياق الجلسة من جانب الخادم عند الإنشاء (IP، User-Agent، Accept-Language)
- قارن الطلبات الواردة بالبصمة المخزنة
- اسمح بالانحراف الحميد (تغييرات الشبكة الفرعية، تحديثات UA)
- استجابة قائمة على المخاطر

**English:**
- Fingerprint session context server-side at establishment
- Compare incoming requests to stored fingerprint
- Allow for benign drift (subnet changes, UA updates)
- Risk-based responses

```python
# Python Session Fingerprinting
class UAESessionFingerprint:
    """
    Detect session hijacking through fingerprinting
    """
    
    @staticmethod
    def generate_fingerprint(request) -> dict:
        """Generate session fingerprint"""
        return {
            'ip_address': request.remote_addr,
            'user_agent': request.user_agent.string,
            'accept_language': request.headers.get('Accept-Language', ''),
            'sec_ch_ua': request.headers.get('Sec-Ch-Ua', ''),
        }
    
    @classmethod
    def assess_risk(cls, current_request, stored_fingerprint: dict) -> str:
        """Assess risk level of session usage"""
        current = cls.generate_fingerprint(current_request)
        
        risk_score = 0
        
        # IP address check (allow same /24 subnet)
        if not cls._ip_in_same_subnet(current['ip_address'], stored_fingerprint['ip_address']):
            risk_score += 3
        
        # User-Agent check
        if current['user_agent'] != stored_fingerprint['user_agent']:
            risk_score += 2
        
        # Language check
        if current['accept_language'] != stored_fingerprint['accept_language']:
            risk_score += 1
        
        # Determine risk level
        if risk_score >= 4:
            return 'HIGH'
        elif risk_score >= 2:
            return 'MEDIUM'
        elif risk_score > 0:
            return 'LOW'
        
        return 'NONE'
    
    @staticmethod
    def _ip_in_same_subnet(ip1: str, ip2: str) -> bool:
        """Check if IPs are in same /24 subnet"""
        try:
            parts1 = ip1.split('.')
            parts2 = ip2.split('.')
            return parts1[:3] == parts2[:3]
        except:
            return False
    
    @classmethod
    def handle_risk(cls, session_id: str, risk_level: str, session_data: dict):
        """Handle detected risk"""
        if risk_level == 'HIGH':
            # Require re-authentication
            cls.invalidate_session(session_id)
            audit_logger.log_session_hijacking_attempt(
                session_hash=UAESessionManager.hash_session_id(session_id),
                user_id=session_data['user_id'],
                risk_level=risk_level
            )
            raise SecurityError("Session invalidated due to suspicious activity")
        
        elif risk_level == 'MEDIUM':
            # Step-up verification
            cls.require_step_up(session_id)
            audit_logger.log_suspicious_session_activity(
                session_hash=UAESessionManager.hash_session_id(session_id),
                user_id=session_data['user_id'],
                risk_level=risk_level
            )
        
        elif risk_level == 'LOW':
            # Log but allow
            audit_logger.log_suspicious_session_activity(
                session_hash=UAESessionManager.hash_session_id(session_id),
                user_id=session_data['user_id'],
                risk_level=risk_level
            )
```

---

## التخزين من جانب العميل — Client-Side Storage

**العربية:**
- لا تخزن رموز الجلسة في `localStorage`/`sessionStorage` بسبب مخاطر XSS
- فضّل ملفات تعريف الارتباط HttpOnly للنقل
- إذا كان التخزين من جانب العميل لا مفر منه، عزل عبر Web Workers

**English:**
- Do not store session tokens in `localStorage`/`sessionStorage` due to XSS risk
- Prefer HttpOnly cookies for transport
- If client-side storage is unavoidable, isolate via Web Workers

```javascript
// JavaScript Secure Client-Side Storage
// AVOID: localStorage for session tokens
localStorage.setItem('sessionToken', token); // DANGEROUS!

// PREFER: HttpOnly cookie (set server-side)
// Cookie: id=<token>; HttpOnly; Secure; SameSite=Strict

// If client storage is absolutely necessary:
class SecureClientStorage {
    constructor() {
        // Use a Web Worker to isolate from page context
        this.worker = new Worker('storage-worker.js');
    }
    
    async storeSecure(key, value) {
        // Store in worker context
        this.worker.postMessage({
            action: 'store',
            key: key,
            value: value
        });
    }
    
    async retrieveSecure(key) {
        return new Promise((resolve) => {
            this.worker.onmessage = (e) => {
                if (e.data.key === key) {
                    resolve(e.data.value);
                }
            };
            this.worker.postMessage({
                action: 'retrieve',
                key: key
            });
        });
    }
}
```

---

## المراقبة والقياس — Monitoring and Telemetry

**العربية:**
- سجل أحداث دورة حياة الجلسة (الإنشاء، التدوير، الإنهاء)
- استخدم تجزئة مملحة لمعرف الجلسة، ليس القيم الخام
- راقب للقوة الغاشمة على معرفات الجلسة
- راقب الاستخدام المتزامن الشاذ

**English:**
- Log session lifecycle events (creation, rotation, termination)
- Use salted hashes of the session ID, not raw values
- Monitor for brute force of session IDs
- Monitor anomalous concurrent usage

```python
# Python Session Monitoring
class UAESessionMonitor:
    """
    Monitor session activity for security events
    """
    
    @staticmethod
    def log_session_event(event_type: str, session_id: str, user_id: str, metadata: dict = None):
        """Log session event with hashed ID"""
        event = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'event_type': event_type,
            'session_hash': UAESessionManager.hash_session_id(session_id),
            'user_id': user_id,
            'metadata': metadata or {}
        }
        
        security_logger.info(json.dumps(event))
    
    @staticmethod
    def detect_concurrent_sessions(user_id: str, max_concurrent: int = 3):
        """Detect anomalous concurrent session usage"""
        # Query active sessions for user
        active_sessions = session_store.get_user_sessions(user_id)
        
        if len(active_sessions) > max_concurrent:
            audit_logger.log_anomaly(
                user_id=user_id,
                anomaly_type='excessive_concurrent_sessions',
                details={'session_count': len(active_sessions)}
            )
            
            # Optionally invalidate oldest sessions
            if len(active_sessions) > max_concurrent + 2:
                oldest = sorted(active_sessions, key=lambda s: s['created_at'])
                for session in oldest[:len(active_sessions) - max_concurrent]:
                    session_store.invalidate(session['id'])
```

---

## قائمة التحقق — Implementation Checklist

- [ ] معرفات الجلسة من CSPRNG (≥64 بت عشوائية)، معتمة، من جانب الخادم فقط
- [ ] أعلام ملفات تعريف الارتباط: `Secure` و`HttpOnly` و`SameSite` مضبوطة
- [ ] نطاق ومسار ضيقان
- [ ] HTTPS فقط مع HSTS؛ لا محتوى مختلط
- [ ] إعادة توليد المعرفات عند المصادقة وتغيير الامتيازات
- [ ] إبطال المعرفات القديمة
- [ ] مهلات خمول ومطلقة مفروضة من جانب الخادم
- [ ] تسجيل خروج كامل منفذ
- [ ] `Cache-Control: no-store` للاستجابات الحساسة
- [ ] البصمات من جانب الخادم والاستجابات القائمة على المخاطر
- [ ] لا تخزين من جانب العميل لرموز الجلسة
- [ ] إعدادات الإطار الافتراضية مُقوَّاة

---

## خطة الاختبار — Test Plan

- [ ] اختبار توليد معرفات الجلسة (العشوائية، الطول)
- [ ] اختبار أعلام ملفات تعريف الارتباط
- [ ] اختبار إعادة توليد الجلسة
- [ ] اختبار المهلات (الخمول والمطلقة)
- [ ] اختبار تسجيل الخروج (إبطال كامل)
- [ ] اختبار كشف سرقة الجلسة
- [ ] اختبار الاستجابة للمخاطر العالية
- [ ] اختبار القوة الغاشمة على معرفات الجلسة
- [ ] اختبار الاستخدام المتزامن

---

## مراجع — References

- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [OWASP Cookies Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cookies_Security_Cheat_Sheet.html)
- [NIST SP 800-63B - Session Management](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [UAE Information Assurance Framework](https://www.tra.gov.ae/)
