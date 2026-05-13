---
description: التسجيل والمراقبة (القياس المنظم، التنقيح، النزاهة، الكشف والتنبيه)
languages:
- c
- javascript
- yaml
- python
- java
tags:
- privacy
- monitoring
- uae
alwaysApply: false
---

# التسجيل والمراقبة — Logging & Monitoring

## نظرة عامة — Overview

أنشئ قياساً منظماً وواعياً بالخصوصية يدعم الكشف والاستجابة والتحقيق الجنائي دون كشف الأسرار.

Produce structured, privacy-aware telemetry that supports detection, response, and forensics without exposing secrets.

---

## ما يجب تسجيله — What to Log

**العربية:**
- أحداث المصادقة/التفويض
- إجراءات المسؤول
- تغييرات الإعدادات
- وصول البيانات الحساسة
- فشل التحقق من المدخلات
- أخطاء الأمان

**English:**
- Authn/authz events
- Admin actions
- Config changes
- Sensitive data access
- Input validation failures
- Security errors

### الحقول المطلوبة — Required Fields

| الحقل | الوصف | مثال |
|-------|-------|------|
| timestamp | UTC RFC3339 | `2026-05-13T10:30:00Z` |
| correlation_id | معرف الطلب | `req_abc123` |
| session_hash | تجزئة الجلسة | `a1b2c3...` |
| user_id | معرف المستخدم | `user_123` |
| source_ip | عنوان IP | `10.0.1.100` |
| user_agent | وكيل المستخدم | `Mozilla/5.0...` |
| event_type | نوع الحدث | `AUTH_SUCCESS` |
| severity | الخطورة | `INFO` |

```python
# Python Structured Logging for UAE
import json
import logging
import hashlib
from datetime import datetime
from enum import Enum
from typing import Optional, Dict, Any

class LogEventType(Enum):
    AUTH_SUCCESS = "AUTH_SUCCESS"
    AUTH_FAILURE = "AUTH_FAILURE"
    AUTH_MFA = "AUTH_MFA"
    AUTH_LOGOUT = "AUTH_LOGOUT"
    PRIVILEGE_ELEVATION = "PRIVILEGE_ELEVATION"
    ADMIN_ACTION = "ADMIN_ACTION"
    CONFIG_CHANGE = "CONFIG_CHANGE"
    DATA_ACCESS = "DATA_ACCESS"
    DATA_EXPORT = "DATA_EXPORT"
    VALIDATION_FAILURE = "VALIDATION_FAILURE"
    SECURITY_ERROR = "SECURITY_ERROR"
    SESSION_ROTATION = "SESSION_ROTATION"
    SESSION_INVALIDATION = "SESSION_INVALIDATION"

class LogSeverity(Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"

class UAELogger:
    """
    UAE-compliant structured logger
    """
    
    def __init__(self, service_name: str, environment: str):
        self.service_name = service_name
        self.environment = environment
        self.logger = logging.getLogger(f"uae.{service_name}")
        
        # Configure structured logging
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter('%(message)s'))
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)
    
    def log_event(
        self,
        event_type: LogEventType,
        severity: LogSeverity,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        source_ip: Optional[str] = None,
        correlation_id: Optional[str] = None
    ):
        """Log structured security event"""
        
        # Build log entry
        log_entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "service": self.service_name,
            "environment": self.environment,
            "event_type": event_type.value,
            "severity": severity.value,
            "correlation_id": correlation_id or self._generate_correlation_id(),
        }
        
        # Add user context (hashed for privacy)
        if user_id:
            log_entry["user_id_hash"] = self._hash_identifier(user_id)
        
        if session_id:
            log_entry["session_hash"] = self._hash_identifier(session_id)
        
        if source_ip:
            log_entry["source_ip"] = source_ip
        
        # Add details (sanitized)
        if details:
            log_entry["details"] = self._sanitize_details(details)
        
        # Log based on severity
        log_method = getattr(self.logger, severity.value.lower())
        log_method(json.dumps(log_entry, ensure_ascii=False))
        
        # Alert on critical events
        if severity in [LogSeverity.ERROR, LogSeverity.CRITICAL]:
            self._send_alert(log_entry)
    
    def _hash_identifier(self, identifier: str) -> str:
        """Hash identifier for privacy"""
        return hashlib.sha256(
            f"{identifier}:{self.service_name}".encode()
        ).hexdigest()[:16]
    
    def _generate_correlation_id(self) -> str:
        """Generate correlation ID"""
        import uuid
        return f"req_{uuid.uuid4().hex[:12]}"
    
    def _sanitize_details(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize details to prevent log injection"""
        sanitized = {}
        
        for key, value in details.items():
            if isinstance(value, str):
                # Remove control characters
                value = ''.join(char for char in value if ord(char) >= 32)
                # Truncate long strings
                value = value[:1000]
            
            sanitized[key] = value
        
        return sanitized
    
    def _send_alert(self, log_entry: dict):
        """Send alert for critical events"""
        # Implementation depends on alerting system
        pass

# Usage example
logger = UAELogger("payment-service", "production")

logger.log_event(
    event_type=LogEventType.AUTH_FAILURE,
    severity=LogSeverity.WARNING,
    user_id="user123",
    session_id="sess456",
    source_ip="10.0.1.100",
    details={
        "reason": "invalid_password",
        "attempt_count": 3,
        "mfa_required": True
    }
)
```

---

## كيفية التسجيل — How to Log

**العربية:**
- سجلات منظمة (JSON) بأسماء حقول مستقرة
- تجنب النص الحر للإشارات الحرجة
- نظف جميع مدخلات السجل لمنع حقن السجل
- استبدل/رمم الأسرار والحقول الحساسة
- لا تسجل الاعتمادات أو الرموز أو أكواد الاسترداد

**English:**
- Structured logs (JSON) with stable field names
- Avoid free-form text for critical signals
- Sanitize all log inputs to prevent log injection
- Redact/tokenize secrets and sensitive fields
- Never log credentials, tokens, or recovery codes

```python
# Python Log Redaction
import re
from typing import Any

class UAELogRedactor:
    """
    Redact sensitive data from logs
    """
    
    # Patterns to redact
    SENSITIVE_PATTERNS = {
        'password': re.compile(r'(?i)(password|passwd|pwd)\s*[:=]\s*\S+'),
        'token': re.compile(r'(?i)(token|bearer)\s*[:=]\s*\S+'),
        'api_key': re.compile(r'(?i)(api[_-]?key|apikey)\s*[:=]\s*\S+'),
        'credit_card': re.compile(r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b'),
        'emirates_id': re.compile(r'784-\d{4}-\d{7}-\d{1}'),
        'phone': re.compile(r'\+971\s?\d{2}\s?\d{3}\s?\d{4}'),
        'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
    }
    
    @classmethod
    def redact(cls, message: str) -> str:
        """Redact sensitive information from log message"""
        redacted = message
        
        for pattern_name, pattern in cls.SENSITIVE_PATTERNS.items():
            redacted = pattern.sub(f'[{pattern_name}_REDACTED]', redacted)
        
        return redacted
    
    @classmethod
    def redact_dict(cls, data: dict) -> dict:
        """Redact sensitive fields from dictionary"""
        redacted = {}
        
        for key, value in data.items():
            # Check if key indicates sensitive data
            if any(sensitive in key.lower() for sensitive in [
                'password', 'token', 'secret', 'key', 'credential',
                'credit_card', 'emirates_id', 'phone', 'email'
            ]):
                redacted[key] = '[REDACTED]'
            elif isinstance(value, str):
                redacted[key] = cls.redact(value)
            elif isinstance(value, dict):
                redacted[key] = cls.redact_dict(value)
            else:
                redacted[key] = value
        
        return redacted

# Example usage
raw_log = {
    "user": "john.doe@example.com",
    "action": "login",
    "password": "secret123",
    "api_key": "sk_live_abc123",
    "emirates_id": "784-1234-5678901-2",
    "phone": "+971 50 123 4567",
    "request": "GET /api/users"
}

redacted = UAELogRedactor.redact_dict(raw_log)
# Result: sensitive fields replaced with [REDACTED]
```

---

## الكشف والتنبيه — Detection & Alerting

**العربية:**
- أنشئ تنبيهات لشذوذ المصادقة
- حشو الاعتمادات، السفر المستحيل
- تغييرات الامتيازات
- الفشل المفرط
- مؤشرات SSRF
- أنماط تسريب البيانات

**English:**
- Build alerts for auth anomalies
- Credential stuffing patterns, impossible travel
- Privilege changes
- Excessive failures
- SSRF indicators
- Data exfil patterns

```python
# Python Alert Detection
from datetime import datetime, timedelta
from collections import defaultdict

class UAEAlertDetector:
    """
    Detect security anomalies and trigger alerts
    """
    
    def __init__(self):
        self.failure_counts = defaultdict(int)
        self.last_alert_time = {}
    
    def detect_credential_stuffing(self, events: list) -> bool:
        """Detect credential stuffing attack"""
        # Group by time window
        window_start = datetime.utcnow() - timedelta(minutes=5)
        recent_failures = [
            e for e in events
            if e['event_type'] == 'AUTH_FAILURE'
            and e['timestamp'] > window_start
        ]
        
        # Count unique IPs
        unique_ips = len(set(e['source_ip'] for e in recent_failures))
        
        if len(recent_failures) > 50 and unique_ips > 5:
            return True
        
        return False
    
    def detect_impossible_travel(self, events: list) -> bool:
        """Detect impossible travel (login from distant locations)"""
        # Sort by timestamp
        sorted_events = sorted(events, key=lambda e: e['timestamp'])
        
        for i in range(1, len(sorted_events)):
            prev_event = sorted_events[i-1]
            curr_event = sorted_events[i]
            
            # Calculate time difference
            time_diff = (curr_event['timestamp'] - prev_event['timestamp']).total_seconds()
            
            # Calculate distance (simplified - would use geoip in production)
            distance = self._calculate_distance(
                prev_event['source_ip'],
                curr_event['source_ip']
            )
            
            # Check if impossible (faster than 900 km/h)
            if distance > 0 and time_diff > 0:
                speed_kmh = (distance / time_diff) * 3600
                if speed_kmh > 900:
                    return True
        
        return False
    
    def detect_privilege_escalation(self, events: list) -> bool:
        """Detect suspicious privilege escalation"""
        # Look for rapid privilege changes
        privilege_events = [
            e for e in events
            if e['event_type'] == 'PRIVILEGE_ELEVATION'
        ]
        
        if len(privilege_events) > 3:
            # Check if within short time window
            time_span = (
                privilege_events[-1]['timestamp'] - 
                privilege_events[0]['timestamp']
            ).total_seconds()
            
            if time_span < 300:  # 5 minutes
                return True
        
        return False
    
    def detect_data_exfiltration(self, events: list) -> bool:
        """Detect potential data exfiltration"""
        # Look for large data access patterns
        data_access_events = [
            e for e in events
            if e['event_type'] == 'DATA_ACCESS'
        ]
        
        # Count records accessed
        total_records = sum(
            e.get('details', {}).get('record_count', 0)
            for e in data_access_events
        )
        
        if total_records > 10000:
            return True
        
        return False
    
    def _calculate_distance(self, ip1: str, ip2: str) -> float:
        """Calculate distance between two IPs (placeholder)"""
        # In production, use GeoIP database
        return 0.0
    
    def send_alert(self, alert_type: str, details: dict):
        """Send security alert"""
        alert = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "alert_type": alert_type,
            "severity": "HIGH",
            "details": details,
        }
        
        # Send to alerting system
        # Implementation depends on your alerting infrastructure
        pass
```

---

## التخزين والحماية — Storage & Protection

**العربية:**
- عزل تخزين السجلات (قسم/قاعدة بيانات منفصلة)
- أذونات ملف/دليل صارمة
- تخزين خارج المواقع المتاحة للويب
- مزامنة الوقت عبر الأنظمة
- استخدم بروتوكولات آمنة للنقل
- نفذ كشف العبث والمراقبة

**English:**
- Isolate log storage (separate partition/database)
- Strict file/directory permissions
- Store outside web-accessible locations
- Synchronize time across systems
- Use secure protocols for transmission
- Implement tamper detection and monitoring

```yaml
# Log Storage Configuration
logging:
  # Structured JSON logging
  format: json
  
  # Storage configuration
  storage:
    type: elasticsearch
    hosts: ["https://logs.uae.gov.ae:9200"]
    
    # Security settings
    ssl:
      enabled: true
      verification_mode: certificate
      certificate_authorities: ["/etc/ssl/certs/ca.crt"]
    
    # Authentication
    username: "log_writer"
    password: "${LOGS_PASSWORD}"  # From secrets manager
  
  # Retention policy
  retention:
    hot: 7d      # Fast storage
    warm: 30d    # Standard storage
    cold: 365d   # Archive storage
    delete: 2555d  # 7 years for government
  
  # Integrity
  integrity:
    enabled: true
    algorithm: sha256
    verification: hourly
  
  # Access control
  access:
    read_roles: ["security_analyst", "auditor"]
    write_roles: ["log_writer"]
    admin_roles: ["security_admin"]
```

---

## الخصوصية والامتثال — Privacy & Compliance

**العربية:**
- حافظ على جرد البيانات والتصنيف
- تقليل البيانات الشخصية في السجلات
- الالتزام بسياسات الاحتفاظ والحذف
- توفير آليات لتتبع وحذف بيانات السجل المرتبطة بالمستخدم

**English:**
- Maintain data inventory and classification
- Minimize personal data in logs
- Honor retention and deletion policies
- Provide mechanisms to trace and delete user-linked log data

```python
# Python Privacy Compliance
class UAEPrivacyCompliance:
    """
    Handle privacy compliance for UAE government logs
    """
    
    RETENTION_PERIODS = {
        'AUTH_EVENTS': 2555,      # 7 years
        'ADMIN_ACTIONS': 2555,    # 7 years
        'SECURITY_INCIDENTS': 2555,  # 7 years
        'GENERAL_ACCESS': 365,    # 1 year
        'DEBUG': 30,              # 30 days
    }
    
    @classmethod
    def get_retention_period(cls, log_type: str) -> int:
        """Get retention period in days"""
        return cls.RETENTION_PERIODS.get(log_type, 365)
    
    @classmethod
    def should_delete(cls, log_entry: dict) -> bool:
        """Check if log should be deleted based on retention"""
        log_type = log_entry.get('log_type', 'GENERAL_ACCESS')
        retention = cls.get_retention_period(log_type)
        
        log_date = datetime.fromisoformat(log_entry['timestamp'])
        age_days = (datetime.utcnow() - log_date).days
        
        return age_days > retention
    
    @classmethod
    def delete_user_logs(cls, user_id: str, log_store):
        """Delete all logs associated with user (GDPR/UAE privacy)"""
        user_hash = hashlib.sha256(user_id.encode()).hexdigest()
        
        # Query logs by user hash
        logs = log_store.query(f"user_id_hash:{user_hash}")
        
        for log in logs:
            log_store.delete(log['id'])
        
        # Log the deletion
        audit_logger.log_event(
            event_type="USER_LOGS_DELETED",
            severity="INFO",
            details={
                "user_id_hash": user_hash,
                "logs_deleted": len(logs)
            }
        )
```

---

## قائمة التحقق — Implementation Checklist

- [ ] التسجيل JSON مُمكّن
- [ ] تطهير حقن السجل نشط
- [ ] مرشحات التنقيح نشطة
- [ ] معرفات الارتباط على جميع الطلبات
- [ ] تخزين السجلات معزول مع كشف العبث
- [ ] خط أنابيب السجلات المركزي مع حماية النزاهة
- [ ] الاحتفاظ مُكوَّن
- [ ] تنبيهات الأمان مُحددة ومُختبرة
- [ ] لوحات المعلومات والتقارير جاهزة
- [ ] مزامنة الوقت عبر الأنظمة
- [ ] بروتوكولات آمنة للنقل
- [ ] سياسات الاحتفاظ مُطبَّقة
- [ ] آليات حذف بيانات المستخدم

---

## خطة الاختبار — Test Plan

- [ ] اختبار الحقول المطلوبة موجودة
- [ ] اختبار التنقيح يعمل
- [ ] اختبار عدم تسريب الأسرار
- [ ] اختبار كشف العبث
- [ ] اختبار التنبيهات
- [ ] اختبار الاحتفاظ والحذف
- [ ] اختبار الخصوصية
- [ ] اختبار الأداء تحت الحمل

---

## مراجع — References

- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
- [NIST SP 800-92 - Log Management](https://csrc.nist.gov/publications/detail/sp/800-92/final)
- [UAE Information Assurance Framework](https://www.tra.gov.ae/)
- [GDPR Logging Requirements](https://gdpr.eu/article-30-records-of-processing/)
