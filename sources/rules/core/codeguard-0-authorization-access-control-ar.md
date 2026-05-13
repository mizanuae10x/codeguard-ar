---
description: التفويض والتحكم بالوصول (RBAC/ABAC/ReBAC، IDOR، التعيين الجماعي، مصادقة المعاملات)
languages:
- c
- go
- java
- javascript
- php
- python
- ruby
- typescript
- yaml
tags:
- authorization
- access-control
- uae
alwaysApply: false
---

# التفويض والتحكم بالوصول — Authorization & Access Control

## نظرة عامة — Overview

فرض أقل امتياز (least privilege) وقرارات وصول دقيقة لكل طلب وكل مورد، ومنع IDOR والتعيين الجماعي (mass assignment)، وتوفير مصادقة قوية للمعاملات الحساسة.

Enforce least privilege and precise access decisions for every request and resource, prevent IDOR and mass assignment, and provide strong transaction authorization where necessary.

---

## المبادئ الأساسية — Core Principles

### 1. الرفض افتراضياً — Deny by Default

**العربية:**
- الافتراض لأي طلب وصول يجب أن يكون "رفض"
- منح الأذونات صراحةً للأدوار أو المستخدمين
- عندما لا تطابق قاعدة سماح → HTTP 403 Forbidden

**English:**
- The default for any access request should be 'deny'
- Explicitly grant permissions to roles or users
- When no allow rule matches, return HTTP 403 Forbidden

### 2. مبدأ أقل الامتياز — Principle of Least Privilege

**العربية:**
- امنح المستخدمين الحد الأدنى من الوصول المطلوب لأداء وظائفهم
- راجع الأذونات بانتظام للتأكد من عدم زيادتها
- أزل الوصول غير المستخدم (access revocation)

**English:**
- Grant users the minimum level of access required
- Regularly audit permissions to ensure they are not excessive
- Remove unused access

### 3. تحقق من الأذونات في كل طلب — Validate Permissions on Every Request

**العربية:**
- تحقق من التفويض لكل طلب فردي
- بغض النظر عن المصدر (AJAX، API، مباشر)
- استخدم middleware/filters لضمان التنفيذ المتسق

**English:**
- Check authorization for every single request
- Regardless of source (AJAX, API, direct)
- Use middleware/filters to ensure consistent enforcement

### 4. فضّل ABAC/ReBAC على RBAC — Prefer ABAC/ReBAC over RBAC

**العربية:**
- استخدم التحكم بالوصول المبني على السمات (ABAC)
- أو التحكم بالوصول المبني على العلاقات (ReBAC)
- للأذونات الدقيقة بدلاً من RBAC البسيط

**English:**
- Use Attribute-Based Access Control (ABAC)
- Or Relationship-Based Access Control (ReBAC)
- For fine-grained permissions instead of simple RBAC

---

## الضوابط النظامية — Systemic Controls

**العربية:**
- ركز التفويض عند حدود الخدمة عبر middleware/policies/filters
- نمذجة الأذونات على مستوى المورد (الملكية/الإيجار)
- فرض النطاق في استعلامات البيانات
- أعد استجابات عامة 403/404 لتجنب تسريب وجود المورد
- سجل جميع الرفض مع المستخدم والإجراء ومعرف المورد (غير PII)

**English:**
- Centralize authorization at service boundaries via middleware/policies/filters
- Model permissions at the resource level (ownership/tenancy)
- Enforce scoping in data queries
- Return generic 403/404 responses to avoid leaking resource existence
- Log all denials with user, action, resource identifier (non-PII), and rationale code

```python
# Python Authorization Middleware (UAE Context)
from functools import wraps
from flask import request, g

class UAEAuthorizationMiddleware:
    """
    UAE-compliant authorization middleware
    Enforces deny-by-default and comprehensive logging
    """
    
    def __init__(self, policy_engine, audit_logger):
        self.policy_engine = policy_engine
        self.audit_logger = audit_logger
    
    def authorize(self, action, resource_type, resource_id=None):
        """Decorator for endpoint authorization"""
        def decorator(f):
            @wraps(f)
            def wrapper(*args, **kwargs):
                user = g.current_user
                
                # Build context for ABAC decision
                context = {
                    'user': {
                        'id': user.id,
                        'roles': user.roles,
                        'department': user.department,
                        'clearance_level': user.clearance_level,
                        'is_uae_citizen': user.is_uae_citizen,
                        'emirates_id': user.emirates_id,
                    },
                    'resource': {
                        'type': resource_type,
                        'id': resource_id or kwargs.get('id'),
                        'owner': kwargs.get('owner_id'),
                        'classification': kwargs.get('classification', 'internal'),
                    },
                    'environment': {
                        'time': datetime.utcnow(),
                        'source_ip': request.remote_addr,
                        'is_business_hours': self.is_business_hours(),
                        'is_government_network': self.is_gov_network(request.remote_addr),
                    },
                    'action': action,
                }
                
                # Evaluate policy
                decision = self.policy_engine.evaluate(context)
                
                if not decision.allowed:
                    # Log denial
                    self.audit_logger.log_access_denied(
                        user_id=user.id,
                        action=action,
                        resource_type=resource_type,
                        resource_id=resource_id,
                        reason=decision.reason,
                        context=context
                    )
                    
                    # Return generic error
                    return {'error': 'Access denied'}, 403
                
                # Log approval for sensitive actions
                if action in ['DELETE', 'EXPORT', 'ADMIN']:
                    self.audit_logger.log_access_approved(
                        user_id=user.id,
                        action=action,
                        resource_type=resource_type,
                        resource_id=resource_id,
                        context=context
                    )
                
                return f(*args, **kwargs)
            return wrapper
        return decorator
```

---

## منع IDOR — Preventing IDOR

**العربية:**
- لا تثق أبداً بالمعرفات المقدمة من المستخدم وحدها
- تحقق دائماً من الوصول لكل كائن
- حل الموارد عبر استعلامات ذات نطاق مستخدم
- استخدم معرفات غير قابلة للتعداد (UUIDs) كدفاع إضافي

**English:**
- Never trust user-supplied identifiers alone
- Always verify access to each object instance
- Resolve resources through user-scoped queries
- Use non-enumerable identifiers (UUIDs) as defense-in-depth

```python
# Python IDOR Prevention
class UAEResourceAccess:
    """
    UAE-compliant resource access with IDOR prevention
    """
    
    @staticmethod
    def get_user_document(user, document_id):
        """
        Securely retrieve document with ownership verification
        """
        # WRONG: Direct lookup (vulnerable to IDOR)
        # document = Document.query.get(document_id)
        
        # CORRECT: Scoped query
        document = Document.query.filter_by(
            id=document_id,
            owner_id=user.id  # Enforce ownership
        ).first()
        
        if not document:
            # Return 404 (not 403) to avoid leaking existence
            raise NotFound('Document not found')
        
        # Additional UAE-specific checks
        if document.classification == 'CONFIDENTIAL':
            if not user.has_clearance('CONFIDENTIAL'):
                raise Forbidden('Insufficient clearance')
        
        return document
    
    @staticmethod
    def get_department_documents(user, department_id):
        """
        Retrieve documents for user's department
        """
        # Verify user belongs to department
        if user.department_id != department_id and not user.is_admin:
            raise Forbidden('Access denied')
        
        return Document.query.filter_by(
            department_id=department_id
        ).all()
```

---

## منع التعيين الجماعي — Preventing Mass Assignment

**العربية:**
- لا تربط أجسام الطلب مباشرة بالكائنات الحساسة
- اعرض فقط الحقول الآمنة عبر DTOs
- حافظ على قوائم السماح الصريحة للتصحيح/التحديث
- استخدم خصائص الإطار لحظر الحقول الحساسة

**English:**
- Do not bind request bodies directly to domain objects
- Expose only safe, editable fields via DTOs
- Maintain explicit allow-lists for patch/update
- Use framework features to block-list sensitive fields

```python
# Python DTO Pattern for Mass Assignment Prevention
from dataclasses import dataclass
from typing import Optional

@dataclass
class UserUpdateDTO:
    """
    Safe fields for user update
    Only these fields can be modified by users
    """
    full_name: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    preferred_language: Optional[str] = None  # ar/en
    
    # Explicitly excluded (admin only):
    # - role
    # - clearance_level
    # - department_id
    # - is_active
    # - emirates_id

class UAEUserService:
    """
    UAE-compliant user service with mass assignment protection
    """
    
    ALLOWED_UPDATE_FIELDS = {
        'full_name', 'email', 'phone', 'preferred_language'
    }
    
    ADMIN_ONLY_FIELDS = {
        'role', 'clearance_level', 'department_id', 
        'is_active', 'emirates_id'
    }
    
    def update_user(self, user_id: str, update_data: dict, updater: User) -> User:
        """
        Update user with strict field validation
        """
        user = User.query.get(user_id)
        if not user:
            raise NotFound('User not found')
        
        # Validate all provided fields
        for field in update_data.keys():
            if field in self.ADMIN_ONLY_FIELDS:
                if not updater.is_admin:
                    raise Forbidden(f'Field {field} requires admin privileges')
            elif field not in self.ALLOWED_UPDATE_FIELDS:
                raise BadRequest(f'Field {field} cannot be modified')
        
        # Apply updates safely
        for field, value in update_data.items():
            setattr(user, field, value)
        
        db.session.commit()
        
        # Log update
        audit_logger.log_user_update(
            user_id=user_id,
            updater_id=updater.id,
            fields_updated=list(update_data.keys())
        )
        
        return user
```

---

## مصادقة المعاملات (الترقية) — Transaction Authorization (Step-Up)

**العربية:**
- تتطلب عاملاً ثانياً للإجراءات الحساسة
- ما تراه هو ما توقع (What-You-See-Is-What-You-Sign)
- استخدم بيانات اعتماد فريدة ومحدودة الوقت لكل معاملة
- ارفض عند تغيير البيانات منتصف التدفق
- فرض طريقة المصادقة من جانب الخادم

**English:**
- Require a second factor for sensitive actions
- What-You-See-Is-What-You-Sign
- Use unique, time-limited authorization credentials per transaction
- Reject on data changes mid-flow
- Enforce authorization method server-side

```python
# Python Transaction Authorization
import secrets
import hashlib
from datetime import datetime, timedelta

class UAETransactionAuth:
    """
    UAE-compliant transaction authorization (step-up)
    """
    
    TOKEN_EXPIRY_MINUTES = 5
    MAX_ATTEMPTS = 3
    
    def __init__(self, mfa_service, audit_logger):
        self.mfa_service = mfa_service
        self.audit_logger = audit_logger
    
    def initiate_transaction(self, user, transaction_details):
        """
        Initiate sensitive transaction with step-up auth
        """
        # Generate transaction token
        token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        
        # Store transaction context
        transaction = Transaction.create(
            user_id=user.id,
            details=transaction_details,
            token_hash=token_hash,
            expires_at=datetime.utcnow() + timedelta(minutes=self.TOKEN_EXPIRY_MINUTES),
            status='pending_auth',
            attempt_count=0
        )
        
        # Request MFA verification
        self.mfa_service.send_challenge(
            user=user,
            context={
                'transaction_id': transaction.id,
                'amount': transaction_details.get('amount'),
                'currency': transaction_details.get('currency', 'AED'),
                'recipient': transaction_details.get('recipient'),
            }
        )
        
        return {
            'transaction_id': transaction.id,
            'auth_token': token,  # Single-use, short-lived
            'expires_at': transaction.expires_at,
        }
    
    def authorize_transaction(self, transaction_id, auth_token, mfa_code):
        """
        Authorize transaction with MFA
        """
        transaction = Transaction.query.get(transaction_id)
        
        if not transaction:
            raise NotFound('Transaction not found')
        
        if transaction.status != 'pending_auth':
            raise BadRequest('Transaction not awaiting authorization')
        
        if transaction.expires_at < datetime.utcnow():
            transaction.status = 'expired'
            db.session.commit()
            raise BadRequest('Transaction authorization expired')
        
        # Verify token
        token_hash = hashlib.sha256(auth_token.encode()).hexdigest()
        if token_hash != transaction.token_hash:
            transaction.attempt_count += 1
            if transaction.attempt_count >= self.MAX_ATTEMPTS:
                transaction.status = 'blocked'
                db.session.commit()
                raise Forbidden('Transaction blocked due to failed attempts')
            db.session.commit()
            raise Forbidden('Invalid authorization token')
        
        # Verify MFA
        if not self.mfa_service.verify_code(transaction.user, mfa_code):
            transaction.attempt_count += 1
            db.session.commit()
            raise Forbidden('Invalid MFA code')
        
        # Check transaction details haven't changed
        current_details = self.get_current_transaction_details(transaction)
        if current_details != transaction.details:
            transaction.status = 'rejected'
            db.session.commit()
            raise Forbidden('Transaction details changed during authorization')
        
        # Mark as authorized
        transaction.status = 'authorized'
        transaction.authorized_at = datetime.utcnow()
        db.session.commit()
        
        # Log successful authorization
        self.audit_logger.log_transaction_authorized(
            transaction_id=transaction.id,
            user_id=transaction.user_id,
            details=transaction.details
        )
        
        return {'status': 'authorized', 'transaction_id': transaction.id}
```

---

## الاختبار والأتمتة — Testing and Automation

**العربية:**
- حافظ على مصفوفة تفويض (YAML/JSON)
- اكتب اختبارات تكامل تكرر المصفوفة
- اختبر رموز الأدوار وتأكد من النتائج
- اختبر الحالات السلبية: معرفات مبادلة، أدوار مخفضة، نطاقات مفقودة

**English:**
- Maintain an authorization matrix (YAML/JSON)
- Automate integration tests that iterate the matrix
- Test role tokens and assert allow/deny results
- Test negative cases: swapped IDs, downgraded roles, missing scopes

```yaml
# Authorization Matrix Example
authorization_matrix:
  - endpoint: /api/v1/documents/{id}
    methods: [GET, PUT, DELETE]
    resources:
      - type: document
        ownership: self
    roles:
      CITIZEN:
        GET: allow
        PUT: allow
        DELETE: deny
      GOVERNMENT_EMPLOYEE:
        GET: allow
        PUT: allow  # If in same department
        DELETE: deny
      ADMIN:
        GET: allow
        PUT: allow
        DELETE: allow
    
  - endpoint: /api/v1/citizens/{emirates_id}
    methods: [GET]
    resources:
      - type: citizen_record
        classification: CONFIDENTIAL
    roles:
      CITIZEN:
        GET: deny  # Can't access other citizens' data
      GOVERNMENT_EMPLOYEE:
        GET: conditional  # If clearance matches and department needs access
      ADMIN:
        GET: allow
```

---

## قائمة التحقق — Implementation Checklist

- [ ] Middleware/policies تفرض الرفض افتراضياً
- [ ] فحوصات الموارد على كل نقطة نهاية
- [ ] نطاق الاستعلام يضمن وصول المستخدمين فقط للصفوف/الكائنات المسموح بها
- [ ] DTOs وقوائم السماح تمنع التعيين الجماعي
- [ ] الحقول الحساسة غير قابلة للربط أبداً
- [ ] مصادقة الترقية (step-up) للعمليات الحساسة
- [ ] بيانات اعتماد فريدة وقصيرة العمر لكل معاملة
- [ ] مصفوفة التفويض تقود اختبارات CI
- [ ] الفشل في الاختبارات يمنع الدمج
- [ ] تسجيل جميع الرفض مع السياق
- [ ] استجابات عامة (403/404) لتجنب تسريب المعلومات
- [ ] مراجعة دورية للأذونات
- [ ] إلغاء الوصول غير المستخدم

---

## خطة الاختبار — Test Plan

- [ ] اختبارات تكامل للمصفوفة الكاملة
- [ ] اختبار رموز الأدوار المختلفة
- [ ] اختبار انتهاء الصلاحية/الإبطال
- [ ] اختبارات سلبية: معرفات مبادلة
- [ ] أدوار مخفضة
- [ ] نطاقات مفقودة
- [ ] محاولات تجاوز
- [ ] اختبار IDOR: الوصول إلى موارد المستخدمين الآخرين
- [ ] اختبار mass assignment: محاولة تعديل الحقول المحظورة
- [ ] اختبار step-up: محاولة تنفيذ معاملة بدون MFA

---

## مراجع — References

- [OWASP Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)
- [NIST SP 800-178 - ABAC](https://csrc.nist.gov/publications/detail/sp/800-178/final)
- [UAE Information Assurance Framework](https://www.tra.gov.ae/)
- [Google Zanzibar Paper (ReBAC)](https://research.google/pubs/pub48190/)
