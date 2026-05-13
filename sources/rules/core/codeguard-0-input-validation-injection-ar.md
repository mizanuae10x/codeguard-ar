---
description: التحقق من المدخلات والدفاع ضد الحقن (SQL/SOQL/LDAP/OS)، التحديد المعلمي، تلوث النموذج
languages:
- apex
- c
- go
- html
- java
- javascript
- php
- powershell
- python
- ruby
- shell
- sql
- typescript
tags:
- web
- injection
- uae
alwaysApply: false
---

# التحقق من المدخلات والدفاع ضد الحقن — Input Validation & Injection Defense

## نظرة عامة — Overview

تأكد من أن المدخلات غير الموثوقة يتم التحقق منها ولا تُفسر أبداً ككود. امنع الحقن عبر SQL وLDAP وأوامر نظام التشغيل والقوالب ورسوم كائنات JavaScript.

Ensure untrusted input is validated and never interpreted as code. Prevent injection across SQL, LDAP, OS commands, templating, and JavaScript runtime object graphs.

---

## الاستراتيجية الأساسية — Core Strategy

**العربية:**
- تحقق مبكراً عند حدود الثقة باستخدام التحقق الإيجابي (قائمة السماح) والتوحيد القياسي
- تعامل مع جميع المدخلات غير الموثوقة كبيانات، وليس ككود
- استخدم واجهات برمجة آمنة تفصل الكود عن البيانات
- حدد الاستعلامات/الأوامر معلمياً؛ الهروب فقط كملاذ أخير

**English:**
- Validate early at trust boundaries with positive (allow-list) validation and canonicalization
- Treat all untrusted input as data, never as code
- Use safe APIs that separate code from data
- Parameterize queries/commands; escape only as last resort and context-specific

---

## دليل التحقق — Validation Playbook

### التحقق النحوي — Syntactic Validation

**العربية:**
- فرض التنسيق والنوع والنطاقات والأطوال لكل حقل
- استخدم regex مع مراسي (^$) للتحقق من السلاسل الكاملة
- احذر من ReDoS (التحققات المعقدة جداً)

**English:**
- Enforce format, type, ranges, and lengths for each field
- Use regex with anchors (^$) for complete string validation
- Beware ReDoS (overly complex patterns)

```python
# Python UAE Input Validation
import re
from dataclasses import dataclass
from typing import Optional

@dataclass
class UAEInputValidator:
    """
    UAE-specific input validator
    """
    
    # UAE Emirates ID pattern: 784-XXXX-XXXXXXX-X
    EMIRATES_ID_PATTERN = re.compile(r'^784-\d{4}-\d{7}-\d{1}$')
    
    # UAE phone number pattern
    PHONE_PATTERN = re.compile(r'^\+971\s?(?:50|52|54|55|56|58)\s?\d{3}\s?\d{4}$')
    
    # Email pattern for government domains
    GOV_EMAIL_PATTERN = re.compile(r'^[a-zA-Z0-9._%+-]+@(?:gov\.ae|\.uae)$')
    
    @classmethod
    def validate_emirates_id(cls, emirates_id: str) -> bool:
        """Validate UAE Emirates ID format"""
        if not emirates_id:
            return False
        return bool(cls.EMIRATES_ID_PATTERN.match(emirates_id))
    
    @classmethod
    def validate_phone(cls, phone: str) -> bool:
        """Validate UAE phone number"""
        if not phone:
            return False
        return bool(cls.PHONE_PATTERN.match(phone))
    
    @classmethod
    def validate_email(cls, email: str, allow_gov_only: bool = False) -> bool:
        """Validate email address"""
        if not email or len(email) > 254:
            return False
        
        if allow_gov_only:
            return bool(cls.GOV_EMAIL_PATTERN.match(email))
        
        # General email validation
        pattern = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
        return bool(pattern.match(email))
    
    @classmethod
    def sanitize_input(cls, input_str: str, max_length: int = 1000) -> str:
        """Sanitize general input"""
        if not input_str:
            return ""
        
        # Truncate to max length
        sanitized = input_str[:max_length]
        
        # Remove null bytes
        sanitized = sanitized.replace('\x00', '')
        
        # Normalize Unicode
        import unicodedata
        sanitized = unicodedata.normalize('NFKC', sanitized)
        
        return sanitized
```

### التحقق الدلالي — Semantic Validation

**العربية:**
- فرض قواعد العمل (مثال: تاريخ البداية ≤ تاريخ النهاية)
- قوائم السماح للقيم المعدودة (enums)
- التحقق من العلاقات المنطقية بين الحقول

**English:**
- Enforce business rules (e.g., start ≤ end date)
- Allow-lists for enumerated values
- Validate logical relationships between fields

```python
# Python Semantic Validation
from datetime import datetime, timedelta
from typing import Optional

class UAESemanticValidator:
    """
    UAE business rule validation
    """
    
    @staticmethod
    def validate_date_range(
        start_date: datetime,
        end_date: datetime,
        max_duration_days: int = 365
    ) -> tuple[bool, Optional[str]]:
        """Validate date range"""
        if start_date > end_date:
            return False, "Start date must be before end date"
        
        duration = (end_date - start_date).days
        if duration > max_duration_days:
            return False, f"Duration exceeds maximum of {max_duration_days} days"
        
        if end_date > datetime.now() + timedelta(days=365*5):
            return False, "End date too far in the future"
        
        return True, None
    
    @staticmethod
    def validate_transaction_amount(
        amount: float,
        user_clearance: str,
        daily_limit: float = 50000.0
    ) -> tuple[bool, Optional[str]]:
        """Validate transaction amount based on user clearance"""
        limits = {
            'STANDARD': 10000,
            'PREMIUM': 50000,
            'VIP': 100000,
            'GOVERNMENT': 1000000,
        }
        
        user_limit = limits.get(user_clearance, 1000)
        
        if amount <= 0:
            return False, "Amount must be positive"
        
        if amount > user_limit:
            return False, f"Amount exceeds limit of {user_limit} AED for {user_clearance} users"
        
        return True, None
```

---

## منع حقن SQL — SQL Injection Prevention

**العربية:**
- استخدم العبارات المُحضَّرة والاستعلامات المُحدَّدة معلمياً لـ 100% من الوصول إلى البيانات
- استخدم متغيرات الربط لأي بناء SQL ديناميكي
- لا تسلسل أبداً مدخلات المستخدم في SQL
- تفضل مستخدمي قاعدة البيانات ذوي الامتياز الأدنى

**English:**
- Use prepared statements and parameterized queries for 100% of data access
- Use bind variables for any dynamic SQL construction
- Never concatenate user input into SQL
- Prefer least-privilege DB users

```python
# Python SQL Parameterization
import psycopg2
from psycopg2.extras import RealDictCursor

class UAEDatabaseService:
    """
    UAE-compliant database service with SQL injection prevention
    """
    
    def __init__(self, connection_string: str):
        self.connection_string = connection_string
    
    def get_citizen_by_emirates_id(self, emirates_id: str):
        """
        Securely retrieve citizen by Emirates ID
        """
        # Validate input first
        if not UAEInputValidator.validate_emirates_id(emirates_id):
            raise ValueError("Invalid Emirates ID format")
        
        with psycopg2.connect(self.connection_string) as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                # SAFE: Parameterized query
                cur.execute(
                    """
                    SELECT id, full_name, emirates_id, date_of_birth
                    FROM citizens
                    WHERE emirates_id = %s
                    AND status = 'active'
                    """,
                    (emirates_id,)  # Parameter bound safely
                )
                
                return cur.fetchone()
    
    def search_documents(self, document_type: str, department_id: int, user_clearance: str):
        """
        Securely search documents with multiple parameters
        """
        # Validate inputs
        allowed_doc_types = ['PASSPORT', 'VISA', 'RESIDENCY', 'DRIVING_LICENSE']
        if document_type not in allowed_doc_types:
            raise ValueError("Invalid document type")
        
        if not isinstance(department_id, int) or department_id <= 0:
            raise ValueError("Invalid department ID")
        
        with psycopg2.connect(self.connection_string) as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                # SAFE: All parameters bound
                cur.execute(
                    """
                    SELECT d.id, d.document_number, d.status, d.issue_date
                    FROM documents d
                    JOIN departments dep ON d.department_id = dep.id
                    WHERE d.document_type = %s
                    AND d.department_id = %s
                    AND d.clearance_level <= (
                        SELECT clearance_value 
                        FROM clearance_levels 
                        WHERE name = %s
                    )
                    AND d.status = 'active'
                    ORDER BY d.issue_date DESC
                    LIMIT 100
                    """,
                    (document_type, department_id, user_clearance)
                )
                
                return cur.fetchall()
    
    def unsafe_example(self, user_input: str):
        """
        UNSAFE: Do not use this pattern!
        """
        # DANGEROUS: String concatenation
        query = f"SELECT * FROM users WHERE name = '{user_input}'"
        # This is vulnerable to SQL injection!
```

---

## منع حقن LDAP — LDAP Injection Prevention

**العربية:**
- طبق الهروب المناسب للسياق دائماً
- هروب DN لـ `\ # + < > , ; " =` والمسافات البادئة/النهائية
- هروب الفلتر لـ `* ( ) \ NUL`
- تحقق من المدخلات بقوائم السماح قبل بناء الاستعلامات

**English:**
- Always apply context-appropriate escaping
- DN escaping for `\ # + < > , ; " =` and leading/trailing spaces
- Filter escaping for `* ( ) \ NUL`
- Validate inputs with allow-lists before constructing queries

```python
# Python LDAP Injection Prevention
import ldap
from ldap.filter import escape_filter_chars

class UAELDAPService:
    """
    UAE-compliant LDAP service with injection prevention
    """
    
    def __init__(self, ldap_uri: str, bind_dn: str, bind_password: str):
        self.ldap_uri = ldap_uri
        self.bind_dn = bind_dn
        self.bind_password = bind_password
    
    def search_user(self, emirates_id: str):
        """
        Securely search for user in LDAP
        """
        # Validate Emirates ID
        if not UAEInputValidator.validate_emirates_id(emirates_id):
            raise ValueError("Invalid Emirates ID")
        
        # Escape the filter value
        escaped_id = escape_filter_chars(emirates_id)
        
        # Build safe filter
        search_filter = f"(uaeEmiratesID={escaped_id})"
        
        conn = ldap.initialize(self.ldap_uri)
        conn.simple_bind_s(self.bind_dn, self.bind_password)
        
        try:
            result = conn.search_s(
                "ou=users,dc=uae,dc=gov",
                ldap.SCOPE_SUBTREE,
                search_filter,
                ['cn', 'mail', 'department', 'clearanceLevel']
            )
            return result
        finally:
            conn.unbind_s()
    
    def authenticate_user(self, username: str, password: str):
        """
        Authenticate user with LDAP
        """
        # Validate username (allow-list)
        if not re.match(r'^[a-zA-Z0-9._-]+$', username):
            raise ValueError("Invalid username format")
        
        # Escape username for DN construction
        escaped_username = escape_filter_chars(username)
        
        user_dn = f"uid={escaped_username},ou=users,dc=uae,dc=gov"
        
        try:
            conn = ldap.initialize(self.ldap_uri)
            conn.simple_bind_s(user_dn, password)
            conn.unbind_s()
            return True
        except ldap.INVALID_CREDENTIALS:
            return False
```

---

## الدفاع ضد حقن أوامر نظام التشغيل — OS Command Injection Defense

**العربية:**
- فضّل واجهات برمجة مدمجة بدلاً من استدعاء الصدفة
- إذا كان لا بد، استخدم تنفيذ منظم يفصل الأمر والمعاملات
- لا تستدعِ الصدفة أبداً
- قم بقائمة سماح صارمة للأوامر والمعاملات

**English:**
- Prefer built-in APIs instead of shelling out
- If unavoidable, use structured execution separating command and arguments
- Do not invoke shells
- Strictly allow-list commands and validate arguments

```python
# Python OS Command Injection Prevention
import subprocess
import shlex
import re

class UAECommandExecutor:
    """
    UAE-compliant safe command execution
    """
    
    ALLOWED_COMMANDS = {
        'ls': ['/bin/ls'],
        'cat': ['/bin/cat'],
        'grep': ['/bin/grep'],
        'head': ['/usr/bin/head'],
        'tail': ['/usr/bin/tail'],
        'wc': ['/usr/bin/wc'],
    }
    
    @classmethod
    def execute_safe(cls, command_name: str, arguments: list, working_dir: str = None):
        """
        Execute command safely with strict validation
        """
        # Validate command is in allow-list
        if command_name not in cls.ALLOWED_COMMANDS:
            raise ValueError(f"Command '{command_name}' not in allow-list")
        
        command_path = cls.ALLOWED_COMMANDS[command_name][0]
        
        # Validate all arguments
        validated_args = []
        for arg in arguments:
            # Only allow alphanumeric and safe characters
            if not re.match(r'^[a-zA-Z0-9_./-]+$', arg):
                raise ValueError(f"Invalid argument: {arg}")
            validated_args.append(arg)
        
        # Build command list (no shell invocation)
        cmd = [command_path] + validated_args
        
        # Execute with restricted environment
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
                cwd=working_dir,
                # Restrict environment
                env={'PATH': '/bin:/usr/bin'},
                # Prevent shell injection
                shell=False
            )
            
            return {
                'returncode': result.returncode,
                'stdout': result.stdout,
                'stderr': result.stderr
            }
        except subprocess.TimeoutExpired:
            raise TimeoutError("Command execution timed out")
    
    @staticmethod
    def unsafe_example(user_input: str):
        """
        UNSAFE: Never do this!
        """
        # DANGEROUS: Shell injection vulnerability
        result = subprocess.run(
            f"ls {user_input}",  # User input in shell command!
            shell=True,  # Shell invocation!
            capture_output=True
        )
        return result
```

---

## تلوث النموذج (JavaScript) — Prototype Pollution

**العربية:**
- استخدم `new Set()` أو `new Map()` بدلاً من الكائنات الحرفية
- عند الحاجة للكائنات، أنشئ بـ `Object.create(null)` أو `{ __proto__: null }`
- تجمد أو أغلق الكائنات التي يجب أن تكون غير قابلة للتغيير
- تجنب أدوات الدمج العميق غير الآمنة

**English:**
- Use `new Set()` or `new Map()` instead of object literals
- When objects required, create with `Object.create(null)` or `{ __proto__: null }`
- Freeze or seal objects that should be immutable
- Avoid unsafe deep merge utilities

```javascript
// JavaScript Prototype Pollution Prevention

// UNSAFE: Object literal
const unsafeObj = {};

// SAFE: Object without prototype
const safeObj = Object.create(null);
// or
const safeObj2 = { __proto__: null };

// SAFE: Using Map for key-value storage
const safeMap = new Map();
safeMap.set('key', 'value');

// SAFE: Using Set for unique values
const safeSet = new Set();
safeSet.add('value');

// Safe object merge
function safeMerge(target, source) {
    const safeTarget = Object.create(null);
    
    // Only copy allowed keys
    const allowedKeys = ['name', 'email', 'department'];
    
    for (const key of allowedKeys) {
        if (source.hasOwnProperty(key)) {
            // Block dangerous keys
            if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
                continue;
            }
            safeTarget[key] = source[key];
        }
    }
    
    return safeTarget;
}

// Freeze objects that shouldn't change
const config = Object.freeze({
    apiEndpoint: 'https://api.uae.gov.ae',
    timeout: 30000,
    retries: 3
});

// Node.js defense-in-depth
// Run with: node --disable-proto=delete app.js
```

---

## التخزين المؤقت والنقل — Caching and Transport

**العربية:**
- طبق `Cache-Control: no-store` على الاستجابات الحساسة
- فرض HTTPS عبر جميع تدفقات البيانات
- لا تخزن بيانات المصادقة في التخزين المؤقت

**English:**
- Apply `Cache-Control: no-store` on responses containing sensitive data
- Enforce HTTPS across data flows
- Do not cache authentication data

```python
# Python Secure Headers
from flask import Flask, Response

app = Flask(__name__)

@app.after_request
def add_security_headers(response: Response):
    """Add security headers to all responses"""
    
    # Prevent caching of sensitive data
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, private'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    
    # Security headers
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    # Strict HTTPS
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
    
    return response
```

---

## قائمة التحقق — Implementation Checklist

- [ ] مدققات مركزية: أنواع، نطاقات، أطوال، قوائم سماح
- [ ] التوحيد القياسي قبل الفحوصات
- [ ] تغطية 100% للتحديد المعلمي لـ SQL
- [ ] المعرفات الديناميكية عبر قوائم السماح فقط
- [ ] هروب DN/فلتر LDAP قيد الاستخدام
- [ ] المدخلات مُتحقَّقة قبل الاستعلام
- [ ] لا استدعاء للصدفة لمدخلات غير موثوقة
- [ ] إذا لا بد: تنفيذ منظم + قائمة سماح + تحقق regex
- [ ] رسوم كائنات JS مُقوَّاة
- [ ] منشئات آمنة، مسارات نموذج محجوبة
- [ ] أدوات دمج آمنة
- [ ] تحميلات الملفات مُتحقَّقة بالمحتوى والحجم والامتداد
- [ ] تخزين الملفات خارج web root
- [ ] فحص الملفات المرفوعة

---

## خطة الاختبار — Test Plan

- [ ] فحوصات ثابتة لتسلسل السلاسل في الاستعلامات/الأوامر
- [ ] Fuzzing لمتجهات حقن SQL/LDAP/OS
- [ ] اختبارات وحدة لحالات حافة المدقق
- [ ] اختبارات سلبية لمفاتيح النموذج المحجوبة
- [ ] اختبار سلوك الدمج العميق
- [ ] اختبار رفض المدخلات غير الصالحة
- [ ] اختبار قبول المدخلات الصالحة فقط
- [ ] اختبار حدود الطول والحجم

---

## مراجع — References

- [OWASP Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [OWASP LDAP Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html)
- [OWASP Command Injection Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html)
- [Prototype Pollution Prevention](https://learn.snyk.io/lesson/prototype-pollution/)
