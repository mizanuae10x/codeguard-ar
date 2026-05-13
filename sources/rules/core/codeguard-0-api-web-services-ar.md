---
description: أمان API وخدمات الويب (REST/GraphQL/SOAP)، التحقق من المخطط، المصادقة/التفويض، SSRF
languages:
- c
- go
- java
- javascript
- php
- python
- ruby
- typescript
- xml
- yaml
tags:
- web
- api
- uae
alwaysApply: false
---

# أمان API وخدمات الويب — API & Web Services Security

## نظرة عامة — Overview

يغطي هذا القسم أمان خدمات REST وGraphQL وSOAP/WS من النهاية إلى النهاية: النقل، المصادقة/التفويض، التحقق من المخطط، ضوابط SSRF، حدود DoS، وأنماط آمنة للخدمات المصغرة.

This section covers securing REST, GraphQL, and SOAP/WS services end-to-end: transport, authn/z, schema validation, SSRF controls, DoS limits, and microservice-safe patterns.

---

## النقل وتشفير TLS — Transport and TLS

**العربية:**
- HTTPS فقط؛ فكر في mTLS للخدمات عالية القيمة/الداخلية
- تحقق من الشهادات (CN/SAN، الإبطال)
- منع المحتوى المختلط (mixed content)

**English:**
- HTTPS only; consider mTLS for high-value/internal services
- Validate certs (CN/SAN, revocation)
- Prevent mixed content

---

## المصادقة والرموز — Authentication and Tokens

### OAuth2/OIDC
**العربية:**
- استخدم تدفقات OAuth2/OIDC القياسية للعملاء
- تجنب مخططات المصادقة المخصصة
- للخدمات الداخلية، استخدم mTLS أو رموز الخدمة الموقعة

**English:**
- Use standard OAuth2/OIDC flows for clients
- Avoid custom authentication schemes
- For internal services, use mTLS or signed service tokens

### JWT Best Practices
**العربية:**
- ثبت خوارزميات التوقيع (pin algorithms)
- تحقق من iss/aud/exp/nbf
- أوقات حياة قصيرة (short lifetimes)
- تدوير المفاتيح
- قائمة الرفض (denylist) عند تسجيل الخروج

**English:**
- Pin signature algorithms
- Validate iss/aud/exp/nbf
- Short token lifetimes
- Key rotation
- Denylist on logout/revoke

```python
# Python JWT Validation Example
import jwt
from datetime import datetime, timedelta

def validate_uae_jwt(token: str, public_key: str) -> dict:
    """
    Validate JWT according to UAE security standards
    """
    try:
        payload = jwt.decode(
            token,
            public_key,
            algorithms=['RS256'],  # Pin algorithm
            audience='uae-government-api',
            issuer='https://auth.uae.gov.ae',
            options={
                'require': ['exp', 'iat', 'iss', 'aud'],
                'verify_exp': True,
                'verify_iat': True,
            }
        )
        
        # Additional UAE-specific checks
        if payload.get(' EmiratesID') and not validate_emirates_id(payload['EmiratesID']):
            raise jwt.InvalidTokenError('Invalid Emirates ID')
        
        return payload
    except jwt.ExpiredSignatureError:
        raise PermissionError('Token expired - requires re-authentication')
    except jwt.InvalidTokenError as e:
        raise PermissionError(f'Invalid token: {str(e)}')
```

---

## التفويض — Authorization

**العربية:**
- فرض فحوصات التفويض لكل نقطة نهاية وكل مورد
- الرفض افتراضياً (deny by default)
- للخدمات المصغرة: فوّض عند البوابة (خشن) والخدمة (دقيق)
- انشر هوية داخلية موقعة، لا الرموز الخارجية

**English:**
- Enforce per-endpoint, per-resource checks server-side
- Deny by default
- For microservices: authorize at gateway (coarse) and service (fine) layers
- Propagate signed internal identity, not external tokens

```java
// Java Spring Authorization Example
@PreAuthorize("hasRole('GOVERNMENT_USER') and @uaeAuthService.hasAccess(#documentId, 'READ')")
@GetMapping("/api/v1/documents/{documentId}")
public ResponseEntity<Document> getDocument(
    @PathVariable String documentId,
    @AuthenticationPrincipal UAEUser user
) {
    // Additional UAE-specific authorization
    if (!user.isUAEResident() && documentId.startsWith("UAE-CONFIDENTIAL")) {
        throw new AccessDeniedException("UAE residents only");
    }
    
    return ResponseEntity.ok(documentService.findById(documentId));
}
```

---

## التحقق من المدخلات والمحتوى — Input and Content Handling

**العربية:**
- تحقق من المدخلات عبر العقود: OpenAPI/JSON Schema
- ارفض الحقول المجهولة
- حدد حجم الحمولة (payload size limits)
- قسّط معالجات XML ضد XXE

**English:**
- Validate inputs via contracts: OpenAPI/JSON Schema
- Reject unknown fields
- Set payload size limits
- Harden XML parsers against XXE

```yaml
# OpenAPI Schema Example
openapi: 3.0.3
info:
  title: UAE Government API
  version: 1.0.0
paths:
  /api/v1/citizens/{emiratesId}:
    get:
      parameters:
        - name: emiratesId
          in: path
          required: true
          schema:
            type: string
            pattern: '^784-\d{4}-\d{7}-\d{1}$'
            description: UAE Emirates ID format
      responses:
        '200':
          description: Citizen data
          content:
            application/json:
              schema:
                type: object
                properties:
                  emiratesId:
                    type: string
                    pattern: '^784-\d{4}-\d{7}-\d{1}$'
                  fullName:
                    type: string
                    maxLength: 100
                  dateOfBirth:
                    type: string
                    format: date
                required: [emiratesId, fullName]
                additionalProperties: false  # Reject unknown fields
```

---

## أمان GraphQL — GraphQL-Specific Controls

**العربية:**
- حدد عمق الاستعلام (query depth limit)
- فرض تعقيد إجمالي (complexity limits)
- فرض تقسيم الصفحات (pagination)
- مهلة التنفيذ (timeouts)
- عطل الاستبطان (introspection) في الإنتاج
- فوّض على مستوى الحقل/الكائن

**English:**
- Limit query depth and overall complexity
- Enforce pagination
- Execution timeouts
- Disable introspection in production
- Implement field/object-level authorization

```javascript
// Node.js GraphQL Security Configuration
const { ApolloServer } = require('apollo-server-express');
const { createComplexityLimitRule } = require('graphql-validation-complexity');
const depthLimit = require('graphql-depth-limit');

const server = new ApolloServer({
  typeDefs,
  resolvers,
  validationRules: [
    depthLimit(5),  // Max query depth
    createComplexityLimitRule(1000),  // Complexity limit
  ],
  introspection: process.env.NODE_ENV !== 'production',
  plugins: [
    {
      requestDidStart() {
        return {
          didResolveOperation({ request, document }) {
            // UAE-specific: log all queries for audit
            auditLogger.logGraphQLQuery(request.operationName, document);
          },
        };
      },
    },
  ],
});
```

---

## منع SSRF — SSRF Prevention

**العربية:**
- لا تقبل عناوين URL خام
- تحقق من النطاقات/IPs باستخدام مكتبات
- قصر على HTTP/HTTPS فقط
- احجب نطاقات private/link-local/localhost

**English:**
- Do not accept raw URLs
- Validate domains/IPs using libraries
- Restrict to HTTP/HTTPS only
- Block private/link-local/localhost ranges

```python
# Python SSRF Prevention
import ipaddress
import re
from urllib.parse import urlparse

class UAESSRFPrevention:
    """
    SSRF prevention for UAE government APIs
    """
    
    ALLOWED_SCHEMES = {'https', 'http'}
    BLOCKED_IP_RANGES = [
        ipaddress.ip_network('10.0.0.0/8'),
        ipaddress.ip_network('172.16.0.0/12'),
        ipaddress.ip_network('192.168.0.0/16'),
        ipaddress.ip_network('127.0.0.0/8'),
        ipaddress.ip_network('169.254.0.0/16'),  # Link-local
        ipaddress.ip_network('::1/128'),  # IPv6 localhost
        ipaddress.ip_network('fc00::/7'),  # IPv6 private
    ]
    
    @classmethod
    def validate_url(cls, url: str) -> bool:
        """Validate URL is safe for outbound requests"""
        parsed = urlparse(url)
        
        # Check scheme
        if parsed.scheme not in cls.ALLOWED_SCHEMES:
            raise ValueError(f"Scheme {parsed.scheme} not allowed")
        
        # Resolve hostname
        hostname = parsed.hostname
        if not hostname:
            raise ValueError("Invalid URL: no hostname")
        
        # Check if IP address
        try:
            ip = ipaddress.ip_address(hostname)
            if any(ip in network for network in cls.BLOCKED_IP_RANGES):
                raise ValueError(f"IP {hostname} is in blocked range")
        except ValueError:
            # It's a domain, check against allowlist
            pass
        
        return True
    
    @classmethod
    def safe_request(cls, url: str, method='GET', **kwargs):
        """Make safe HTTP request"""
        cls.validate_url(url)
        
        # Disable redirects
        kwargs['allow_redirects'] = False
        
        # Set timeout
        kwargs.setdefault('timeout', 30)
        
        return requests.request(method, url, **kwargs)
```

---

## تقييد المعدل وحماية DoS — Rate Limiting and DoS

**العربية:**
- حدود لكل IP/مستخدم/عميل
- قواطع الدوائر (circuit breakers)
- مهلات (timeouts)
- تخزين مؤقت (caching) من جانب الخادم

**English:**
- Per-IP/user/client limits
- Circuit breakers
- Timeouts
- Server-side caching

```python
# Python Rate Limiting with Redis
import redis
from functools import wraps
from datetime import datetime

class UAERateLimiter:
    """
    Rate limiter for UAE government APIs
    """
    
    def __init__(self, redis_client: redis.Redis):
        self.redis = redis_client
        
        # UAE-specific limits
        self.limits = {
            'anonymous': {'requests': 100, 'window': 3600},  # 100/hour
            'authenticated': {'requests': 1000, 'window': 3600},  # 1000/hour
            'government': {'requests': 10000, 'window': 3600},  # 10000/hour
        }
    
    def is_allowed(self, user_id: str, user_type: str = 'anonymous') -> bool:
        """Check if request is allowed"""
        limit = self.limits.get(user_type, self.limits['anonymous'])
        key = f"rate_limit:{user_type}:{user_id}"
        
        current = self.redis.get(key)
        if current is None:
            self.redis.setex(key, limit['window'], 1)
            return True
        
        if int(current) >= limit['requests']:
            return False
        
        self.redis.incr(key)
        return True
    
    def rate_limit_decorator(self, user_type='anonymous'):
        """Decorator for rate limiting"""
        def decorator(f):
            @wraps(f)
            def wrapper(*args, **kwargs):
                # Extract user ID from request context
                user_id = get_current_user_id() or request.remote_addr
                
                if not self.is_allowed(user_id, user_type):
                    return jsonify({
                        'error': 'Rate limit exceeded',
                        'retry_after': self.redis.ttl(f"rate_limit:{user_type}:{user_id}")
                    }), 429
                
                return f(*args, **kwargs)
            return wrapper
        return decorator
```

---

## نقاط نهاية الإدارة — Management Endpoints

**العربية:**
- لا تعرض على الإنترنت
- تتطلب مصادقة قوية (MFA)
- قيود شبكية
- منافذ/مضيفات منفصلة

**English:**
- Do not expose over the Internet
- Require strong auth (MFA)
- Network restrictions
- Separate ports/hosts

```yaml
# Kubernetes Management Endpoint Security
apiVersion: v1
kind: Service
metadata:
  name: uae-api-management
  namespace: production
spec:
  selector:
    app: uae-api
    tier: management
  ports:
    - port: 9090
      targetPort: 9090
  type: ClusterIP  # Not exposed externally
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: management-network-policy
spec:
  podSelector:
    matchLabels:
      tier: management
  policyTypes:
    - Ingress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              name: monitoring
        - ipBlock:
            cidr: 10.0.0.0/8  # Internal VPN only
      ports:
        - protocol: TCP
          port: 9090
```

---

## قائمة التحقق — Implementation Checklist

- [ ] HTTPS/mTLS مُهيأ
- [ ] إدارة الشهادات
- [ ] لا محتوى مختلط
- [ ] التحقق من العقود عند الحافة والخدمة
- [ ] الحقول المجهولة مرفوضة
- [ ] حدود الحجم/الوقت مفروضة
- [ ] مصادقة/تفويض قوي لكل نقطة نهاية
- [ ] حدود GraphQL مفروضة
- [ ] الاستبطان معطل في الإنتاج
- [ ] حماية SSRF عند طبقات التطبيق والشبكة
- [ ] إعادة التوجيه معطلة
- [ ] قوائم السماح حيثما أمكن
- [ ] تقييد المعدل
- [ ] قواطع الدوائر
- [ ] أنماط مرنة
- [ ] نقاط نهاية الإدارة معزولة
- [ ] السجلات منظمة وآمنة من حيث الخصوصية
- [ ] معرفات الارتباط (correlation IDs)

---

## خطة الاختبار — Test Plan

- [ ] اختبارات العقد للالتزام بالمخطط
- [ ] Fuzzing بأدوات واعية بالمخطط
- [ ] اختبارات الاختراق لـ SSRF وIDOR/BOLA وتجاوز التفويض
- [ ] اختبارات الأداء لحدود DoS
- [ ] اختبر جميع طرق HTTP لكل نقطة نهاية
- [ ] اكتشف المعاملات في مسارات URL والرؤوس والبيانات المنظمة
- [ ] فحوصات آلية للتحقق من الرموز وسلوك الإبطال

---

## مراجع — References

- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [UAE Information Assurance Framework](https://www.tra.gov.ae/)
- [NIST SP 800-207 - Zero Trust Architecture](https://csrc.nist.gov/publications/detail/sp/800-207/final)
- [RFC 8725 - JWT Best Current Practices](https://tools.ietf.org/html/rfc8725)
