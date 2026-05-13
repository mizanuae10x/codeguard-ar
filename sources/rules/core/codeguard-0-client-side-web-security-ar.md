---
description: أمان الويب من جانب العميل (XSS/DOM XSS، CSP، CSRF، clickjacking، XS-Leaks، JS طرف ثالث)
languages:
- c
- html
- javascript
- php
- typescript
- vlang
tags:
- web
- client-side
- uae
alwaysApply: false
---

# أمان الويب من جانب العميل — Client-side Web Security

## نظرة عامة — Overview

حمِ عملاء المتصفح ضد حقن الكود، وتزوير الطلبات، وإعادة رسم واجهة المستخدم، وتسريبات المواقع المتقاطعة، والسكربتات غير الآمنة من طرف ثالث باستخدام ضوابط طبقية وواعية بالسياق.

Protect browser clients against code injection, request forgery, UI redress, cross-site leaks, and unsafe third-party scripts with layered, context-aware controls.

---

## منع XSS (واعٍ بالسياق) — XSS Prevention (Context-Aware)

**العربية:**
- سياق HTML: فضّل `textContent`. إذا لزم HTML، نظف بمكتبة موثوقة (مثل DOMPurify) مع قوائم سماح صارمة.
- سياق السمة: ضع دائماً علامات الاقتباس على السمات وشفر القيم.
- سياق JavaScript: لا تبنِ JS من سلاسل غير موثوقة؛ تجنب معالجات الأحداث المضمنة؛ استخدم `addEventListener`.
- سياق URL: تحقق من البروتوكول/النطاق وشفر؛ احجب `javascript:` وعناوين URL للبيانات.
- التوجيهات/التحويلات: لا تستخدم مدخلات المستخدم مباشرة للوجهات.
- سياق CSS: قوائم سماح للقيم؛ لا تحقن نص أسلوب خام من المستخدمين.

**English:**
- HTML context: prefer `textContent`. If HTML required, sanitize with vetted library (e.g., DOMPurify) and strict allow-lists.
- Attribute context: always quote attributes and encode values.
- JavaScript context: do not build JS from untrusted strings; avoid inline event handlers; use `addEventListener`.
- URL context: validate protocol/domain and encode; block `javascript:` and data URLs.
- Redirects/forwards: never use user input directly for destinations.
- CSS context: allow-list values; never inject raw style text from users.

```javascript
// JavaScript XSS Prevention with DOMPurify
// Sanitize user HTML
const clean = DOMPurify.sanitize(userHtml, {
  ALLOWED_TAGS: ['b', 'i', 'p', 'a', 'ul', 'li', 'br'],
  ALLOWED_ATTR: ['href', 'target', 'rel', 'class'],
  ALLOW_DATA_ATTR: false,
  SANITIZE_DOM: true,
  // UAE-specific: block any reference to government domains in href
  FORBID_ATTR: ['onerror', 'onload', 'onclick'],
});

// Safe text insertion
element.textContent = userInput;  // Safe
// element.innerHTML = userInput;  // DANGEROUS!

// Safe attribute setting
element.setAttribute('data-value', encodeURIComponent(userInput));
```

---

## XSS المستند إلى DOM والأحواض الخطرة — DOM-based XSS and Dangerous Sinks

**العربية:**
- امنع `innerHTML` و`outerHTML` و`document.write` مع بيانات غير موثوقة.
- امنع `eval` و`new Function` و`setTimeout/Interval` المبني على سلاسل.
- تحقق وشفر البيانات قبل إسنادها إلى `location` أو خصائص معالج الأحداث.
- استخدم الوضع الصارم (strict mode) وإعلانات المتغيرات الصريحة.
- اعتمد Trusted Types وفرض CSP صارم.

**English:**
- Prohibit `innerHTML`, `outerHTML`, `document.write` with untrusted data.
- Prohibit `eval`, `new Function`, string-based `setTimeout/Interval`.
- Validate and encode data before assigning to `location` or event handler properties.
- Use strict mode and explicit variable declarations.
- Adopt Trusted Types and enforce strict CSP.

```javascript
// Trusted Types + CSP Implementation
// Register Trusted Types policy
if (window.trustedTypes && trustedTypes.createPolicy) {
  const policy = trustedTypes.createPolicy('uaePolicy', {
    createHTML: (input) => {
      // Sanitize with DOMPurify
      return DOMPurify.sanitize(input);
    },
    createScriptURL: (input) => {
      // Only allow specific domains
      const allowedDomains = ['uae.gov.ae', 'cdn.uae.gov.ae'];
      const url = new URL(input);
      if (!allowedDomains.includes(url.hostname)) {
        throw new Error('Domain not allowed');
      }
      return input;
    },
    createScript: (input) => {
      // Block all inline scripts
      throw new Error('Inline scripts not allowed');
    }
  });
}

// CSP Header (server-side)
// Content-Security-Policy: 
//   default-src 'self';
//   script-src 'self' 'nonce-{random}';
//   style-src 'self' 'unsafe-inline';
//   img-src 'self' data: https:;
//   font-src 'self';
//   connect-src 'self';
//   frame-ancestors 'none';
//   base-uri 'none';
//   form-action 'self';
//   require-trusted-types-for 'script';
//   trusted-types uaePolicy;
```

---

## سياسة أمان المحتوى (CSP) — Content Security Policy

**العربية:**
- فضّل CSP المعتمد على nonce أو hash على قوائم السماح للنطاقات.
- ابدأ بوضع Report-Only؛ اجمع الانتهاكات؛ ثم فرض.
- الأساس المستهدف: `default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'self'; form-action 'self'; object-src 'none'; base-uri 'none'; upgrade-insecure-requests`.

**English:**
- Prefer nonce-based or hash-based CSP over domain allow-lists.
- Start with Report-Only mode; collect violations; then enforce.
- Baseline: `default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'self'; form-action 'self'; object-src 'none'; base-uri 'none'; upgrade-insecure-requests`.

```python
# Python Flask CSP Configuration
from flask import Flask, Response
import secrets

app = Flask(__name__)

@app.after_request
def set_csp_header(response: Response):
    """Set Content Security Policy with nonce"""
    # Generate random nonce for this request
    nonce = secrets.token_urlsafe(16)
    
    # Store nonce for template use
    response.headers['X-CSP-Nonce'] = nonce
    
    # Set CSP with nonce
    response.headers['Content-Security-Policy'] = (
        f"default-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}'; "
        f"style-src 'self' 'nonce-{nonce}' 'unsafe-inline'; "
        f"img-src 'self' data: https:; "
        f"font-src 'self'; "
        f"connect-src 'self'; "
        f"frame-ancestors 'none'; "
        f"base-uri 'none'; "
        f"form-action 'self'; "
        f"object-src 'none'; "
        f"upgrade-insecure-requests; "
        f"require-trusted-types-for 'script'; "
        f"trusted-types uaePolicy"
    )
    
    # Report violations
    response.headers['Content-Security-Policy'] += (
        "; report-uri /api/csp-report"
    )
    
    return response

# CSP Report Endpoint
@app.route('/api/csp-report', methods=['POST'])
def csp_report():
    """Receive CSP violation reports"""
    report = request.get_json()
    
    # Log violation
    security_logger.warning({
        'event': 'csp_violation',
        'document_uri': report.get('csp-report', {}).get('document-uri'),
        'blocked_uri': report.get('csp-report', {}).get('blocked-uri'),
        'violated_directive': report.get('csp-report', {}).get('violated-directive'),
        'timestamp': datetime.utcnow().isoformat()
    })
    
    return '', 204
```

---

## الدفاع ضد CSRF — CSRF Defense

**العربية:**
- أصلح XSS أولاً؛ ثم أضف دفاعات CSRF.
- استخدم حمايات CSRF الأصلية للإطار ورموز المزامنة على جميع الطلبات المغيرة للحالة.
- إعدادات ملفات تعريف الارتباط: `SameSite=Lax` أو `Strict`؛ جلسات `Secure` و`HttpOnly`.
- تحقق من Origin/Referer؛ اطلب رؤوس مخصصة لطفرات API في نموذج SPA.
- لا تستخدم GET لتغيير الحالة.

**English:**
- Fix XSS first; then layer CSRF defenses.
- Use framework-native CSRF protections and synchronizer tokens on all state-changing requests.
- Cookie settings: `SameSite=Lax` or `Strict`; sessions `Secure` and `HttpOnly`.
- Validate Origin/Referer; require custom headers for API mutations in SPA token models.
- Never use GET for state changes.

```javascript
// JavaScript CSRF Token Handling
class UAECSRFProtection {
    constructor() {
        this.token = this.getTokenFromCookie();
    }
    
    getTokenFromCookie() {
        // Read CSRF token from cookie (set by server)
        const match = document.cookie.match(/csrf_token=([^;]+)/);
        return match ? match[1] : null;
    }
    
    async makeRequest(url, method, data) {
        const headers = {
            'Content-Type': 'application/json',
            'X-CSRF-Token': this.token,
            'X-Requested-With': 'XMLHttpRequest'
        };
        
        const response = await fetch(url, {
            method: method,
            headers: headers,
            body: JSON.stringify(data),
            credentials: 'same-origin'
        });
        
        if (response.status === 403) {
            // CSRF token expired or invalid
            this.refreshToken();
            throw new Error('CSRF token invalid');
        }
        
        return response;
    }
    
    refreshToken() {
        // Request new CSRF token from server
        fetch('/api/csrf-token', { credentials: 'same-origin' })
            .then(response => response.json())
            .then(data => {
                this.token = data.token;
            });
    }
}
```

---

## الدفاع ضد Clickjacking — Clickjacking Defense

**العربية:**
- الأساسي: `Content-Security-Policy: frame-ancestors 'none'` أو قائمة سماح محددة.
- احتياطي للمتصفحات القديمة: `X-Frame-Options: DENY` أو `SAMEORIGIN`.
- فكر في تأكيدات UX للإجراءات الحساسة عند الحاجة للإطار.

**English:**
- Primary: `Content-Security-Policy: frame-ancestors 'none'` or specific allow-list.
- Fallback for legacy browsers: `X-Frame-Options: DENY` or `SAMEORIGIN`.
- Consider UX confirmations for sensitive actions when framing is required.

```python
# Python Clickjacking Protection
from flask import Flask, Response

app = Flask(__name__)

@app.after_request
def set_frame_protection(response: Response):
    """Set clickjacking protection headers"""
    # Primary defense: CSP frame-ancestors
    response.headers['Content-Security-Policy'] = (
        "frame-ancestors 'none'"
    )
    
    # Fallback for legacy browsers
    response.headers['X-Frame-Options'] = 'DENY'
    
    return response

# If framing is required for specific origins
@app.after_request
def set_frame_protection_conditional(response: Response):
    """Allow framing only from trusted origins"""
    allowed_origins = ['https://partner.uae.gov.ae']
    
    # Build frame-ancestors directive
    origins_str = ' '.join(allowed_origins)
    response.headers['Content-Security-Policy'] = (
        f"frame-ancestors {origins_str}"
    )
    
    response.headers['X-Frame-Options'] = 'ALLOW-FROM https://partner.uae.gov.ae'
    
    return response
```

---

## ضوابط تسريبات المواقع المتقاطعة (XS-Leaks) — Cross-Site Leaks Controls

**العربية:**
- استخدم ملفات تعريف الارتباط `SameSite` بشكل مناسب؛ فضّل `Strict` للإجراءات الحساسة.
- اعتمد حمايات Fetch Metadata لحجب الطلبات المتقاطعة المشبوهة.
- عزل سياقات التصفح: COOP/COEP وCORP حيثما ينطبق.
- عطل التخزين المؤقت وأضف رموز فريدة للمستخدم للاستجابات الحساسة.

**English:**
- Use `SameSite` cookies appropriately; prefer `Strict` for sensitive actions.
- Adopt Fetch Metadata protections to block suspicious cross-site requests.
- Isolate browsing contexts: COOP/COEP and CORP where applicable.
- Disable caching and add user-unique tokens for sensitive responses.

```javascript
// Fetch Metadata Request Headers
// Server-side check (Node.js example)
function checkFetchMetadata(req, res, next) {
    const site = req.headers['sec-fetch-site'];
    const mode = req.headers['sec-fetch-mode'];
    const dest = req.headers['sec-fetch-dest'];
    
    // Block cross-site requests to sensitive endpoints
    if (site === 'cross-site' && req.path.startsWith('/api/sensitive')) {
        return res.status(403).json({
            error: 'Cross-site requests not allowed'
        });
    }
    
    // Block nested navigations
    if (site === 'cross-site' && mode === 'navigate') {
        return res.status(403).json({
            error: 'Cross-site navigation not allowed'
        });
    }
    
    next();
}

// COOP/COEP Headers
app.use((req, res, next) => {
    res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
    res.setHeader('Cross-Origin-Embedder-Policy', 'require-corp');
    res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
    next();
});
```

---

## JavaScript من طرف ثالث — Third-Party JavaScript

**العربية:**
- قلل وعزل: فضّل iframes معزولة مع `sandbox` وفحوصات postMessage origin.
- استخدم Subresource Integrity (SRI) للسكربتات الخارجية وراقب التغييرات.
- قدم طبقة بيانات من الطرف الأول؛ امنع الوصول المباشر للـ DOM من العلامات.

**English:**
- Minimize and isolate: prefer sandboxed iframes with `sandbox` and postMessage origin checks.
- Use Subresource Integrity (SRI) for external scripts and monitor for changes.
- Provide a first-party, sanitized data layer; deny direct DOM access from tags.

```html
<!-- Subresource Integrity (SRI) Example -->
<script src="https://cdn.uae.gov.ae/analytics.js"
  integrity="sha384-abc123..."
  crossorigin="anonymous"></script>

<!-- Sandboxed iframe for third-party content -->
<iframe 
  src="https://partner.uae.gov.ae/widget"
  sandbox="allow-scripts allow-same-origin"
  referrerpolicy="no-referrer"
  csp="default-src 'self';"></iframe>
```

---

## HTML5، CORS، WebSockets، التخزين — HTML5, CORS, WebSockets, Storage

**العربية:**
- postMessage: حدد دائماً origin الهدف بالضبط؛ تحقق من `event.origin` عند الاستلام.
- CORS: تجنب `*`؛ قوائم سماح للأصول؛ تحقق من preflights.
- WebSockets: اطلب `wss://`، فحوصات origin، مصادقة، حدود حجم الرسالة.
- التخزين من جانب العميل: لا تخزن أسرار في `localStorage`/`sessionStorage`.

**English:**
- postMessage: always specify exact target origin; verify `event.origin` on receive.
- CORS: avoid `*`; allow-list origins; validate preflights.
- WebSockets: require `wss://`, origin checks, auth, message size limits.
- Client storage: never store secrets in `localStorage`/`sessionStorage`.

```javascript
// Safe postMessage
// Sender
iframe.contentWindow.postMessage(
    { action: 'update', data: sanitizedData },
    'https://partner.uae.gov.ae'  // Exact target origin
);

// Receiver
window.addEventListener('message', (event) => {
    // Verify origin
    if (event.origin !== 'https://partner.uae.gov.ae') {
        return;
    }
    
    // Verify data structure
    if (event.data && event.data.action === 'update') {
        // Process data
    }
});

// Secure WebSocket
const ws = new WebSocket('wss://api.uae.gov.ae/socket');

ws.onopen = () => {
    // Authenticate
    ws.send(JSON.stringify({
        type: 'auth',
        token: getSecureToken()  // From HttpOnly cookie
    }));
};

ws.onmessage = (event) => {
    // Validate message size
    if (event.data.length > 100000) {
        ws.close();
        return;
    }
    
    // Safe JSON parsing
    try {
        const data = JSON.parse(event.data);
        // Process data
    } catch (e) {
        console.error('Invalid JSON');
    }
};
```

---

## رؤوس أمان HTTP — HTTP Security Headers

```python
# Python Flask Security Headers
@app.after_request
def set_security_headers(response: Response):
    """Set comprehensive security headers"""
    
    # Prevent MIME sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'
    
    # XSS Protection (legacy browsers)
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    # Referrer Policy
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    # Permissions Policy
    response.headers['Permissions-Policy'] = (
        'camera=(), '
        'microphone=(), '
        'geolocation=(self), '
        'payment=(), '
        'usb=(), '
        'magnetometer=(), '
        'gyroscope=(), '
        'speaker=()'
    )
    
    # HSTS
    response.headers['Strict-Transport-Security'] = (
        'max-age=31536000; includeSubDomains; preload'
    )
    
    return response
```

---

## قائمة التحقق — Implementation Checklist

- [ ] التشفير/التنقية السياقية لكل حوض
- [ ] لا واجهات برمجة خطرة بدون حماية
- [ ] CSP صارم مع nonces و Trusted Types
- [ ] مراقبة انتهاكات CSP
- [ ] رموز CSRF على جميع الطلبات المغيرة للحالة
- [ ] سمات ملفات تعريف الارتباط الآمنة
- [ ] حمايات الإطار مضبوطة
- [ ] تخفيفات XS-Leaks مفعلة (Fetch Metadata, COOP/COEP/CORP)
- [ ] JS طرف ثالث معزول بـ SRI و sandbox
- [ ] طبقة بيانات موثقة فقط
- [ ] HTML5/CORS/WebSocket مُصلَّب
- [ ] لا أسرار في تخزين الويب
- [ ] رؤوس الأمان مفعلة ومُتحقَّقة

---

## خطة الاختبار — Test Plan

- [ ] فحوصات آلية للأنماط الخطرة في DOM/API
- [ ] اختبارات E2E لـ CSRF و clickjacking
- [ ] مراقبة تقارير CSP
- [ ] تحقق يدوي من XS-Leaks
- [ ] اختبار سلوك التوجيه المفتوح
- [ ] اختبار SRI
- [ ] اختبار عزل iframe
- [ ] اختبار WebSocket security

---

## مراجع — References

- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [OWASP Clickjacking Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html)
- [CSP Quick Reference Guide](https://content-security-policy.com/)
- [Fetch Metadata Request Headers](https://developer.mozilla.org/en-US/docs/Glossary/Fetch_metadata_request_header)
