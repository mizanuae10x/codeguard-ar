---
description: أمن الأطر واللغات (Django/DRF، Laravel/Symfony/Rails، .NET، Java/JAAS، Node.js، PHP)
languages:
- c
- java
- javascript
- kotlin
- php
- python
- ruby
- typescript
- xml
- yaml
tags:
- framework
- language
- uae
alwaysApply: false
---

# أمن الأطر واللغات — Framework & Language Guides

## نظرة عامة — Overview

طبق أنماط آمنة افتراضياً حسب المنصة. قسّم التكوينات، استخدم الحمايات المدمجة، وتجنب الأخطاء الشائعة.

Apply secure-by-default patterns per platform. Harden configurations, use built-in protections, and avoid common pitfalls.

---

## Django

**العربية:**
- عطّل DEBUG في الإنتاج؛ حافظ على Django والتبعيات محدثة.
- فعّل `SecurityMiddleware`، وسيط clickjacking، وحماية MIME sniffing.
- افرض HTTPS (`SECURE_SSL_REDIRECT`)；اضبط HSTS؛ اضبط أعلام الكعكات الآمنة (`SESSION_COOKIE_SECURE`، `CSRF_COOKIE_SECURE`).
- CSRF: تأكد من `CsrfViewMiddleware` و`{% csrf_token %}` في النماذج؛ معالجة مناسبة لرموز AJAX.
- XSS: اعتمد على الهروب التلقائي للقوالب؛ تجنب `mark_safe` ما لم يكن موثوقاً؛ استخدم `json_script` للـ JS.
- Auth: استخدم `django.contrib.auth`؛ المحققون في `AUTH_PASSWORD_VALIDATORS`.
- Secrets: أنشئ عبر `get_random_secret_key`؛ خزن في env/مدير الأسرار.

**English:**
- Disable DEBUG in production; keep Django and deps updated.
- Enable `SecurityMiddleware`, clickjacking middleware, MIME sniffing protection.
- Force HTTPS (`SECURE_SSL_REDIRECT`); configure HSTS; set secure cookie flags.
- CSRF: ensure `CsrfViewMiddleware` and `{% csrf_token %}` in forms; proper AJAX token handling.
- XSS: rely on template auto-escaping; avoid `mark_safe` unless trusted; use `json_script` for JS.
- Auth: use `django.contrib.auth`; validators in `AUTH_PASSWORD_VALIDATORS`.
- Secrets: generate via `get_random_secret_key`; store in env/secrets manager.

```python
# settings.py - UAE Django Configuration
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# Security
SECRET_KEY = os.environ.get('DJANGO_SECRET_KEY')
DEBUG = False
ALLOWED_HOSTS = ['.tamkeenai.ae', '.uae.gov.ae']

# HTTPS
SECURE_SSL_REDIRECT = True
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
SECURE_HSTS_SECONDS = 31536000  # 1 year
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True

# Cookies
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Strict'
CSRF_COOKIE_SECURE = True
CSRF_COOKIE_HTTPONLY = True
CSRF_COOKIE_SAMESITE = 'Strict'

# Middleware
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

# Security headers
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_BROWSER_XSS_FILTER = True
X_FRAME_OPTIONS = 'DENY'

# Password validators
AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator', 'OPTIONS': {'min_length': 12}},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]
```

---

## Django REST Framework (DRF)

**العربية:**
- اضبط `DEFAULT_AUTHENTICATION_CLASSES` و`DEFAULT_PERMISSION_CLASSES` التقييدية؛ لا تترك `AllowAny` لنقاط النهاية المحمية.
- استدعِ دائماً `self.check_object_permissions(request, obj)` للتفويض على مستوى الكائن.
- Serializers: `fields=[...]` صريحة؛ تجنب `exclude` و`"__all__"`.
- Throttling: فعّل حدود المعدل (و/أو عند البوابة/WAF).
- عطل طرق HTTP غير الآمنة حيث لا تكون مطلوبة. تجنب SQL الخام؛ استخدم ORM/المعاملات.

**English:**
- Set `DEFAULT_AUTHENTICATION_CLASSES` and restrictive `DEFAULT_PERMISSION_CLASSES`; never leave `AllowAny` for protected endpoints.
- Always call `self.check_object_permissions(request, obj)` for object-level authz.
- Serializers: explicit `fields=[...]`; avoid `exclude` and `"__all__"`.
- Throttling: enable rate limits (and/or at gateway/WAF).
- Disable unsafe HTTP methods where not needed. Avoid raw SQL; use ORM/parameters.

```python
# DRF settings
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework.authentication.SessionAuthentication',
        'rest_framework.authentication.TokenAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
    'DEFAULT_THROTTLE_CLASSES': [
        'rest_framework.throttling.AnonRateThrottle',
        'rest_framework.throttling.UserRateThrottle',
    ],
    'DEFAULT_THROTTLE_RATES': {
        'anon': '100/hour',
        'user': '1000/hour',
    },
    'DEFAULT_RENDERER_CLASSES': [
        'rest_framework.renderers.JSONRenderer',
    ],
}
```

---

## Laravel

**العربية:**
- الإنتاج: `APP_DEBUG=false`؛ أنشئ مفتاح التطبيق؛ أذونات ملف آمنة.
- الكعكات/الجلسات: فعّل وسيط التشفير؛ اضبط `http_only`، `same_site`، `secure`، مهلات قصيرة.
- التعيين الجماعي: استخدم `$request->only()` / `$request->validated()`؛ تجنب `$request->all()`.
- SQLi: استخدم معاملات Eloquent؛ تحقق من المعرفات الديناميكية.
- XSS: اعتمد على هروب Blade؛ تجنب `{!! ... !!}` للبيانات غير الموثوقة.
- رفع الملفات: تحقق من `file`، الحجم، و`mimes`؛ نظف أسماء الملفات بـ `basename`.
- CSRF: تأكد من الوسيط ورموز النماذج مفعلة.

**English:**
- Production: `APP_DEBUG=false`; generate app key; secure file perms.
- Cookies/sessions: enable encryption middleware; set `http_only`, `same_site`, `secure`, short lifetimes.
- Mass assignment: use `$request->only()` / `$request->validated()`; avoid `$request->all()`.
- SQLi: use Eloquent parameterization; validate dynamic identifiers.
- XSS: rely on Blade escaping; avoid `{!! ... !!}` for untrusted data.
- File uploads: validate `file`, size, and `mimes`; sanitize filenames with `basename`.
- CSRF: ensure middleware and form tokens enabled.

```php
<?php
// .env - UAE Laravel Production
APP_ENV=production
APP_DEBUG=false
APP_KEY=base64:your-key-here

SESSION_DRIVER=database
SESSION_LIFETIME=120
SESSION_ENCRYPT=true
SESSION_SECURE_COOKIE=true
SESSION_HTTP_ONLY=true
SESSION_SAME_SITE=strict

// config/session.php
'secure' => env('SESSION_SECURE_COOKIE', true),
'http_only' => true,
'same_site' => 'strict',

// Controller - Secure mass assignment
class UserController extends Controller
{
    public function store(Request $request)
    {
        $validated = $request->validated([
            'name' => 'required|string|max:255',
            'email' => 'required|email|unique:users',
            'emirates_id' => 'required|string|regex:/^784\d{9}$/',
        ]);
        
        $user = User::create($validated);
        return response()->json($user, 201);
    }
}
```

---

## Symfony

**العربية:**
- XSS: هروب Twig التلقائي؛ تجنب `|raw` ما لم يكن موثوقاً.
- CSRF: استخدم `csrf_token()` و`isCsrfTokenValid()` للتدفقات اليدوية؛ النماذج تتضمن رموزاً افتراضياً.
- SQLi: استعلامات Doctrine المعاملية؛ لا تسلسل المدخلات أبداً.
- تنفيذ الأوامر: تجنب `exec/shell_exec`؛ استخدم مكون Filesystem.
- الرفع: تحقق بـ `#[File(...)]`；خزن خارج public؛ أسماء فريدة.
- التجاوز الدليلي: تحقق من `realpath`/`basename` وافرض جذوراً مسموحاً بها.

**English:**
- XSS: Twig auto-escaping; avoid `|raw` unless trusted.
- CSRF: use `csrf_token()` and `isCsrfTokenValid()` for manual flows; Forms include tokens by default.
- SQLi: Doctrine parameterized queries; never concatenate inputs.
- Command execution: avoid `exec/shell_exec`; use Filesystem component.
- Uploads: validate with `#[File(...)]`; store outside public; unique names.
- Directory traversal: validate `realpath`/`basename` and enforce allowed roots.

```php
<?php
// Symfony Controller - UAE Compliant
use Symfony\Component\HttpFoundation\File\UploadedFile;
use Symfony\Component\Validator\Constraints as Assert;

class DocumentController extends AbstractController
{
    #[Route('/upload', methods: ['POST'])]
    public function upload(
        #[Assert\File(
            maxSize: '10M',
            mimeTypes: ['application/pdf', 'image/jpeg'],
            mimeTypesMessage: 'Only PDF and JPEG files are allowed'
        )]
        UploadedFile $file
    ): Response {
        $safeFilename = basename($file->getClientOriginalName());
        $newFilename = uniqid().'_'.$safeFilename;
        
        $file->move(
            $this->getParameter('uploads_directory'),
            $newFilename
        );
        
        return $this->json(['filename' => $newFilename]);
    }
}
```

---

## Ruby on Rails

**العربية:**
- تجنب الدوال الخطرة: `eval`، `system`، backticks، `exec`، `spawn`، `open`، `IO.popen`، إلخ.
- SQLi: معاملات دائماً؛ استخدم `sanitize_sql_like` لأنماط LIKE.
- XSS: الهروب التلقائي افتراضياً؛ تجنب `raw`، `html_safe` على بيانات غير موثوقة؛ استخدم `sanitize` مع قوائم السماح.
- الجلسات: تخزين مدعوم بقاعدة البيانات للتطبيقات الحساسة؛ افرض HTTPS (`config.force_ssl = true`).
- Auth: استخدم Devise أو مكتبات مثبتة؛ اضبط المسارات والمناطق المحمية.
- CSRF: `protect_from_forgery` للإجراءات المغيرة للحالة.

**English:**
- Avoid dangerous functions: `eval`, `system`, backticks, `exec`, `spawn`, `open`, `IO.popen`, etc.
- SQLi: always parameterize; use `sanitize_sql_like` for LIKE patterns.
- XSS: default auto-escape; avoid `raw`, `html_safe` on untrusted data; use `sanitize` allow-lists.
- Sessions: database-backed store for sensitive apps; force HTTPS (`config.force_ssl = true`).
- Auth: use Devise or proven libraries; configure routes and protected areas.
- CSRF: `protect_from_forgery` for state-changing actions.

```ruby
# config/application.rb - UAE Rails Configuration
module UAEApp
  class Application < Rails::Application
    config.force_ssl = true
    config.ssl_options = { redirect: { exclude: -> request { request.path =~ /health/ } } }
    
    # Session security
    config.session_store :cookie_store, 
      key: '_uae_session',
      secure: true,
      httponly: true,
      same_site: :strict
    
    # CSRF
    config.action_controller.default_protect_from_forgery = true
    
    # Content Security Policy
    config.content_security_policy do |policy|
      policy.default_src :self
      policy.script_src :self
      policy.style_src :self, :unsafe_inline
      policy.img_src :self, :https
      policy.connect_src :self
      policy.font_src :self
      policy.object_src :none
      policy.frame_ancestors :none
      policy.base_uri :self
      policy.form_action :self
    end
  end
end

# Controller - Secure patterns
class UsersController < ApplicationController
  before_action :authenticate_user!
  before_action :set_user, only: [:show, :update, :destroy]
  
  def create
    @user = User.new(user_params)
    if @user.save
      render json: @user, status: :created
    else
      render json: @user.errors, status: :unprocessable_entity
    end
  end
  
  private
  
  def set_user
    @user = User.find(params[:id])
    authorize @user  # Pundit authorization
  end
  
  def user_params
    params.require(:user).permit(:name, :email, :emirates_id)
  end
end
```

---

## .NET (ASP.NET Core)

**العربية:**
- حافظ على runtime وNuGet محدثة؛ فعّل SCA في CI.
- Authz: استخدم سمات `[Authorize]`；نفذ فحوصات من جانب الخادم；منع IDOR.
- Authn/الجلسات: ASP.NET Identity؛ lockouts؛ كعكات `HttpOnly`/`Secure`؛ مهلات قصيرة.
- Crypto: استخدم PBKDF2 لكلمات المرور، AES-GCM للتشفير；DPAPI للأسرار المحلية؛ TLS 1.2+.
- الحقن: معاملات SQL/LDAP؛ تحقق مع قوائم السماح.
- Config: افرض إعادة توجيه HTTPS؛ أزل رؤوس الإصدار；اضبط CSP/HSTS/X-Content-Type-Options.
- CSRF: رموز anti-forgery على الإجراءات المغيرة للحالة；تحقق من جانب الخادم.

**English:**
- Keep runtime and NuGet packages updated; enable SCA in CI.
- Authz: use `[Authorize]` attributes; perform server-side checks; prevent IDOR.
- Authn/sessions: ASP.NET Identity; lockouts; cookies `HttpOnly`/`Secure`; short timeouts.
- Crypto: use PBKDF2 for passwords, AES-GCM for encryption; DPAPI for local secrets; TLS 1.2+.
- Injection: parameterize SQL/LDAP; validate with allow-lists.
- Config: enforce HTTPS redirects; remove version headers; set CSP/HSTS/X-Content-Type-Options.
- CSRF: anti-forgery tokens on state-changing actions; validate on server.

```csharp
// Program.cs - UAE ASP.NET Core
var builder = WebApplication.CreateBuilder(args);

// Security headers
builder.Services.AddHsts(options =>
{
    options.MaxAge = TimeSpan.FromDays(365);
    options.IncludeSubDomains = true;
    options.Preload = true;
});

builder.Services.AddHttpsRedirection(options =>
{
    options.RedirectStatusCode = StatusCodes.Status308PermanentRedirect;
    options.HttpsPort = 443;
});

// Authentication & Authorization
builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{
    options.Password.RequireDigit = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireUppercase = true;
    options.Password.RequireNonAlphanumeric = true;
    options.Password.RequiredLength = 12;
    options.Lockout.MaxFailedAccessAttempts = 5;
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
})
.AddEntityFrameworkStores<ApplicationDbContext>();

builder.Services.AddAuthentication()
    .AddCookie(options =>
    {
        options.Cookie.HttpOnly = true;
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        options.Cookie.SameSite = SameSiteMode.Strict;
        options.ExpireTimeSpan = TimeSpan.FromHours(2);
    });

builder.Services.AddAntiforgery(options =>
{
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Strict;
});

var app = builder.Build();

// Security middleware
app.UseHsts();
app.UseHttpsRedirection();
app.UseXContentTypeOptions();
app.UseXFrameOptions(options => options.Deny());
app.UseXXssProtection(options => options.EnabledWithBlockMode());
app.UseReferrerPolicy(options => options.StrictOriginWhenCrossOrigin());

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();
app.Run();
```

---

## Java و JAAS

**العربية:**
- SQL/JPA: استخدم `PreparedStatement`/معاملات مسماة；لا تسلسل المدخلات أبداً.
- XSS: تحقق قائم السماح؛ نظف المخرجات بمكتبات موثوقة؛ اكوِد حسب السياق.
- التسجيل: تسجيل معامل لمنع حقن السجلات.
- Crypto: AES-GCM؛ nonces عشوائية آمنة؛ لا تُضمن مفاتيح أبداً؛ استخدم KMS/HSM.
- JAAS: اضبط `LoginModule`؛ نفذ `initialize/login/commit/abort/logout`；تجنب كشف الاعتمادات.

**English:**
- SQL/JPA: use `PreparedStatement`/named parameters; never concatenate input.
- XSS: allow-list validation; sanitize output with reputable libs; encode for context.
- Logging: parameterized logging to prevent log injection.
- Crypto: AES-GCM; secure random nonces; never hardcode keys; use KMS/HSM.
- JAAS: configure `LoginModule` stanzas; implement `initialize/login/commit/abort/logout`; avoid exposing credentials.

```java
// Java - Secure Database Access
import java.sql.*;
import javax.sql.DataSource;

public class UAEUserRepository {
    private final DataSource dataSource;
    
    public UAEUserRepository(DataSource dataSource) {
        this.dataSource = dataSource;
    }
    
    public User findByEmiratesId(String emiratesId) throws SQLException {
        // Parameterized query - prevents SQL injection
        String sql = "SELECT * FROM users WHERE emirates_id = ? AND status = 'active'";
        
        try (Connection conn = dataSource.getConnection();
             PreparedStatement stmt = conn.prepareStatement(sql)) {
            
            stmt.setString(1, emiratesId);
            
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    return mapUser(rs);
                }
            }
        }
        return null;
    }
    
    public void updateUser(User user) throws SQLException {
        String sql = "UPDATE users SET name = ?, email = ?, updated_at = NOW() WHERE id = ?";
        
        try (Connection conn = dataSource.getConnection();
             PreparedStatement stmt = conn.prepareStatement(sql)) {
            
            stmt.setString(1, user.getName());
            stmt.setString(2, user.getEmail());
            stmt.setLong(3, user.getId());
            
            stmt.executeUpdate();
        }
    }
}
```

---

## Node.js

**العربية:**
- قيّد أحجام الطلبات؛ تحقق ونظف المدخلات؛ اهرب المخرجات.
- تجنب `eval`، `child_process.exec` مع مدخلات المستخدم；استخدم `helmet` للرؤوس؛ `hpp` لتلوث المعاملات.
- قيّد معدل نقاط نهاية المصادقة؛ راقب صحة حلقة الأحداث؛ تعامل مع الاستثناءات غير الملتقطة بشكل نظيف.
- الكعكات: اضبط `secure`، `httpOnly`، `sameSite`；اضبط `NODE_ENV=production`.
- حافظ على الحزم محدثة؛ شغّل `npm audit`；استخدم linters أمان واختبار ReDoS.

**English:**
- Limit request sizes; validate and sanitize input; escape output.
- Avoid `eval`, `child_process.exec` with user input; use `helmet` for headers; `hpp` for parameter pollution.
- Rate limit auth endpoints; monitor event loop health; handle uncaught exceptions cleanly.
- Cookies: set `secure`, `httpOnly`, `sameSite`; set `NODE_ENV=production`.
- Keep packages updated; run `npm audit`; use security linters and ReDoS testing.

```javascript
// Node.js - UAE Express Security
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const hpp = require('hpp');
const mongoSanitize = require('express-mongo-sanitize');

const app = express();

// Security headers
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"],
      upgradeInsecureRequests: [],
    },
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true,
  },
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.',
});
app.use('/api/', limiter);

// Stricter rate limiting for auth endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  skipSuccessfulRequests: true,
});
app.use('/api/auth/', authLimiter);

// Prevent parameter pollution
app.use(hpp());

// Sanitize MongoDB queries
app.use(mongoSanitize());

// Body parser limits
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// Cookie settings
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: true,
    httpOnly: true,
    sameSite: 'strict',
    maxAge: 2 * 60 * 60 * 1000, // 2 hours
  },
}));

// Error handling
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

module.exports = app;
```

---

## PHP Configuration

**العربية:**
- php.ini الإنتاج: `expose_php=Off`، سجل الأخطاء لا تعرضها；قيد `allow_url_fopen/include`；اضبط `open_basedir`.
- عطل الدوال الخطرة；اضبط أعلام كعكة الجلسة (`Secure`، `HttpOnly`، `SameSite=Strict`)；فعّل وضع الجلسة الصارم.
- قيد حجم/عدد الرفع；اضبط حدود الموارد (الذاكرة، حجم POST، وقت التنفيذ).
- استخدم Snuffleupagus أو مشابه للتقوية الإضافية.

**English:**
- Production php.ini: `expose_php=Off`, log errors not display; restrict `allow_url_fopen/include`; set `open_basedir`.
- Disable dangerous functions; set session cookie flags (`Secure`, `HttpOnly`, `SameSite=Strict`); enable strict session mode.
- Constrain upload size/number; set resource limits (memory, post size, execution time).
- Use Snuffleupagus or similar for additional hardening.

```ini
; php.ini - UAE Production Configuration
expose_php = Off
display_errors = Off
log_errors = On
error_log = /var/log/php/errors.log

; Restrict dangerous functions
disable_functions = exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source

; File uploads
file_uploads = On
upload_max_filesize = 10M
max_file_uploads = 5
upload_tmp_dir = /var/www/uploads/tmp

; Resource limits
memory_limit = 256M
post_max_size = 10M
max_execution_time = 30
max_input_time = 60
max_input_vars = 1000

; Session security
session.cookie_httponly = 1
session.cookie_secure = 1
session.cookie_samesite = "Strict"
session.use_strict_mode = 1
session.use_only_cookies = 1
session.gc_maxlifetime = 3600

; URL restrictions
allow_url_fopen = Off
allow_url_include = Off

; Open basedir restriction
open_basedir = /var/www/html:/var/www/uploads:/tmp
```

---

## قائمة التحقق — Implementation Checklist

- [ ] استخدم حمايات CSRF/XSS/الجلسات المدمجة لكل إطار وأعلام الكعكات الآمنة
- [ ] معاملات جميع وصول البيانات；تجنب دوال OS/exec الخطرة مع مدخلات غير موثوقة
- [ ] افرض HTTPS/HSTS；اضبط رؤوس آمنة
- [ ] مركز إدارة الأسرار；لا تُضمن أسرار أبداً；اقفل التصحيح في الإنتاج
- [ ] تحقق/قائمة سماح لإعادة التوجيه والمعرفات الديناميكية
- [ ] حافظ على التبعيات والأطر محدثة；شغّل SCA وتحليلاً ثابتاً بانتظام

---

## مراجع — References

- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [Django Security Documentation](https://docs.djangoproject.com/en/stable/topics/security/)
- [Laravel Security](https://laravel.com/docs/security)
- [Symfony Security](https://symfony.com/doc/current/security.html)
- [Rails Security Guide](https://guides.rubyonrails.org/security.html)
- [ASP.NET Core Security](https://docs.microsoft.com/en-us/aspnet/core/security/)
- [Node.js Security Best Practices](https://nodejs.org/en/docs/guides/security/)
- [PHP Security Consortium](https://phpsec.org/)
- [UAE Information Assurance Framework](https://www.tra.gov.ae/)
