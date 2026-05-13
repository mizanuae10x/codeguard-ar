---
description: لا اعتمادات مُضمَّنة — No Hardcoded Credentials
languages: []
tags:
- secrets
- credentials
- uae
alwaysApply: true
---

# لا اعتمادات مُضمَّنة — No Hardcoded Credentials

## نظرة عامة — Overview

**لا تخزن** أبداً أسرار أو كلمات مرور أو مفاتيح API أو رموز أو أي اعتمادات أخرى مباشرة في كود المصدر.

NEVER store secrets, passwords, API keys, tokens or any other credentials directly in source code.

**العربية:**
عامل قاعدة الكود الخاصة بك كعامة وغير موثوقة. أي اعتماد يظهر في كود المصدر مُخترق ويجب التعامل معه من خلال بدائل آمنة.

**English:**
Treat your codebase as public and untrusted. Any credential that appears in source code is compromised and must be handled through secure alternatives.

---

## ما يجب ألا تُضمنه أبداً — NEVER hardcode these types of values

### كلمات المرور والمصادقة — Passwords and Authentication

**العربية:**

**English:**

- ❌ كلمات مرور قواعد البيانات، كلمات مرور المستخدمين، كلمات مرور المسؤولين
- ❌ مفاتيح API، مفاتيح سرية، رموز وصول، رموز تجديد
- ❌ مفاتيح خاصة، شهادات، مفاتيح توقيع
- ❌ سلاسل اتصال تحتوي على اعتمادات
- ❌ أسرار عميل OAuth، أسرار webhook
- ❌ أي اعتمادات أخرى يمكن استخدامها للوصول إلى خدمات خارجية

---

## أنماط التعرف — Recognition Patterns

### تنسيقات الأسرار الشائعة التي يجب ألا تُضمن أبداً — Common Secret Formats You Must NEVER Hardcode

**العربية:**

**English:**

| النوع — Type | النمط — Pattern | مثال — Example |
|---|---|---|
| AWS Keys | تبدأ بـ `AKIA`، `AGPA`، `AIDA`، `AROA`، `AIPA`، `ANPA`، `ANVA`، `ASIA` | `AKIAIOSFODNN7EXAMPLE` |
| Stripe Keys | تبدأ بـ `sk_live_`، `pk_live_`، `sk_test_`، `pk_test_` | `sk_live_51Hx...` |
| Google API | تبدأ بـ `AIza` متبوعة بـ 35 حرفاً | `AIzaSyB-...` |
| GitHub Tokens | تبدأ بـ `ghp_`، `gho_`، `ghu_`، `ghs_`، `ghr_` | `ghp_xxxxxxxxxxxx` |
| JWT Tokens | ثلاث أقسام base64 مفصولة بنقاط، تبدأ بـ `eyJ` | `eyJhbGciOiJIUzI1NiIs...` |
| Private Key Blocks | أي نص بين `-----BEGIN` و`-----END PRIVATE KEY-----` | `-----BEGIN RSA PRIVATE KEY-----` |
| Connection Strings | عناوين URL مع اعتمادات مثل `mongodb://user:pass@host` | `mongodb://admin:secret@db:27017` |

---

## علامات التحذير في الكود — Warning Signs in Your Code

**العربية:**

**English:**

- ⚠️ أسماء متغيرات تحتوي على: `password`، `secret`، `key`، `token`، `auth`
- ⚠️ سلاسل عشوائية طويلة غير واضحة ما هي
- ⚠️ سلاسل مشفرة base64 بالقرب من كود المصادقة
- ⚠️ أي سلسلة تمنح وصولاً إلى خدمات خارجية

---

## البدائل الآمنة — Secure Alternatives

### 1. متغيرات البيئة — Environment Variables

```python
# ✅ Secure - Use environment variables
import os

# Database credentials
DB_PASSWORD = os.environ.get('DB_PASSWORD')
DB_HOST = os.environ.get('DB_HOST', 'localhost')

# API keys
STRIPE_SECRET_KEY = os.environ.get('STRIPE_SECRET_KEY')
AWS_ACCESS_KEY = os.environ.get('AWS_ACCESS_KEY_ID')

# Validate required variables
if not DB_PASSWORD:
    raise ValueError("DB_PASSWORD environment variable is required")
```

### 2. مديرو الأسرار — Secret Managers

```python
# ✅ Secure - Use AWS Secrets Manager
import boto3
import json

class UAESecretManager:
    """Secure secret retrieval for UAE applications"""
    
    def __init__(self, region='me-central-1'):
        self.client = boto3.client('secretsmanager', region_name=region)
    
    def get_secret(self, secret_name: str) -> dict:
        """Retrieve secret from AWS Secrets Manager"""
        try:
            response = self.client.get_secret_value(SecretId=secret_name)
            return json.loads(response['SecretString'])
        except Exception as e:
            raise ValueError(f"Failed to retrieve secret {secret_name}: {e}")

# Usage
secrets = UAESecretManager()
db_creds = secrets.get_secret('uae/production/database')
```

### 3. ملفات التكوين الخارجية — External Config Files

```yaml
# config/secrets.yml (not in version control!)
database:
  password: "${DB_PASSWORD}"
  host: "${DB_HOST}"

api_keys:
  stripe: "${STRIPE_SECRET_KEY}"
  google: "${GOOGLE_API_KEY}"
```

### 4. HashiCorp Vault — Vault

```python
# ✅ Secure - Use HashiCorp Vault
import hvac

class UAEVaultClient:
    """HashiCorp Vault client for UAE applications"""
    
    def __init__(self, vault_url: str, token: str):
        self.client = hvac.Client(url=vault_url, token=token)
    
    def get_database_credentials(self, path: str = 'uae/database'):
        """Retrieve dynamic database credentials"""
        response = self.client.secrets.database.generate_credentials(
            name='uae-postgres-role'
        )
        return response['data']
```

---

## أمثلة على الكود الآمن — Secure Code Examples

### Python

```python
# ❌ BAD - Hardcoded credentials
DB_PASSWORD = "SuperSecret123!"
API_KEY = "sk_live_51Hx..."

# ✅ GOOD - Environment variables
import os

DB_PASSWORD = os.environ['DB_PASSWORD']
API_KEY = os.environ['STRIPE_SECRET_KEY']
```

### Node.js

```javascript
// ❌ BAD - Hardcoded credentials
const dbPassword = 'SuperSecret123!';
const apiKey = 'sk_live_51Hx...';

// ✅ GOOD - Environment variables
const dbPassword = process.env.DB_PASSWORD;
const apiKey = process.env.STRIPE_SECRET_KEY;

if (!dbPassword || !apiKey) {
    throw new Error('Required environment variables are missing');
}
```

### Java

```java
// ❌ BAD - Hardcoded credentials
String dbPassword = "SuperSecret123!";
String apiKey = "sk_live_51Hx...";

// ✅ GOOD - Environment variables
String dbPassword = System.getenv("DB_PASSWORD");
String apiKey = System.getenv("STRIPE_SECRET_KEY");

if (dbPassword == null || apiKey == null) {
    throw new IllegalStateException("Required environment variables are missing");
}
```

### .NET

```csharp
// ❌ BAD - Hardcoded credentials
var dbPassword = "SuperSecret123!";
var apiKey = "sk_live_51Hx...";

// ✅ GOOD - Environment variables or Azure Key Vault
var dbPassword = Environment.GetEnvironmentVariable("DB_PASSWORD");
var apiKey = Environment.GetEnvironmentVariable("STRIPE_SECRET_KEY");

// Or use Azure Key Vault
var secretClient = new SecretClient(
    new Uri("https://uae-keyvault.vault.azure.net/"),
    new DefaultAzureCredential()
);
var secret = await secretClient.GetSecretAsync("db-password");
```

---

## أدوات الكشف — Detection Tools

**العربية:**

**English:**

```bash
# GitLeaks - Scan for secrets in git history
gitleaks detect --source . --verbose

# TruffleHog - Scan for high-entropy secrets
trufflehog filesystem .

# Git-secrets - Prevent committing secrets
git secrets --scan

# Detect-secrets - Scan for secrets
detect-secrets scan --all-files

# Pre-commit hook
cat > .git/hooks/pre-commit << 'EOF'
#!/bin/bash
# Scan for secrets before commit
if gitleaks detect --source . --verbose; then
    echo "No secrets found"
else
    echo "Secrets detected! Commit aborted."
    exit 1
fi
EOF
chmod +x .git/hooks/pre-commit
```

---

## قائمة التحقق — Implementation Checklist

- [ ] لا كلمات مرور مُضمَّنة
- [ ] لا مفاتيح API مُضمَّنة
- [ ] لا رموز وصول مُضمَّنة
- [ ] لا مفاتيح خاصة مُضمَّنة
- [ ] لا شهادات مُضمَّنة
- [ ] لا سلاسل اتصال تحتوي على اعتمادات
- [ ] متغيرات البيئة للتطوير المحلي
- [ ] مدير أسرار للإنتاج (AWS Secrets Manager, Azure Key Vault, HashiCorp Vault)
- [ ] فحوصات pre-commit لكشف الأسرار
- [ ] فحوصات CI/CD لكشف الأسرار
- [ ] تدوير الأسرار بانتظام
- [ ] مراقبة الوصول إلى الأسرار
- [ ] تسجيل استخدام الأسرار

---

## مراجع — References

- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
- [AWS Secrets Manager Best Practices](https://docs.aws.amazon.com/secretsmanager/latest/userguide/best-practices.html)
- [Azure Key Vault Best Practices](https://docs.microsoft.com/en-us/azure/key-vault/general/best-practices)
- [HashiCorp Vault Documentation](https://www.vaultproject.io/docs)
- [GitLeaks - Secret Scanner](https://github.com/zricethezav/gitleaks)
- [TruffleHog - Secret Scanner](https://github.com/trufflesecurity/trufflehog)
- [UAE Information Assurance Framework](https://www.tra.gov.ae/)
