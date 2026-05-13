---
description: أمان البيانات والتخزين (عزل قاعدة البيانات، TLS، أقل امتياز، RLS/CLS، نسخ احتياطي، تدقيق)
languages:
- c
- javascript
- sql
- yaml
tags:
- data-security
- infrastructure
- uae
alwaysApply: false
---

# أمان قواعد البيانات — Database Security Guidelines

## نظرة عامة — Overview

يقدم هذا القسم إرشادات لتكوين قواعد بيانات SQL وNoSQL بأمان لحماية البيانات من الاختراق والوصول غير المصرح به.

This section advises on securely configuring SQL and NoSQL databases to protect against data breaches and unauthorized access.

---

## حماية قاعدة البيانات الخلفية — Backend Database Protection

**العربية:**
- عزل خوادم قواعد البيانات عن الأنظمة الأخرى
- حدد اتصالات المضيف
- عطل وصول الشبكة (TCP) عندما يكون ممكناً
- استخدم ملفات المقبس المحلية أو الأنابيب المسماة
- اربط قاعدة البيانات على localhost فقط عند الاقتباس
- قصر وصول المنفذ الشبكي على مضيفين محددين بقواعد جدار الحماية
- ضع خادم قاعدة البيانات في DMZ منفصلة
- لا تسمح أبداً باتصالات مباشرة من العملاء السميكة

**English:**
- Isolate database servers from other systems
- Limit host connections
- Disable network (TCP) access when possible
- Use local socket files or named pipes
- Configure database to bind only on localhost when appropriate
- Restrict network port access to specific hosts with firewall rules
- Place database server in separate DMZ isolated from application server
- Never allow direct connections from thick clients to backend database

```yaml
# Kubernetes Network Policy for Database Isolation
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: database-isolation
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: postgres
      tier: database
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: uae-api
              tier: backend
      ports:
        - protocol: TCP
          port: 5432
  egress:
    - to:
        - podSelector:
            matchLabels:
              app: postgres-backup
      ports:
        - protocol: TCP
          port: 5432
```

---

## أمان طبقة النقل — Transport Layer Security

**العربية:**
- اربط قاعدة البيانات للسماح فقط بالاتصالات المشفرة
- ثبت شهادات رقمية موثوقة على خوادم قواعد البيانات
- استخدم TLSv1.2+ مع تشفيرات حديثة (AES-GCM، ChaCha20)
- تحقق من صلاحية الشهادة الرقمية في تطبيقات العميل
- تأكد من تشفير جميع حركة مرور قاعدة البيانات

**English:**
- Configure database to only allow encrypted connections
- Install trusted digital certificates on database servers
- Use TLSv1.2+ with modern ciphers (AES-GCM, ChaCha20)
- Verify digital certificate validity in client applications
- Ensure all database traffic is encrypted

```ini
# PostgreSQL SSL Configuration (postgresql.conf)
ssl = on
ssl_cert_file = '/etc/ssl/certs/server.crt'
ssl_key_file = '/etc/ssl/private/server.key'
ssl_ca_file = '/etc/ssl/certs/ca.crt'
ssl_crl_file = '/etc/ssl/certs/server.crl'
ssl_ciphers = 'HIGH:!aNULL:!MD5'
ssl_min_protocol_version = 'TLSv1.2'

# Require SSL for all connections
hostssl all all 0.0.0.0/0 scram-sha-256
```

---

## تكوين المصادقة الآمنة — Secure Authentication Configuration

**العربية:**
- تتطلب المصادقة دائماً، بما في ذلك من الاتصالات المحلية
- حماية الحسابات بكلمات مرور قوية وفريدة
- استخدم حسابات مخصصة لكل تطبيق أو خدمة
- امنح الحد الأدنى من الأذونات المطلوبة فقط
- راجع الحسابات والأذونات بانتظام
- أزل الحسابات عند إيقاف التطبيقات
- غير كلمات المرور عند مغادرة الموظفين أو الاشتباه في اختراق

**English:**
- Always require authentication, including from local server connections
- Protect accounts with strong, unique passwords
- Use dedicated accounts per application or service
- Configure minimum required permissions only
- Regularly review accounts and permissions
- Remove accounts when applications are decommissioned
- Change passwords when staff leave or compromise is suspected

```sql
-- PostgreSQL Secure User Setup
-- Create application-specific user with minimal privileges
CREATE USER uae_app_user WITH PASSWORD 'strong_random_password';

-- Grant only required permissions
GRANT CONNECT ON DATABASE uae_gov_db TO uae_app_user;
GRANT USAGE ON SCHEMA public TO uae_app_user;
GRANT SELECT, INSERT, UPDATE ON TABLE citizens, documents TO uae_app_user;

-- Explicitly deny dangerous permissions
REVOKE ALL ON TABLE admin_logs, security_events FROM uae_app_user;

-- Set connection limit
ALTER USER uae_app_user WITH CONNECTION LIMIT 20;

-- Require SSL
ALTER USER uae_app_user WITH REQUIRE SSL;
```

---

## تخزين بيانات الاعتماد — Database Credential Storage

**العربية:**
- لا تخزن بيانات الاعتماد في كود التطبيق
- خزنها في ملفات إعداد خارج web root
- ضع أذونات ملف مناسبة
- لا تُدخل ملفات بيانات الاعتماد في مستودعات الكود
- استخدم متغيرات البيئة أو حلول إدارة الأسرار

**English:**
- Never store credentials in application source code
- Store credentials in configuration files outside web root
- Set appropriate file permissions for credential access
- Never check credential files into source code repositories
- Use environment variables or secrets management solutions

```python
# Python Secure Credential Management
import os
from dataclasses import dataclass

@dataclass
class DatabaseCredentials:
    """
    UAE-compliant database credentials
    """
    host: str
    port: int
    database: str
    username: str
    password: str
    ssl_mode: str = 'verify-full'
    ssl_root_cert: str = None

class UAECredentialManager:
    """
    Secure credential management for UAE government systems
    """
    
    @staticmethod
    def get_database_credentials() -> DatabaseCredentials:
        """
        Retrieve database credentials from secure sources
        Priority: Environment > Secrets Manager > Config File
        """
        # 1. Try environment variables (for local development)
        if os.getenv('DB_PASSWORD'):
            return DatabaseCredentials(
                host=os.getenv('DB_HOST', 'localhost'),
                port=int(os.getenv('DB_PORT', '5432')),
                database=os.getenv('DB_NAME', 'uae_gov_db'),
                username=os.getenv('DB_USER'),
                password=os.getenv('DB_PASSWORD'),
                ssl_mode=os.getenv('DB_SSL_MODE', 'verify-full'),
                ssl_root_cert=os.getenv('DB_SSL_ROOT_CERT')
            )
        
        # 2. Try cloud secrets manager (production)
        try:
            return UAECredentialManager._get_from_azure_keyvault()
        except:
            pass
        
        try:
            return UAECredentialManager._get_from_aws_secrets_manager()
        except:
            pass
        
        raise SecurityError('No secure credential source available')
    
    @staticmethod
    def _get_from_azure_keyvault():
        """Retrieve credentials from Azure Key Vault"""
        from azure.identity import DefaultAzureCredential
        from azure.keyvault.secrets import SecretClient
        
        credential = DefaultAzureCredential()
        client = SecretClient(
            vault_url="https://uae-gov-kv.vault.azure.net/",
            credential=credential
        )
        
        return DatabaseCredentials(
            host=client.get_secret('db-host').value,
            port=int(client.get_secret('db-port').value),
            database=client.get_secret('db-name').value,
            username=client.get_secret('db-user').value,
            password=client.get_secret('db-password').value,
            ssl_mode='verify-full',
            ssl_root_cert='/etc/ssl/certs/ca.crt'
        )
```

---

## إدارة الأذونات الآمنة — Secure Permission Management

**العربية:**
- طبق مبدأ أقل الامتياز على جميع حسابات قاعدة البيانات
- لا تستخدم حسابات root أو sa أو SYS المدمجة
- لا تمنح حقوق إدارية لحسابات التطبيق
- قصر اتصالات الحساب على المضيفين المسموح بهم فقط
- استخدم قواعد بيانات وحسابات منفصلة للتطوير والاختبار والإنتاج
- امنح فقط الأذونات المطلوبة (SELECT، UPDATE، DELETE حسب الحاجة)
- تجنب جعل الحسابات مالكين لقاعدة البيانات

**English:**
- Apply principle of least privilege to all database accounts
- Do not use built-in root, sa, or SYS accounts
- Do not grant administrative rights to application accounts
- Restrict account connections to allowed hosts only
- Use separate databases and accounts for Dev, UAT, and Production
- Grant only required permissions (SELECT, UPDATE, DELETE as needed)
- Avoid making accounts database owners to prevent privilege escalation

```sql
-- PostgreSQL Row-Level Security (RLS) for UAE Government
-- Enable RLS on sensitive tables
ALTER TABLE citizens ENABLE ROW LEVEL SECURITY;
ALTER TABLE classified_documents ENABLE ROW LEVEL SECURITY;

-- Create policy for citizens table
CREATE POLICY citizen_self_access ON citizens
    FOR ALL
    TO uae_app_user
    USING (emirates_id = current_setting('app.current_user_emirates_id')::text);

-- Create policy for department-based access
CREATE POLICY department_document_access ON classified_documents
    FOR SELECT
    TO uae_app_user
    USING (
        department_id = current_setting('app.current_user_department_id')::int
        OR clearance_level <= current_setting('app.current_user_clearance')::int
    );

-- Force RLS for table owners
ALTER TABLE citizens FORCE ROW LEVEL SECURITY;
ALTER TABLE classified_documents FORCE ROW LEVEL SECURITY;
```

---

## التكوين والتصليب — Database Configuration and Hardening

**العربية:**
- ثبت تحديثات الأمان والتصحيحات بانتظام
- شغل خدمات قاعدة البيانات تحت حسابات مستخدمين منخفضي الامتياز
- أزل الحسابات الافتراضية وقواعد البيانات النموذجية
- خزن سجلات المعاملات على قرص منفصل عن ملفات قاعدة البيانات الرئيسية
- اضبط نسخاً احتياطية مشفرة بانتظام
- عطل الإجراءات المخزنة غير الضرورية والميزات الخطرة
- نفذ مراقبة نشاط قاعدة البيانات والتنبيهات

**English:**
- Install required security updates and patches regularly
- Run database services under low-privileged user accounts
- Remove default accounts and sample databases
- Store transaction logs on separate disk from main database files
- Configure regular encrypted database backups with proper permissions
- Disable unnecessary stored procedures and dangerous features
- Implement database activity monitoring and alerting

```bash
#!/bin/bash
# PostgreSQL Hardening Script for UAE Government

# Run as postgres user

# Remove default databases
dropdb template0 2>/dev/null || true
dropdb template1 2>/dev/null || true

# Remove sample data
psql -c "DROP SCHEMA IF EXISTS public CASCADE;"

# Secure configuration
psql -c "ALTER SYSTEM SET password_encryption = 'scram-sha-256';"
psql -c "ALTER SYSTEM SET ssl = on;"
psql -c "ALTER SYSTEM SET ssl_min_protocol_version = 'TLSv1.2';"
psql -c "ALTER SYSTEM SET log_connections = on;"
psql -c "ALTER SYSTEM SET log_disconnections = on;"
psql -c "ALTER SYSTEM SET log_statement = 'mod';"
psql -c "ALTER SYSTEM SET log_min_duration_statement = 1000;"

# Disable dangerous features
psql -c "ALTER SYSTEM SET allow_system_table_mods = off;"
psql -c "ALTER SYSTEM SET ignore_system_indexes = off;"

# Reload configuration
psql -c "SELECT pg_reload_conf();"
```

---

## التصليب الخاص بالمنصة — Platform-Specific Hardening

### SQL Server
```sql
-- Disable xp_cmdshell
EXEC sp_configure 'xp_cmdshell', 0;
RECONFIGURE;

-- Disable CLR execution
EXEC sp_configure 'clr enabled', 0;
RECONFIGURE;

-- Disable SQL Browser service
-- (via Windows Services)

-- Use Windows Authentication when possible
-- Avoid Mixed Mode unless required
```

### MySQL/MariaDB
```sql
-- Run mysql_secure_installation
-- Then apply additional hardening

-- Disable FILE privilege for users
REVOKE FILE ON *.* FROM 'app_user'@'%';

-- Disable LOCAL INFILE
SET GLOBAL local_infile = 0;

-- Secure log files
SET GLOBAL log_error = '/var/log/mysql/error.log';
SET GLOBAL general_log_file = '/var/log/mysql/general.log';
SET GLOBAL slow_query_log_file = '/var/log/mysql/slow.log';
```

### PostgreSQL
```ini
# postgresql.conf security settings
ssl = on
ssl_cert_file = '/etc/ssl/certs/server.crt'
ssl_key_file = '/etc/ssl/private/server.key'
ssl_ca_file = '/etc/ssl/certs/ca.crt'

# Logging
log_destination = 'syslog,csvlog'
logging_collector = on
log_directory = '/var/log/postgresql'
log_filename = 'postgresql-%Y-%m-%d_%H%M%S.log'
log_statement = 'mod'
log_min_duration_statement = 1000
log_connections = on
log_disconnections = on

# Authentication
password_encryption = scram-sha-256
auth_delay.milliseconds = 500
```

### MongoDB
```javascript
// MongoDB Security Configuration
// Enable authentication
security:
  authorization: enabled
  javascriptEnabled: false  // Disable server-side JS

// Network
net:
  bindIp: 127.0.0.1  // Or specific IPs
  port: 27017
  ssl:
    mode: requireSSL
    PEMKeyFile: /etc/ssl/mongodb.pem
    CAFile: /etc/ssl/ca.crt

// Audit
auditLog:
  destination: file
  format: JSON
  path: /var/log/mongodb/audit.log
```

### Redis
```conf
# redis.conf security settings
bind 127.0.0.1
protected-mode yes
requirepass strong_password_here

# Disable dangerous commands
rename-command FLUSHALL ""
rename-command FLUSHDB ""
rename-command CONFIG ""
rename-command DEBUG ""
rename-command SHUTDOWN ""

# Enable TLS (Redis 6+)
tls-port 6379
port 0
tls-cert-file /etc/ssl/redis.crt
tls-key-file /etc/ssl/redis.key
tls-ca-cert-file /etc/ssl/ca.crt
```

---

## النسخ الاحتياطي والاسترداد — Backup and Recovery

**العربية:**
- نسخ احتياطي يومي كامل
- نسخ احتياطي تزايدي كل ساعة
- تخزين النسخ الاحتياطية في موقع منفصل جغرافياً
- تشفير النسخ الاحتياطية
- اختبار الاسترداد شهرياً
- الاحتفاظ بالنسخ الاحتياطية لمدة 7 سنوات (للبيانات الحكومية)

**English:**
- Daily full backups
- Hourly incremental backups
- Store backups in geographically separate location
- Encrypt all backups
- Test recovery monthly
- Retain backups for 7 years (government data)

```bash
#!/bin/bash
# UAE Government Database Backup Script

BACKUP_DIR="/backup/postgres"
ENCRYPTION_KEY="/etc/backup/encryption.key"
RETENTION_DAYS=2555  # 7 years

# Create encrypted backup
pg_dump -h localhost -U backup_user \
    --format=custom \
    --compress=9 \
    uae_gov_db | \
    openssl enc -aes-256-cbc -salt -pass file:$ENCRYPTION_KEY \
    > "$BACKUP_DIR/uae_gov_db_$(date +%Y%m%d_%H%M%S).dump.enc"

# Upload to secure storage
aws s3 cp "$BACKUP_DIR" s3://uae-gov-backups/postgres/ \
    --sse aws:kms \
    --sse-kms-key-id alias/uae-gov-backup-key

# Clean old backups
find "$BACKUP_DIR" -type f -mtime +$RETENTION_DAYS -delete
```

---

## قائمة التحقق — Implementation Checklist

- [ ] خوادم قواعد البيانات معزولة
- [ ] وصول الشبكة مقيد
- [ ] جميع الاتصالات مشفرة (TLS 1.2+)
- [ ] شهادات موثوقة مثبتة
- [ ] المصادقة مطلوبة دائماً
- [ ] كلمات مرور قوية وفريدة
- [ ] حسابات مخصصة لكل تطبيق
- [ ] أقل الامتياز مطبق
- [ ] بيانات الاعتماد مخزنة بأمان
- [ ] RLS/CLS مُمكّن للبيانات الحساسة
- [ ] تحديثات الأمان منتظمة
- [ ] الحسابات الافتراضية مُزالة
- [ ] سجلات المعاملات منفصلة
- [ ] نسخ احتياطية مشفرة
- [ ] مراقبة النشاط مُفعلة
- [ ] الإجراءات الخطرة مُعطلة
- [ ] اختبار الاسترداد شهري

---

## خطة الاختبار — Test Plan

- [ ] اختبار الاتصال المشفر فقط
- [ ] اختبار رفض الاتصالات غير المشفرة
- [ ] اختبار صلاحية الشهادات
- [ ] اختبار أذونات الحسابات
- [ ] اختبار RLS/CLS
- [ ] اختبار النسخ الاحتياطي والاسترداد
- [ ] اختبار مراقبة النشاط
- [ ] اختبار رفض الأوامر الخطرة

---

## مراجع — References

- [OWASP Database Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html)
- [CIS Database Benchmarks](https://www.cisecurity.org/cis-benchmarks)
- [PostgreSQL Security Documentation](https://www.postgresql.org/docs/current/security.html)
- [UAE Information Assurance Framework](https://www.tra.gov.ae/)
