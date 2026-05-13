---
description: أمان البنية التحتية ككود (IaC)
languages:
- c
- d
- javascript
- powershell
- ruby
- shell
- yaml
tags:
- infrastructure
- iac
- terraform
- uae
alwaysApply: false
---

# أمان البنية التحتية ككود — Infrastructure as Code (IaC) Security

## نظرة عامة — Overview

عند تصميم البنية التحتية السحابية وكتابة Infrastructure as Code (IaC) بلغات مثل Terraform وCloudFormation، استخدم دائماً الممارسات والإعدادات الافتراضية الآمنة مثل منع التعرض العام واتبع مبدأ أقل الامتياز. حدد بنشاط التكوينات الأمنية الخاطئة وقدم بدائل آمنة.

When designing cloud infrastructure and writing Infrastructure as Code (IaC) in languages like Terraform and CloudFormation, always use secure practices and defaults such as preventing public exposure and follow the principle of least privilege. Actively identify security misconfigurations and provide secure alternatives.

---

## أنماط الأمان الحرجة في IaC — Critical Security Patterns In Infrastructure as Code

### أمان الشبكة — Network Security

**العربية:**
- **دائماً** قصر الوصول إلى الخدمات الإدارية البعيدة وقواعد البيانات وLDAP وTACACS+ أو الخدمات الحساسة الأخرى. لا يجب أن تكون أي خدمة متاحة من الإنترنت بأكمله إذا لم تكن بحاجة إلى ذلك. بدلاً من ذلك، قصر الوصول على مجموعة محددة من عناوين IP أو كتل CIDR التي تتطلب الوصول.
- قواعد الدخول لمجموعات الأمان وACL يجب **ألا تسمح أبداً** بـ `0.0.0.0/0` للمنافذ الإدارية البعيدة (مثل SSH 22، RDP 3389).
- قواعد الدخول لمجموعات الأمان وACL يجب **ألا تسمح أبداً** بـ `0.0.0.0/0` لمنافذ قواعد البيانات (مثل 3306، 5432، 1433، 1521، 27017).
- قوائم السماح لنقاط نهاية Kubernetes API يجب **ألا تسمح أبداً** بـ `0.0.0.0/0`.
- **أبداً** لا تعرض خدمات قواعد البيانات السحابية (RDS، Azure SQL، Cloud SQL) لجميع عناوين IP `0.0.0.0/0`.
- فضّل بشكل عام الشبكات الخاصة، مثل VPC الداخلية، VNET، VPN، أو وسائل نقل داخلية أخرى ما لم يكن الوصول إلى الشبكة العامة مطلوباً.
- **دائماً** فعّل سجلات تدفق VPC/VNET للمراقبة الشبكية وتحليل الأمان.
- **دائماً** نفذ قواعد الرفض الافتراضي وقواعد السماح الصريحة للحركة المطلوبة فقط.
- فضّل بشكل عام حجب حركة الخروج إلى الإنترنت افتراضياً.

**English:**
- **ALWAYS** restrict access to remote administrative services, databases, LDAP, TACACS+, or other sensitive services. No service should be accessible from the entire Internet if it does not need to be.
- Security Group and ACL inbound rules should **NEVER** allow `0.0.0.0/0` to remote administration ports.
- Security Group and ACL inbound rules should **NEVER** allow `0.0.0.0/0` to database ports.
- Kubernetes API endpoints allow lists should **NEVER** allow `0.0.0.0/0`.
- **NEVER** expose cloud platform database services to all IP addresses `0.0.0.0/0`.
- Generally prefer private networking unless public network access is required.
- **ALWAYS** enable VPC/VNET flow logs for network monitoring and security analysis.
- **ALWAYS** implement default deny rules and explicit allow rules for required traffic only.
- Generally prefer blocking egress traffic to the Internet by default.

```hcl
# Terraform: Secure AWS Security Group for UAE
resource "aws_security_group" "uae_admin_access" {
  name        = "uae-admin-access"
  description = "Restricted admin access for UAE operations"
  vpc_id      = aws_vpc.uae_vpc.id

  # Allow SSH only from UAE government IP ranges
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [
      "185.54.16.0/22",    # UAE Government Network
      "10.0.0.0/8",        # Internal VPN
    ]
    description = "SSH from UAE gov and internal VPN only"
  }

  # Allow RDP only from specific admin workstations
  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = [
      "10.10.100.0/24",    # Admin subnet
    ]
    description = "RDP from admin subnet only"
  }

  # Database access from application tier only
  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.uae_app_tier.id]
    description     = "PostgreSQL from app tier only"
  }

  # Deny all other inbound
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = []
    description = "Default deny"
  }

  # Controlled egress
  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS outbound only"
  }

  tags = {
    Name        = "uae-admin-access"
    Compliance  = "DESC"
    Environment = "production"
  }
}
```

---

### حماية البيانات — Data Protection

**العربية:**
- **دائماً** اضبط تشفير البيانات في حالة السكون لجميع خدمات التخزين بما في ذلك قواعد البيانات وأنظمة الملفات والتخزين الكائني والتخزين الكتلي.
- **دائماً** اضبط التشفير أثناء النقل لجميع اتصالات البيانات.
- **دائماً** نفذ تصنيف البيانات وضوابط الحماية بناءً على مستويات الحساسية.
- **دائماً** اضبط سياسات الاحتفاظ والتخلص الآمن من البيانات.
- **دائماً** فعّل المراقبة الشاملة للوصول إلى البيانات والتدقيق.
- **دائماً** شفر نسخ البيانات الاحتياطية.

**English:**
- **ALWAYS** configure data encryption at rest for all storage services.
- **ALWAYS** configure encryption in transit for all data communications.
- **ALWAYS** implement data classification and protection controls based on sensitivity levels.
- **ALWAYS** configure secure data retention and disposal policies.
- **ALWAYS** enable comprehensive data access monitoring and auditing.
- **ALWAYS** encrypt data backups.

```hcl
# Terraform: Encrypted S3 Bucket for UAE Government
resource "aws_s3_bucket" "uae_gov_data" {
  bucket = "uae-government-data-${var.environment}"

  tags = {
    Name           = "UAE Government Data"
    Classification = "CONFIDENTIAL"
    Compliance     = "DESC"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "uae_encryption" {
  bucket = aws_s3_bucket.uae_gov_data.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.uae_data_key.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_kms_key" "uae_data_key" {
  description             = "KMS key for UAE government data encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow UAE Government Services"
        Effect = "Allow"
        Principal = {
          AWS = [
            "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/uae-app-role",
          ]
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:GenerateDataKey*",
        ]
        Resource = "*"
      }
    ]
  })
}
```

---

### التحكم بالوصول — Access Control

**العربية:**
- **أبداً** لا تترك الخدمات الإدارية أو خدمات البيانات الحرجة مع وصول مجهول.
- **أبداً** لا تستخدم أذونات بدلية في سياسات IAM أو RBAC السحابي (`"Action": "*"`, `"Resource": "*"`).
- **أبداً** لا تمنح حسابات الخدمة امتيازات مفرطة بأدوار Owner/Admin عندما لا يكون ذلك ضرورياً.
- **أبداً** لا تستخدم مفاتيح API للخدمة والأسرار العميلة وبدلاً من ذلك استخدم هوية حمل العمل مع التحكم بالوصول المبني على الأدوار.
- **أبداً** لا تُمكّن أو تستخدم IMDSv1 في AWS.
- **أبداً** لا تستخدم طرق مصادقة قديمة أو عفا عليها الزمن.

**English:**
- **NEVER** leave critical administration or data services with anonymous access.
- **NEVER** use wildcard permissions in IAM policies or cloud RBAC.
- **NEVER** overprivilege service accounts with Owner/Admin roles.
- **NEVER** use service API Keys and client secrets; use workload identity with RBAC.
- **NEVER** enable or use IMDSv1 in AWS.
- **NEVER** use legacy or outdated authentication methods.

```hcl
# Terraform: Secure IAM Policy for UAE
resource "aws_iam_policy" "uae_app_policy" {
  name        = "uae-app-policy"
  description = "Least privilege policy for UAE application"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "S3Access"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
        ]
        Resource = [
          "${aws_s3_bucket.uae_gov_data.arn}/uploads/*",
          "${aws_s3_bucket.uae_gov_data.arn}/temp/*",
        ]
      },
      {
        Sid    = "KMSAccess"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey",
        ]
        Resource = aws_kms_key.uae_data_key.arn
      },
      {
        Sid    = "CloudWatchLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
        ]
        Resource = "arn:aws:logs:*:*:log-group:/uae/*"
      }
    ]
  })
}

# Workload Identity (IRSA for EKS)
resource "aws_iam_role" "uae_app_role" {
  name = "uae-app-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Federated = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:oidc-provider/${aws_eks_cluster.uae_cluster.identity[0].oidc[0].issuer}"
        }
        Action = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringEquals = {
            "${aws_eks_cluster.uae_cluster.identity[0].oidc[0].issuer}:sub" = "system:serviceaccount:uae-production:uae-app-sa"
          }
        }
      }
    ]
  })
}
```

---

## إدارة الأسرار — Secrets Management

**العربية:**
- **أبداً** لا تُضمن الأسرار أو كلمات المرور أو مفاتيح API أو الشهادات مباشرة في كود IaC المصدري.
- **دائماً** في Terraform علّم الأسرار بـ `sensitive = true`، في كود IaC الآخر استخدم تعليقات توضيحية أو بيانات وصفية مناسبة للإشارة إلى القيم الحساسة.

**English:**
- **NEVER** hardcode secrets, passwords, API keys, or certificates directly in IaC source code.
- **ALWAYS** in Terraform mark secrets with "sensitive = true", in other IaC code use appropriate annotations or metadata to indicate sensitive values.

```hcl
# Terraform: Secure Secret Handling
variable "db_password" {
  description = "Database password"
  type        = string
  sensitive   = true  # Mark as sensitive
}

variable "api_key" {
  description = "External API key"
  type        = string
  sensitive   = true
}

# Use AWS Secrets Manager
resource "aws_secretsmanager_secret" "uae_db_password" {
  name                    = "uae/production/db-password"
  description             = "Database password for UAE production"
  kms_key_id             = aws_kms_key.uae_data_key.arn
  recovery_window_in_days = 30
}

resource "aws_secretsmanager_secret_version" "uae_db_password_value" {
  secret_id     = aws_secretsmanager_secret.uae_db_password.id
  secret_string = var.db_password
}

# Reference secret in RDS
resource "aws_db_instance" "uae_postgres" {
  identifier     = "uae-production-db"
  engine         = "postgres"
  instance_class = "db.r6g.xlarge"

  username = "uae_admin"
  password = var.db_password  # Still sensitive, but not hardcoded

  # Encryption
  storage_encrypted = true
  kms_key_id       = aws_kms_key.uae_data_key.arn

  # Security
  publicly_accessible = false
  vpc_security_group_ids = [aws_security_group.uae_db_access.id]
  db_subnet_group_name   = aws_db_subnet_group.uae_db_subnet.name

  # Backup
  backup_retention_period = 35
  backup_window          = "03:00-04:00"

  tags = {
    Compliance = "DESC"
    DataClass  = "CONFIDENTIAL"
  }
}
```

---

## التسجيل والوصول الإداري — Logging and Administrative Access

**العربية:**
- **أبداً** لا تعطل تسجيل النشاط الإداري للخدمات الحساسة.
- **دائماً** فعّل تسجيل المراجعة للعمليات المميزة.

**English:**
- **NEVER** disable administrative activity logging for sensitive services.
- **ALWAYS** enable audit logging for privileged operations.

```hcl
# Terraform: CloudTrail for UAE
resource "aws_cloudtrail" "uae_audit_trail" {
  name                          = "uae-audit-trail"
  s3_bucket_name                = aws_s3_bucket.uae_cloudtrail_logs.id
  include_global_service_events = true
  is_multi_region_trail        = true
  enable_logging               = true

  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type   = "AWS::S3::Object"
      values = ["${aws_s3_bucket.uae_gov_data.arn}/*"]
    }
  }

  kms_key_id = aws_kms_key.uae_data_key.arn

  tags = {
    Compliance = "DESC"
    Purpose    = "Audit"
  }
}

# VPC Flow Logs
resource "aws_flow_log" "uae_vpc_flow_logs" {
  vpc_id                   = aws_vpc.uae_vpc.id
  traffic_type             = "ALL"
  log_destination_type     = "cloud-watch-logs"
  log_destination          = aws_cloudwatch_log_group.uae_flow_logs.arn
  iam_role_arn             = aws_iam_role.uae_flow_logs_role.arn
  max_aggregation_interval = 60
}
```

---

## النسخ الاحتياطي واسترداد البيانات — Backup and Data Recovery

**العربية:**
- **أبداً** لا تنشئ نسخاً احتياطية بدون تشفير في حالة السكون وأثناء النقل.
- **دائماً** اضبط تخزين البيانات متعدد المناطق للنسخ الاحتياطية مع النسخ المتماثل عبر المناطق.
- **أبداً** لا تضبط النسخ الاحتياطية بدون سياسات الاحتفاظ وإدارة دورة الحياة.

**English:**
- **NEVER** create backups without encryption at rest and in transit.
- **ALWAYS** configure multi-region data storage for backups with cross-region replication.
- **NEVER** configure backups without retention policies and lifecycle management.

```hcl
# Terraform: Backup Configuration
resource "aws_backup_vault" "uae_backup_vault" {
  name        = "uae-backup-vault"
  kms_key_arn = aws_kms_key.uae_data_key.arn

  tags = {
    Compliance = "DESC"
  }
}

resource "aws_backup_plan" "uae_backup_plan" {
  name = "uae-production-backup"

  rule {
    rule_name         = "daily-backup"
    target_vault_name = aws_backup_vault.uae_backup_vault.name
    schedule          = "cron(0 5 ? * * *)"  # Daily at 5 AM UTC

    lifecycle {
      delete_after = 2555  # 7 years for government
    }

    copy_action {
      destination_vault_arn = aws_backup_vault.uae_backup_vault_secondary.arn
    }
  }

  rule {
    rule_name         = "monthly-archive"
    target_vault_name = aws_backup_vault.uae_backup_vault.name
    schedule          = "cron(0 5 1 * ? *)"  # Monthly

    lifecycle {
      cold_storage_after = 90
      delete_after       = 2555
    }
  }
}
```

---

## قائمة التحقق — Implementation Checklist

- [ ] قواعد مجموعة الأمان لا تسمح بـ 0.0.0.0/0 للمنافذ الإدارية
- [ ] قواعد مجموعة الأمان لا تسمح بـ 0.0.0.0/0 لقواعد البيانات
- [ ] نقاط نهاية Kubernetes API مقيدة
- [ ] خدمات قواعد البيانات السحابية غير عامة
- [ ] سجلات تدفق VPC/VNET مفعلة
- [ ] قواعد الرفض الافتراضي منفذة
- [ ] حركة الخروج محكومة
- [ ] التشفير في حالة السكون مفعل لجميع التخزين
- [ ] التشفير أثناء النقل مفعل (TLS 1.2+)
- [ ] تصنيف البيانات منفذ
- [ ] سياسات الاحتفاط والتخلص مكونة
- [ ] مراقبة الوصول إلى البيانات مفعلة
- [ ] نسخ البيانات الاحتياطية مشفرة
- [ ] لا وصول مجهول للخدمات الحرجة
- [ ] لا أذونات بدلية في IAM
- [ ] لا امتيازات مفرطة لحسابات الخدمة
- [ ] هوية حمل العمل مستخدمة بدلاً من مفاتيح API
- [ ] IMDSv1 معطل
- [ ] لا طرق مصادقة قديمة
- [ ] الصور مُصلَّبة
- [ ] التسجيل الإداري مفعل
- [ ] الأسرار لا تُضمن في كود IaC
- [ ] الأسرار مُعلَّمة كحساسة
- [ ] النسخ الاحتياطية مشفرة
- [ ] النسخ المتماثل عبر المناطق مكون
- [ ] سياسات الاحتفاظ منفذة

---

## مراجع — References

- [CIS AWS Foundations Benchmark](https://www.cisecurity.org/benchmark/amazon_web_services)
- [Terraform Security Best Practices](https://www.terraform.io/docs/cloud/workspaces/terraform.html)
- [AWS Well-Architected Security Pillar](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html)
- [UAE DESC Cloud Security Standard](https://desc.gov.ae/)
- [NIST SP 800-53 Rev. 5](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
