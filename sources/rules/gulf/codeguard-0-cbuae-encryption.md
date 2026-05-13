---
description: CBUAE Encryption Requirements — متطلبات التشفير حسب CBUAE
languages:
- java
- python
- javascript
- typescript
- c#
- go
- ruby
- php
tags:
- cbuae
- encryption
- uae
- financial
alwaysApply: false
---

# CBUAE Encryption Requirements — متطلبات التشفير حسب CBUAE

## Overview — نظرة عامة

The Central Bank of the UAE (CBUAE) mandates specific encryption standards for all licensed financial institutions. These requirements apply to:

مصرف الإمارات العربية المتحدة المركزي (CBUAE) يفرض معايير تشفير محددة لجميع المؤسسات المالية المرخصة. هذه المتطلبات تنطبق على:

- Data at rest (databases, file systems, backups)
- Data in transit (APIs, web services, internal networks)
- Key management and rotation
- End-to-end encryption for sensitive customer data

## Requirements — المتطلبات

### 1. Minimum Encryption Standards — معايير التشفير الدنيا

**English:**
- AES-256-GCM for symmetric encryption
- RSA-4096 or ECC P-384 for asymmetric encryption
- TLS 1.3 for all network communications
- SHA-256 minimum for hashing (SHA-3 recommended)

**العربية:**
- AES-256-GCM للتشفير المتماثل
- RSA-4096 أو ECC P-384 للتشفير غير المتماثل
- TLS 1.3 لجميع الاتصالات الشبكية
- SHA-256 كحد أدنى للتجزئة (يُفضل SHA-3)

### 2. Key Management — إدارة المفاتيح

**English:**
- Keys must be stored in Hardware Security Modules (HSM) or cloud KMS
- Key rotation every 90 days maximum
- Separate keys for each environment (dev, staging, prod)
- No key material in source code or configuration files

**العربية:**
- يجب تخزين المفاتيح في وحدات HSM أو KMS سحابي
- تدوير المفاتيح كل 90 يوماً كحد أقصى
- مفاتيح منفصلة لكل بيئة (تطوير، staging، إنتاج)
- ممنوع وضع مادة المفاتيح في الكود أو ملفات الإعداد

### 3. Data Classification — تصنيف البيانات

| Classification | Encryption Required | Example |
|----------------|---------------------|---------|
| Critical | AES-256-GCM + HSM | Customer PII, financial records |
| High | AES-256-GCM | Transaction data, account numbers |
| Medium | AES-128-GCM minimum | Internal reports, analytics |
| Low | TLS 1.3 in transit | Public marketing data |

## Code Examples — أمثلة برمجية

### Python (with AWS KMS)
```python
import boto3
from cryptography.fernet import Fernet

# Use AWS KMS for key management
kms_client = boto3.client('kms', region_name='me-central-1')

# Encrypt data
response = kms_client.encrypt(
    KeyId='alias/cbuae-production-key',
    Plaintext=b'sensitive customer data'
)
encrypted_data = response['CiphertextBlob']
```

### Java (with Azure Key Vault)
```java
import com.azure.security.keyvault.keys.cryptography.CryptographyClient;
import com.azure.identity.DefaultAzureCredentialBuilder;

// Initialize with managed identity
CryptographyClient cryptoClient = new CryptographyClientBuilder()
    .keyIdentifier("https://cbuae-vault.vault.azure.net/keys/data-key")
    .credential(new DefaultAzureCredentialBuilder().build())
    .buildClient();

// Encrypt data
EncryptResult encryptResult = cryptoClient.encrypt(
    EncryptionAlgorithm.A256GCM,
    plaintextData
);
```

### Node.js (with Google Cloud KMS)
```javascript
const {KeyManagementServiceClient} = require('@google-cloud/kms');

const client = new KeyManagementServiceClient();
const keyName = client.cryptoKeyPath(
    'cbuae-project', 'me-central1', 'cbuae-keyring', 'data-key'
);

// Encrypt data
const [encryptResponse] = await client.encrypt({
    name: keyName,
    plaintext: Buffer.from('sensitive data'),
});
```

## Compliance Checklist — قائمة التحقق

- [ ] All data at rest uses AES-256-GCM
- [ ] All APIs use TLS 1.3
- [ ] Keys stored in HSM or cloud KMS
- [ ] Key rotation implemented (90 days)
- [ ] Separate keys per environment
- [ ] No credentials in source code
- [ ] Encryption audit logs enabled
- [ ] Data classification documented

## References — مراجع

- [CBUAE Information Security Regulations](https://www.cbuae.gov.ae/)
- [UAE Information Assurance (IA) Framework](https://www.tra.gov.ae/)
- [NIST SP 800-57 - Key Management](https://csrc.nist.gov/publications/detail/sp/800-57/final)
