---
description: إرشادات أمان التشفير والجاهزية ما بعد الكم — Cryptographic Security Guidelines & Post-Quantum Readiness
languages: []
tags:
- cryptography
- post-quantum
- uae
alwaysApply: true
---

# إرشادات أمان التشفير والجاهزية ما بعد الكم — Cryptographic Security Guidelines & Post-Quantum Readiness

## نظرة عامة — Overview

هذه القواعد دائمة التطبيق (`alwaysApply: true`) وتغطي متطلبات التشفير الحديث والجاهزية للحوسبة الكمية.

These rules are permanently applied (`alwaysApply: true`) and cover modern cryptographic requirements and quantum computing readiness.

---

## 1. الخوارزميات المحظورة (غير الآمنة) — Banned (Insecure) Algorithms

**العربية:**
الخوارزميات التالية معروفة بأنها مكسورة أو غير آمنة جوهرياً. **لا** تنشئ أو تستخدم كوداً بهذه الخوارزميات أبداً.

**English:**
The following algorithms are known to be broken or fundamentally insecure. NEVER generate or use code with these algorithms.

| النوع — Type | الخوارزميات — Algorithms | السبب — Reason |
|---|---|---|
| التجزئة — Hash | `MD2`, `MD4`, `MD5`, `SHA-0` | مكسورة تشفيرياً — Cryptographically broken |
| المتماثل — Symmetric | `RC2`, `RC4`, `Blowfish`, `DES`, `3DES` | ضعيفة — Weak |
| تبادل المفاتيح — Key Exchange | Static RSA, Anonymous Diffie-Hellman | عرضة لهجمات man-in-the-middle |
| الكلاسيكية — Classical | `Vigenère` | غير آمنة — Insecure |

---

## 2. الخوارزميات المهملة (القديمة/الضعيفة) — Deprecated (Legacy/Weak) Algorithms

**العربية:**
الخوارزميات التالية لها نقاط ضعف معروفة أو تعتبر قديمة. تجنبها في التصميمات الجديدة وأعطِ الأولوية للترحيل.

**English:**
The following algorithms have known weaknesses or are considered obsolete. Avoid in new designs and prioritize migration.

| النوع — Type | الخوارزميات — Algorithms |
|---|---|
| التجزئة — Hash | `SHA-1` |
| المتماثل — Symmetric | `AES-CBC`, `AES-ECB` |
| التوقيع — Signature | RSA with `PKCS#1 v1.5` padding |
| تبادل المفاتيح — Key Exchange | DHE with weak/common primes |

---

## 3. الخوارزميات الموصى بها والجاهزة ما بعد الكم — Recommended & Post-Quantum Ready Algorithms

### التشفير المتماثل — Symmetric Encryption

**العربية:**
- القياسي: `AES-GCM` (AEAD)، `ChaCha20-Poly1305` (عندما يُسمح).
- متطلب PQC: فضّل مفاتيح AES-256 (أو أقوى) لأنها مقاومة للهجمات الكمية (خوارزمية Grover).
- تجنب: التشفير المخصص أو الأنماط غير المصادقة.

**English:**
- Standard: `AES-GCM` (AEAD), `ChaCha20-Poly1305` (when allowed).
- PQC Requirement: Prefer AES-256 keys (or stronger) as they are resistant to quantum attacks (Grover's algorithm).
- Avoid: Custom crypto or unauthenticated modes.

```c
// Secure AES-256-GCM encryption (PQC-Ready Symmetric Strength)
EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
if (!ctx) handle_error();

// Use AES-256-GCM
if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv) != 1)
    handle_error();

int len, ciphertext_len;
if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1)
    handle_error();
ciphertext_len = len;

if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1)
    handle_error();
ciphertext_len += len;

EVP_CIPHER_CTX_free(ctx);
```

### تبادل المفاتيح (KEM) — Key Exchange (KEM)

**العربية:**
- القياسي: ECDHE (`X25519` أو `secp256r1`)
- متطلب PQC: استخدم تبادل المفاتيح الهجين (الكلاسيكي + PQC) عندما يكون مدعوماً.
  - المفضل: `X25519MLKEM768` (X25519 + ML-KEM-768)
  - البديل: `SecP256r1MLKEM768` (P-256 + ML-KEM-768)
  - ضمان عالي: `SecP384r1MLKEM1024` (P-384 + ML-KEM-1024)
- PQC النقي: ML-KEM-768 (أساسي) أو ML-KEM-1024. تجنب ML-KEM-512 إلا إذا تم قبول المخاطر صراحةً.

**English:**
- Standard: ECDHE (`X25519` or `secp256r1`)
- PQC Requirement: Use Hybrid Key Exchange (Classical + PQC) when supported.
  - Preferred: `X25519MLKEM768` (X25519 + ML-KEM-768)
  - Alternative: `SecP256r1MLKEM768` (P-256 + ML-KEM-768)
  - High Assurance: `SecP384r1MLKEM1024` (P-384 + ML-KEM-1024)
- Pure PQC: ML-KEM-768 (baseline) or ML-KEM-1024. Avoid ML-KEM-512 unless explicitly risk-accepted.

### التوقيعات والشهادات — Signatures & Certificates

**العربية:**
- القياسي: ECDSA (`P-256`)
- ترحيل PQC: استمر في استخدام ECDSA (`P-256`) لـ mTLS وتوقيع الكود حتى يتوفر ML-DSA المدعوم بالأجهزة (HSM/TPM).
- متطلب الأجهزة: لا تُمكّن توقيعات PQC ML-DSA باستخدام مفاتيح برمجية فقط. اشترط تخزين HSM/TPM.

**English:**
- Standard: ECDSA (`P-256`)
- PQC Migration: Continue using ECDSA (`P-256`) for mTLS and code signing until hardware-backed (HSM/TPM) ML-DSA is available.
- Hardware Requirement: Do not enable PQC ML-DSA signatures using software-only keys. Require HSM/TPM storage.

### إصدارات البروتوكولات — Protocol Versions

**العربية:**
- (D)TLS: افرض (D)TLS 1.3 فقط (أو أحدث).
- IPsec: افرض IKEv2 فقط.
  - استخدم ESP مع AEAD (AES-256-GCM).
  - اشترط PFS عبر ECDHE.
  - نفذ RFC 9242 وRFC 9370 للـ PQC الهجين (ML-KEM + ECDHE).
- SSH: فعّل فقط KEX PQC/هجين مدعوم من البائع (مثلاً، `sntrup761x25519`).

**English:**
- (D)TLS: Enforce (D)TLS 1.3 only (or later).
- IPsec: Enforce IKEv2 only.
  - Use ESP with AEAD (AES-256-GCM).
  - Require PFS via ECDHE.
  - Implement RFC 9242 and RFC 9370 for Hybrid PQC (ML-KEM + ECDHE).
- SSH: Enable only vendor-supported PQC/hybrid KEX (e.g., `sntrup761x25519`).

---

## 4. إرشادات التنفيذ الآمن — Secure Implementation Guidelines

### الممارسات العامة — General Best Practices

**العربية:**
- التكوين على الكود: اعرض خيارات الخوارزميات في config/policy للسماح بالمرونة بدون تغيير الكود.
- إدارة المفاتيح:
  - استخدم KMS/HSM لتخزين المفاتيح.
  - أنشئ المفاتيح بـ CSPRNG.
  - افصل مفاتيح التشفير عن مفاتيح التوقيع.
  - دوّر المفاتيح حسب السياسة.
  - **لا تُضمن** مفاتيح أو أسرار أو OIDs تجريبية أبداً.
- التتبع: التقط المجموعات المتفاوض عليها وأحجام المصافحة وأسباب الفشل لمراقبة تبني PQC.

**English:**
- Configuration over Code: Expose algorithm choices in config/policy to allow agility without code changes.
- Key Management:
  - Use KMS/HSM for key storage.
  - Generate keys with a CSPRNG.
  - Separate encryption keys from signature keys.
  - Rotate keys per policy.
  - NEVER hardcode keys, secrets, or experimental OIDs.
- Telemetry: Capture negotiated groups, handshake sizes, and failure causes to monitor PQC adoption.

### واجهات برمجة SSL/Crypto المهملة (C/OpenSSL) — Deprecated SSL/Crypto APIs

**العربية:**
**لا** تستخدم هذه الدوال المهملة أبداً. استخدم بدائل واجهات برمجة EVP عالية المستوى.

**English:**
NEVER use these deprecated functions. Use the replacement EVP high-level APIs.

| المهمل — Deprecated | البديل — Replacement |
|---|---|
| `AES_encrypt()`, `AES_decrypt()` | `EVP_EncryptInit_ex()` (استخدم `EVP_aes_256_gcm()`) |
| `RSA_new()`, `RSA_free()`, `RSA_get0_n()` | `EVP_PKEY_new()`, `EVP_PKEY_up_ref()`, `EVP_PKEY_free()` |
| `SHA1_Init()`, `HMAC()` (مع SHA1) | `EVP_DigestInit_ex()` (استخدم SHA-256 أو أقوى)، `EVP_Q_MAC()` |

```c
// Example: Secure replacement for HMAC-SHA1
EVP_Q_MAC(NULL, "HMAC", NULL, "SHA256", NULL, key, key_len, data, data_len, out, out_size, &out_len);
```

---

## 5. متطلبات مشروع Broccoli — Broccoli Project Specific Requirements

**العربية:**
- `HMAC()` مع SHA1: مهمل.
- البديل: استخدم HMAC مع SHA-256 أو أقوى.

**English:**
- HMAC() with SHA1: Deprecated.
- Replacement: Use HMAC with SHA-256 or stronger.

---

## 6. نمط التنفيذ الآمن — Secure Crypto Implementation Pattern

```c
// Secure AES-256-GCM encryption (PQC-Ready Symmetric Strength)
EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
if (!ctx) handle_error();

// Use AES-256-GCM
if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv) != 1)
    handle_error();

int len, ciphertext_len;
if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1)
    handle_error();
ciphertext_len = len;

if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1)
    handle_error();
ciphertext_len += len;

// Get authentication tag
if (EVP_CIPHER_CTX_get_tag(ctx, tag, sizeof(tag)) != 1)
    handle_error();

EVP_CIPHER_CTX_free(ctx);
```

---

## قائمة التحقق — Implementation Checklist

- [ ] لا خوارزميات محظورة مستخدمة
- [ ] لا خوارزميات مهملة في تصميمات جديدة
- [ ] AES-GCM أو ChaCha20-Poly1305 للتشفير المتماثل
- [ ] مفاتيح AES-256+ للجاهزية الكمية
- [ ] تبادل مفاتيح هجين (Classical + PQC) عندما يكون مدعوماً
- [ ] ML-KEM-768 كحد أدنى للـ PQC
- [ ] ECDSA (P-256) للتوقيعات حتى يتوفر ML-DSA بالأجهزة
- [ ] HSM/TPM مطلوب لتخزين مفاتيح PQC
- [ ] (D)TLS 1.3+ فقط
- [ ] IKEv2 فقط لـ IPsec
- [ ] لا دوال OpenSSL المهملة
- [ ] واجهات برمجة EVP عالية المستوى
- [ ] مفاتيح مُنشأة بـ CSPRNG
- [ ] KMS/HSM لتخزين المفاتيح
- [ ] تدوير المفاتيح حسب السياسة
- [ ] لا مفاتيح أو أسرار مُضمنة
- [ ] تتبع تبني PQC

---

## مراجع — References

- [NIST Post-Quantum Cryptography Standardization](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [RFC 9242 - Hybrid Key Exchange in TLS 1.3](https://datatracker.ietf.org/doc/html/rfc9242)
- [RFC 9370 - Multiple KEMs in TLS 1.3](https://datatracker.ietf.org/doc/html/rfc9370)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [UAE Information Assurance Framework](https://www.tra.gov.ae/)
