---
description: أفضل ممارسات الشهادات الرقمية — Certificate Best Practices
languages: []
tags:
- secrets
- certificates
- uae
alwaysApply: true
---

# أفضل ممارسات الشهادات الرقمية — Certificate Best Practices

## نظرة عامة — Overview

عندما تصادف بيانات تبدو شهادة X.509—سواء مُضمَّنة كسلسلة أو محملة من ملف—يجب أن تعلّم الشهادة للتحقق وتضمن التحقق من خصائص الأمان التالية، مع الإبلاغ عن أي مخاوف بتوضيحات واضحة وإجراءات موصى بها.

When you encounter data that appears to be an X.509 certificate—whether embedded as a string or loaded from a file—you must flag the certificate for verification and ensure the following security properties are validated, reporting any concerns with clear explanations and recommended actions.

---

## 1. كيفية تحديد بيانات الشهادة — How to Identify Certificate Data

**العربية:**
امسح بنشاط بحثاً عن بيانات الشهادة باستخدام الاستكشافات التالية:

**English:**
Actively scan for certificate data using the following heuristics:

| النوع — Type | الوصف — Description |
|---|---|
| سلاسل PEM | سلاسل متعددة الأسطر تبدأ بـ `-----BEGIN CERTIFICATE-----` وتنتهي بـ `-----END CERTIFICATE-----` |
| عمليات الملفات | عمليات قراءة ملفات بامتدادات `.pem`، `.crt`، `.cer`، `.der` |
| استدعاءات المكتبات | دوال تحميل أو تحليل الشهادات (OpenSSL `PEM_read_X509`، Python `cryptography.x509.load_pem_x509_certificate`، Java `CertificateFactory`) |

---

## 2. فحوصات السلامة الإلزامية — Mandatory Sanity Checks

**العربية:**
بمجرد تحديد بيانات الشهادة، علّمها للتحقق. يجب التحقق من الخصائص التالية:

**English:**
Once certificate data is identified, flag it for verification. The following properties must be validated:

### التحقق من الشهادة — Certificate Verification

**العربية:**
للفحص خصائص الشهادة، أوصِ بتشغيل:

**English:**
To inspect certificate properties, recommend running:

```bash
openssl x509 -text -noout -in <certificate_file>
```

---

### الفحص 1: حالة انتهاء الصلاحية — Check 1: Expiration Status

**العربية:**

| الحالة — Condition | الخطورة — Severity | الرسالة — Report Message |
|---|---|---|
| `notAfter` في الماضي | ثغرة حرجة — CRITICAL | "انتهت صلاحية هذه الشهادة بتاريخ [YYYY-MM-DD]. لم تعد صالحة وسيتم رفضها من قبل العملاء. يجب تجديدها واستبدالها فوراً." |
| `notBefore` في المستقبل | تحذير — Warning | "هذه الشهادة ليست صالحة بعد. فترة صلاحيتها تبدأ بتاريخ [YYYY-MM-DD]." |

**English:**

| Condition | Severity | Report Message |
|---|---|---|
| `notAfter` in the past | CRITICAL VULNERABILITY | "This certificate expired on [YYYY-MM-DD]. It is no longer valid and will be rejected by clients. It must be renewed and replaced immediately." |
| `notBefore` in the future | Warning | "This certificate is not yet valid. Its validity period begins on [YYYY-MM-DD]." |

---

### الفحص 2: قوة المفتاح العام — Check 2: Public Key Strength

**العربية:**

| الحالة — Condition | الخطورة — Severity | الرسالة — Report Message |
|---|---|---|
| RSA < 2048 bits أو EC < 256-bit | تحذير ذو أولوية عالية — High-Priority Warning | "مفتاح الشهادة العام ضعيف تشفيرياً ([Algorithm], [Key Size]). المفاتيح بهذه القوة عرضة لهجمات التحليل. يجب إعادة إصدار الشهادة باستخدام مفتاح RSA 2048-bit على الأقل أو ECDSA على منحنى P-256 (أو أعلى)." |

**English:**

| Condition | Severity | Report Message |
|---|---|---|
| RSA < 2048 bits or EC < 256-bit | High-Priority Warning | "The certificate's public key is cryptographically weak ([Algorithm], [Key Size]). Keys of this strength are vulnerable to factorization or discrete logarithm attacks. The certificate should be re-issued using at least an RSA 2048-bit key or an ECDSA key on a P-256 (or higher) curve." |

---

### الفحص 3: خوارزمية التوقيع — Check 3: Signature Algorithm

**العربية:**

| الحالة — Condition | الخطورة — Severity | الرسالة — Report Message |
|---|---|---|
| MD5 أو SHA-1 | تحذير ذو أولوية عالية — High-Priority Warning | "الشهادة موقعة بالخوارزمية غير الآمنة '[Algorithm]'. هذا يجعلها عرضة لهجمات التصادم، مما يسمح بتزوير الشهادة. يجب إعادة إصدارها باستخدام توقيع من عائلة SHA-2 (مثلاً، sha256WithRSAEncryption)." |

**English:**

| Condition | Severity | Report Message |
|---|---|---|
| MD5 or SHA-1 | High-Priority Warning | "The certificate is signed with the insecure algorithm '[Algorithm]'. This makes it vulnerable to collision attacks, potentially allowing for certificate forgery. It must be re-issued using a signature based on the SHA-2 family (e.g., sha256WithRSAEncryption)." |

---

### الفحص 4: نوع المُصْدِر (فحص الشهادة الموقعة ذاتياً) — Check 4: Issuer Type (Self-Signed Check)

**العربية:**

| الحالة — Condition | الخطورة — Severity | الرسالة — Report Message |
|---|---|---|
| `Issuer` == `Subject` | إعلامي — Informational | "هذه شهادة موقعة ذاتياً. تأكد من أن هذا مقصود ويُستخدم فقط للتطوير أو الاختبار أو الخدمات الداخلية حيث الثقة مُكوَّنة صراحةً. الشهادات الموقعة ذاتياً يجب ألا تُستخدم أبداً لأنظمة الإنتاج العامة لأنها لن تكون موثوقة من المتصفحات أو العملاء القياسيين." |

**English:**

| Condition | Severity | Report Message |
|---|---|---|
| `Issuer` == `Subject` | Informational | "This is a self-signed certificate. Ensure this is intentional and only used for development, testing, or internal services where trust is explicitly configured. Self-signed certificates should never be used for public-facing production systems as they will not be trusted by browsers or standard clients." |

---

## 3. أمثلة عملية — Actionable Examples

### المثال 1: الإبلاغ عن شهادة مُضمَّنة — Example 1: Flagging a Hardcoded Certificate

**العربية:**

**English:**

```python
# ❌ Security Review Required
# Certificate for connecting to legacy_service
LEGACY_CERT = """
-----BEGIN CERTIFICATE-----
MIIC... (certificate data) ...
-----END CERTIFICATE-----
"""
```

**العربية:**
تحليل وتقرير:

**English:**
Analysis and Report:

> **مراجعة أمان مطلوبة**: شهادة مُضمَّنة في متغير `LEGACY_CERT`. الشهادات غير المُتحقَّقة قد تحتوي على ثغرات حرجة.
>
> - **المخاوف**: الشهادات المُضمَّنة لا يمكن تدويرها بسهولة وقد تحتوي على مشاكل أمان غير مرئية فوراً في الكود.
>
> - **التحقق المطلوب**: يجب التحقق من هذه الشهادة:
>   - انتهاء الصلاحية: يجب ألا تكون منتهية أو غير صالحة بعد
>   - قوة المفتاح: مفاتيح RSA يجب أن تكون 2048-bit على الأقل؛ مفاتيح EC يجب أن تستخدم منحنى P-256 أو أعلى
>   - خوارزمية التوقيع: يجب أن تستخدم عائلة SHA-2 (ليس MD5 أو SHA-1)
>   - موقعة ذاتياً: إذا كانت كذلك، يجب استخدامها فقط للتطوير أو الاختبار أو الخدمات الداخلية
>
> - **الإجراء**: تحقق من أن هذه الشهادة تلبي المتطلبات أعلاه قبل النشر. فكر في تحميل الشهادات من ملفات خارجية أو مخزن شهادات لتسهيل التدوير.

---

### المثال 2: الإبلاغ عن شهادة محملة من ملف — Example 2: Flagging a Certificate Loaded from File

```go
// Load the server certificate from disk
cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
```

> **مراجعة أمان مطلوبة**: شهادة محملة من `server.crt`. الشهادات غير المُتحقَّقة قد تحتوي على ثغرات حرجة.
>
> - **التحقق المطلوب**: تأكد من أن هذه الشهادة تلبي متطلبات الأمان:
>   - انتهاء الصلاحية: يجب ألا تكون منتهية أو غير صالحة بعد
>   - قوة المفتاح: مفاتيح RSA يجب أن تكون 2048-bit على الأقل؛ مفاتيح EC يجب أن تستخدم منحنى P-256 أو أعلى
>   - خوارزمية التوقيع: يجب أن تستخدم عائلة SHA-2 (ليس MD5 أو SHA-1)
>   - موقعة ذاتياً: إذا كانت كذلك، يجب استخدامها فقط للتطوير أو الاختبار أو الخدمات الداخلية
>
> - **الإجراء**: تحقق من أن هذه الشهادة تلبي المتطلبات أعلاه قبل النشر.

---

## قائمة التحقق — Implementation Checklist

- [ ] فحص انتهاء الصلاحية (notAfter, notBefore)
- [ ] فحص قوة المفتاح العام (RSA >= 2048, EC >= P-256)
- [ ] فحص خوارزمية التوقيع (SHA-2 فقط)
- [ ] فحص نوع المُصْدِر (Self-signed)
- [ ] لا شهادات منتهية في الإنتاج
- [ ] لا شهادات موقعة ذاتياً في الإنتاج العام
- [ ] تدوير الشهادات قبل انتهاء الصلاحية
- [ ] تخزين الشهادات في مخازن آمنة (HSM/KMS)
- [ ] مراقبة انتهاء صلاحية الشهادات
- [ ] إشعارات قبل انتهاء الصلاحية (30/60/90 يوم)

---

## مراجع — References

- [OWASP Transport Layer Protection Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)
- [NIST SP 800-57 - Key Management](https://csrc.nist.gov/publications/detail/sp/800-57/final)
- [Mozilla SSL Configuration Generator](https://ssl-config.mozilla.org/)
- [OpenSSL Certificate Verification](https://www.openssl.org/docs/manmaster/man1/openssl-verify.html)
- [UAE Information Assurance Framework](https://www.tra.gov.ae/)
