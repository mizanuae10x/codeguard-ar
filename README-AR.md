# حارس الكود — CodeGuard بالعربية 🇦🇪

نسخة عربية من [Project CodeGuard](https://project-codeguard.org/) مخصصة لمنطقة الخليج والامتثال للأنظمة المحلية.

## الفرق عن النسخة الأصلية

| الميزة | CodeGuard الأصلي | حارس الكود |
|--------|------------------|-----------|
| اللغة | إنجليزي | عربي + إنجليزي |
| السياق | عالمي | UAE / GCC |
| الأنظمة | OWASP | OWASP + CBUAE + DESC + UAE IA |
| الاتجاه | عام | CISO / Enterprise |

## القواعد (23 قاعدة)

### قواعد دائمة (Always-On)
1. `codeguard-1-hardcoded-credentials` — لا تخزن credentials في الكود
2. `codeguard-1-crypto-algorithms` — استخدم خوارزميات تشفير حديثة
3. `codeguard-1-digital-certificates` — إدارة الشهادات الرقمية

### قواعد حسب السياق (Context-Selected)
4. `codeguard-0-input-validation-injection` — التحقق من المدخلات
5. `codeguard-0-api-web-services` — أمان APIs
6. `codeguard-0-authentication-mfa` — المصادقة و MFA
7. `codeguard-0-authorization-access-control` — التفويض والتحكم بالوصول
8. `codeguard-0-session-management-and-cookies` — إدارة الجلسات
9. `codeguard-0-data-storage` — تخزين البيانات
10. `codeguard-0-client-side-web-security` — أمان المتصفح
11. `codeguard-0-file-handling-and-uploads` — معالجة الملفات
12. `codeguard-0-logging` — التسجيل والمراقبة
13. `codeguard-0-supply-chain-security` — أمان سلسلة التوريد
14. `codeguard-0-cloud-orchestration-kubernetes` — Kubernetes والسحابة
15. `codeguard-0-devops-ci-cd-containers` — CI/CD وContainers
16. `codeguard-0-iac-security` — أمان البنية التحتية ككود
17. `codeguard-0-privacy-data-protection` — الخصوصية وحماية البيانات
18. `codeguard-0-mobile-apps` — أمان تطبيقات الجوال
19. `codeguard-0-framework-and-languages` — إطارات العمل واللغات
20. `codeguard-0-safe-c-functions` — دوال C الآمنة
21. `codeguard-0-xml-and-serialization` — XML والتسلسل
22. `codeguard-0-additional-cryptography` — تشفير إضافي
23. `codeguard-0-mcp-security` — أمان MCP

## الامتثال المحلي

- **CBUAE** — توجيهات مصرف الإمارات العربية المتحدة المركزي
- **DESC** — معايير الأمن السيبراني لدبي
- **UAE IA** — إطار الأمن السيبراني الوطني الإماراتي
- **ADGM** — متطلبات مركز أبوظبي العالمي
- **DIFC** — متطلبات مركز دبي المالي العالمي

## الترخيص

CC BY 4.0 — مفتوح المصدر
