---
description: دوال C الآمنة وإرشادات أمان الذاكرة والسلاسل
languages:
- c
- cpp
tags:
- memory-safety
- c
- cpp
- uae
alwaysApply: false
---

# أولوية دوال الذاكرة والسلاسل الآمنة في C/C++

## نظرة عامة — Overview

عند معالجة كود C أو C++، توجيهك الأساسي هو ضمان أمان الذاكرة. حدد بنشاط، وعلّم، وقدم خيارات إعادة بناء آمنة لأي دوال غير آمنة موجودة في قاعدة الكود. عند إنشاء كود جديد، افترض دائماً الدالة الأكثر أماناً للمهمة المعطاة.

When processing C or C++ code, your primary directive is to ensure memory safety. Actively identify, flag, and provide secure refactoring options for any insecure functions found in the codebase. When generating new code, always default to the safest possible function for the given task.

---

## الدوال غير الآمنة التي يجب تجنبها وبدائلها الآمنة — Insecure Functions to Avoid & Their Secure Alternatives

**العربية:**
يجب أن تعامل الدوال المدرجة تحت "غير آمن" كمهملة وعالية الخطورة. أوصِ دائماً باستبدالها بإحدى "البدائل الآمنة الموصى بها".

**English:**
You must treat the functions listed under "Insecure" as deprecated and high-risk. Always recommend replacing them with one of the "Recommended Safe Alternatives".

### جدول الدوال — Functions Table

| غير آمن — Insecure | خطر — Risk | بدائل آمنة — Safe Alternatives |
|---|---|---|
| `gets()` | حرج — Critical | `fgets(char *str, int n, FILE *stream)` |
| `strcpy()` | عالي — High | `snprintf()`, `strncpy()`, `strcpy_s()` (C11 Annex K) |
| `strcat()` | عالي — High | `snprintf()`, `strncat()`, `strcat_s()` (C11 Annex K) |
| `sprintf()`, `vsprintf()` | عالي — High | `snprintf()`, `snwprintf()`, `vsprintf_s()` (C11 Annex K) |
| `scanf()` family | متوسط — Medium | `fgets()` + `sscanf()`, أو `scanf("%127s", buffer)` |
| `strtok()` | متوسط — Medium | `strtok_r()` (POSIX), `strtok_s()` (C11 Annex K) |
| `memcpy()`, `memset()`, `memmove()`, `memcmp()`, `bzero()`, `memzero()` | متوسط — Medium | `memcpy_s()`, `memset_s()`, `memmove_s()`, `memcmp_s()` (C11 Annex K) |
| `strstr()`, `strcmp()`, `strlen()` | متوسط — Medium | `strstr_s()`, `strcmp_s()`, `strnlen_s()` (C11 Annex K) |

---

## إرشادات التنفيذ العملية — Actionable Implementation Guidelines

### لتوليد كود جديد — For New Code Generation

**العربية:**
- **لا** تنشئ كود يستخدم `gets()`، `strcpy()`، `strcat()`، أو `sprintf()`.
- **افترض** `snprintf()` لتنسيق السلاسل والتسلسل، لأنه غالباً الخيار الأكثر مرونة وأماناً.
- **افترض** `fgets()` لقراءة مدخلات السلسلة من الملفات أو المدخلات القياسية.

**English:**
- NEVER generate code that uses `gets()`, `strcpy()`, `strcat()`, or `sprintf()`.
- DEFAULT to `snprintf()` for string formatting and concatenation.
- DEFAULT to `fgets()` for reading string input from files or standard input.

### لتحليل الكود وإعادة البناء — For Code Analysis and Refactoring

**العربية:**
1. **حدد**: امسح الكود وعلّم كل مثيل لدالة من عمود "غير آمن".
2. **اشرح الخطر**: عندما تعلّم دالة غير آمنة، قدم شرحاً موجزاً للثغرة المحددة.
3. **قدم بدائل مدركة للسياق**: اقتراحك يجب أن يكون بديلاً آمناً جاهزاً للاستخدام يأخذ في الاعتبار سياق الكود المحيط.

**English:**
1. **Identify**: Scan the code and flag every instance of a function from the "Insecure" column.
2. **Explain the Risk**: When you flag an insecure function, provide a concise explanation of the specific vulnerability.
3. **Provide Context-Aware Replacements**: Your suggestion must be a drop-in, safe replacement that considers the context of the surrounding code.

---

## أعلام المترجم — Compiler Flags

**العربية:**
فعّل هذه الأعلام الوقائية للمترجم للكشف عن ثغرات تجاوز المخزن المؤقت في وقت الترجمة والتشغيل:

**English:**
Enable these protective compiler flags to catch buffer overflow vulnerabilities at compile time and runtime:

```bash
# Stack Protection
-fstack-protector-all
# or
-fstack-protector-strong

# Address Sanitizer (development only)
-fsanitize=address

# Object Size Checking
-D_FORTIFY_SOURCE=2

# Format String Protection
-Wformat -Wformat-security

# Example compilation for UAE project
gcc -o uae_app uae_app.c \
    -fstack-protector-strong \
    -D_FORTIFY_SOURCE=2 \
    -Wformat -Wformat-security \
    -Wall -Wextra -Werror \
    -O2
```

---

## أمثلة إعادة البناء — Refactoring Examples

### المثال 1: استبدال `strcpy`

**العربية:**
الكود الأصلي غير الآمن:

**English:**
Original Unsafe Code:

```c
// ❌ Unsafe
char destination[64];
strcpy(destination, source_string);
```

**العربية:**
الكود المقترح:

**English:**
Suggested Refactoring:

```c
// ✅ Safe
char destination[64];
snprintf(destination, sizeof(destination), "%s", source_string);
```

**العربية:**
الشرح: استبدلت `strcpy` بـ `snprintf` لضمان عدم كتابة أكثر من 63 حرفاً بالإضافة إلى null terminator في المخزن المؤقت الوجهة، مما يمنع تجاوز المخزن المؤقت المحتمل.

**English:**
Explanation: `Replaced 'strcpy' with 'snprintf' to ensure that no more than 63 characters plus a null terminator are written to the destination buffer, preventing a potential buffer overflow.`

---

### المثال 2: تصحيح استخدام `strncpy`

**العربية:**
دالة `strncpy` شائعة لكنها غير مثالية. قد لا تنهي السلسلة الوجهة بـ null. إذا كان يجب استخدامها أو رأيتها مستخدمة، يجب فرض المعالجة الصحيحة.

**English:**
The `strncpy` function is a common but imperfect replacement. It may not null-terminate the destination buffer.

```c
// ❌ Potentially Unsafe
char dest[10];
strncpy(dest, source, sizeof(dest));
// dest may not be null-terminated!
```

```c
// ✅ Safe
char dest[10];
strncpy(dest, source, sizeof(dest) - 1);
dest[sizeof(dest) - 1] = '\0';
// Explicitly null-terminated
```

**العربية:**
الشرح: أضفت إنهاءاً صريحاً بـ null لـ `strncpy`. دالة `strncpy` لا تضمن سلسلة منتهية بـ null إذا كانت المصدر بنفس طول المخزن المؤقت الوجهة. هذا التصحيح يمنع القراءات المحتملة بعد المخزن المؤقت في عمليات السلسلة اللاحقة.

**English:**
Explanation: `Added an explicit null termination for 'strncpy'. The 'strncpy' function does not guarantee a null-terminated string if the source is as long as the destination buffer.`

---

### المثال 3: تأمين `scanf`

```c
// ❌ Unsafe
char user_name[32];
printf("Enter your name: ");
scanf("%s", user_name);  // No bounds checking!
```

```c
// ✅ Safe
char user_name[32];
printf("Enter your name: ");
if (fgets(user_name, sizeof(user_name), stdin)) {
    // Remove trailing newline
    user_name[strcspn(user_name, "\n")] = 0;
}
```

**العربية:**
الشرح: استبدلت `scanf("%s", ...)` بـ `fgets()` لقراءة مدخلات المستخدم. `fgets` أكثر أماناً لأنها تحد المدخلات لحجم المخزن المؤقت، مما يمنع تجاوز المخزن المؤقت.

**English:**
Explanation: `Replaced 'scanf("%s", ...)' with 'fgets()' to read user input. 'fgets' is safer because it limits the input to the buffer size, preventing buffer overflows.`

---

## بدائل الذاكرة الآمنة — Safe Memory Function Replacements

```c
// ✅ Safe Memory Copy
// Instead of: memcpy(dest, src, count);
errno_t result = memcpy_s(dest, dest_size, src, count);
if (result != 0) {
    // Handle error
    fprintf(stderr, "Memory copy failed: %d\n", result);
    return ERROR;
}

// ✅ Safe Memory Set
// Instead of: memset(dest, value, count);
errno_t result = memset_s(dest, dest_size, value, count);

// ✅ Safe Memory Move
// Instead of: memmove(dest, src, count);
errno_t result = memmove_s(dest, dest_size, src, count);

// ✅ Safe Memory Compare
// Instead of: memcmp(s1, s2, count);
int indicator;
errno_t result = memcmp_s(s1, s1max, s2, s2max, count, &indicator);
if (result == 0) {
    // indicator contains comparison result: <0, 0, or >0
}
```

---

## بدائل السلاسل الآمنة — Safe String Function Replacements

```c
// ✅ Safe String Search
errno_t strstr_s(char *dest, rsize_t dmax, const char *src, rsize_t slen, char **substring);

// ✅ Safe String Tokenization
char *strtok_s(char *dest, rsize_t *dmax, const char *src, char **ptr);

// ✅ Safe String Copy
errno_t strcpy_s(char *dest, rsize_t dmax, const char *src);

// ✅ Safe String Compare
errno_t strcmp_s(const char *dest, rsize_t dmax, const char *src, int *indicator);

// ✅ Safe String Length (bounded)
rsize_t strnlen_s(const char *str, rsize_t strsz);

// ✅ Safe String Concatenation
errno_t strcat_s(char *dest, rsize_t dmax, const char *src);

// ✅ Safe Formatted String
int snprintf(char *s, size_t n, const char *format, ...);
```

---

## أمثلة تنفيذية — Implementation Examples

### نمط النسخ الآمن — Safe String Copy Pattern

```c
// ❌ Bad - unsafe
char dest[256];
strcpy(dest, src); // Buffer overflow risk!

// ✅ Good - safe
char dest[256];
errno_t result = strcpy_s(dest, sizeof(dest), src);
if (result != 0) {
    fprintf(stderr, "String copy failed: %d\n", result);
    return ERROR;
}
```

### نمط التسلسل الآمن — Safe String Concatenation Pattern

```c
// ❌ Bad - unsafe
char buffer[256] = "prefix_";
strcat(buffer, suffix); // Buffer overflow risk!

// ✅ Good - safe
char buffer[256] = "prefix_";
errno_t result = strcat_s(buffer, sizeof(buffer), suffix);
if (result != 0) {
    fprintf(stderr, "String concatenation failed: %d\n", result);
    return ERROR;
}
```

### نمط نسخ الذاكرة الآمن — Safe Memory Copy Pattern

```c
// ❌ Bad - unsafe
memcpy(dest, src, size); // No boundary checking!

// ✅ Good - safe
errno_t result = memcpy_s(dest, dest_max_size, src, size);
if (result != 0) {
    fprintf(stderr, "Memory copy failed: %d\n", result);
    return ERROR;
}
```

### نمط التجزئة الآمن — Safe String Tokenization Pattern

```c
// ❌ Bad - unsafe
char *token = strtok(str, delim); // Modifies original string unsafely

// ✅ Good - safe
char *next_token = NULL;
rsize_t str_max = strnlen_s(str, MAX_STRING_SIZE);
char *token = strtok_s(str, &str_max, delim, &next_token);
while (token != NULL) {
    // Process token
    token = strtok_s(NULL, &str_max, delim, &next_token);
}
```

---

## قائمة التحقق لمراجعة الكود — Code Review Checklist

### ما قبل المراجعة (المطور) — Pre-Code Review (Developer)

- [ ] لا دوال ذاكرة غير آمنة (`memcpy`, `memset`, `memmove`, `memcmp`, `bzero`)
- [ ] لا دوال سلاسل غير آمنة (`strcpy`, `strcat`, `strcmp`, `strlen`, `sprintf`, `strstr`, `strtok`)
- [ ] جميع عمليات الذاكرة تستخدم متغيرات `*_s()` مع معاملات الحجم المناسبة
- [ ] أحجام المخازن المؤقتة محسوبة بشكل صحيح باستخدام `sizeof()` أو حدود معروفة
- [ ] لا أحجام مخازن مؤقتة مُضمَّنة يمكن أن تتغير

### مراجعة الكود (المراجع) — Code Review (Reviewer)

- [ ] **أمان الذاكرة**: تحقق من أن جميع عمليات الذاكرة تستخدم متغيرات آمنة
- [ ] **حدود المخازن المؤقتة**: تأكد من أن أحجام المخازن المؤقتة الوجهة محددة بشكل صحيح
- [ ] **معالجة الأخطاء**: تحقق من أن جميع قيم الإرجاع `errno_t` تُعالج
- [ ] **معاملات الحجم**: تحقق من أن معاملات `rsize_t dmax` صحيحة
- [ ] **إنهاء السلاسل**: تأكد من أن السلاسل منتهية بـ null بشكل صحيح
- [ ] **التحقق من الطول**: تحقق من أن أطوال السلاسل المصدر مُتحقَّقة قبل العمليات

### التحليل الثابت — Static Analysis Integration

- [ ] فعّل تحذيرات المترجم لاستخدام الدوال غير الآمنة
- [ ] استخدم أدوات التحليل الثابت للكشف عن استدعاءات الدوال غير الآمنة
- [ ] اضبط نظام البناء لمعاملة تحذيرات الدوال غير الآمنة كأخطاء
- [ ] أضف خطافات pre-commit للبحث عن الدوال المحظورة

---

## الأخطاء الشائعة والحلول — Common Pitfalls and Solutions

### الخطأ 1: معامل الحجم الخاطئ

```c
// ❌ Wrong - using source size instead of destination size
strcpy_s(dest, strlen(src), src); // WRONG!

// ✅ Correct - using destination buffer size
strcpy_s(dest, sizeof(dest), src); // CORRECT
```

### الخطأ 2: تجاهل قيم الإرجاع

```c
// ❌ Wrong - ignoring potential errors
strcpy_s(dest, sizeof(dest), src); // Error not checked

// ✅ Correct - checking return value
if (strcpy_s(dest, sizeof(dest), src) != 0) {
    // Handle error appropriately
    fprintf(stderr, "Copy failed\n");
    return ERROR;
}
```

### الخطأ 3: استخدام sizeof() على المؤشرات

```c
// ❌ Wrong - sizeof pointer, not buffer
void func(char *buffer) {
    strcpy_s(buffer, sizeof(buffer), src); // sizeof(char*) = 8!
}

// ✅ Correct - pass buffer size as parameter
void func(char *buffer, size_t buffer_size) {
    strcpy_s(buffer, buffer_size, src);
}
```

---

## مراجع — References

- [C11 Standard Annex K (Bounds-checking interfaces)](https://en.cppreference.com/w/c/error)
- [OWASP C-based Toolchain Hardening](https://owasp.org/www-project-c-based-toolchain-hardening/)
- [SEI CERT C Coding Standard](https://wiki.sei.cmu.edu/confluence/display/c/SEI+CERT+C+Coding+Standard)
- [Microsoft Secure CRT](https://docs.microsoft.com/en-us/cpp/c-runtime-library/security-features-in-the-crt)
- [UAE Information Assurance Framework](https://www.tra.gov.ae/)
