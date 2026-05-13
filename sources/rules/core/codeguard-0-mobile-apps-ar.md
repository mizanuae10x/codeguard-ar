---
description: أمان تطبيقات الجوال (iOS/Android): التخزين، النقل، نزاهة الكود، القياسات الحيوية، الأذونات
languages:
- java
- javascript
- kotlin
- matlab
- perl
- swift
- xml
tags:
- mobile
- ios
- android
- uae
alwaysApply: false
---

# أمان تطبيقات الجوال — Mobile Application Security Guidelines

## نظرة عامة — Overview

ممارسات أمان أساسية لتطوير تطبيقات جوال آمنة عبر منصتي iOS وAndroid.

Essential security practices for developing secure mobile applications across iOS and Android platforms.

---

## الهندسة المعمارية والتصميم — Architecture and Design

**العربية:**
- اتبع مبادئ أقل الامتياز والدفاع في العمق
- استخدم بروتوكولات مصادقة آمنة قياسية (OAuth2، JWT)
- نفذ جميع فحوصات المصادقة والتفويض من جانب الخادم
- اطلب فقط الأذونات الضرورية للتطبيق والخدمات الخلفية
- أنشئ ضوابط أمان لتحديثات التطبيق والتصحيحات والإصدارات
- استخدم فقط المكتبات والمكونات الخارجية الموثوقة والمُتحقَّقة

**English:**
- Follow least privilege and defense in depth principles
- Use standard secure authentication protocols (OAuth2, JWT)
- Perform all authentication and authorization checks server-side
- Request only necessary permissions for app and backend services
- Establish security controls for app updates, patches, and releases
- Use only trusted and validated third-party libraries and components

---

## المصادقة والتفويض — Authentication and Authorization

**العربية:**
- نفذ المصادقة/التفويض من جانب الخادم فقط
- لا تخزن كلمات مرور المستخدمين على الجهاز؛ استخدم رموز وصول قابلة للإبطال
- تجنب تضمين الاعتمادات في تطبيق الجوال
- شفر الاعتمادات أثناء النقل
- استخدم التخزين الآمن الخاص بالمنصة (iOS Keychain، Android Keystore)
- اشترط تعقيد كلمة المرور وتجنب PINs قصيرة (4 أرقام)
- نفذ مهلات الجلسة ووظيفة تسجيل الخروج البعيد
- اشترط إعادة المصادقة للعمليات الحساسة
- استخدم المصادقة القياسية الحيوية المدعومة من المنصة مع احتياطات آمنة

**English:**
- Perform authentication/authorization server-side only
- Do not store user passwords on device; use revocable access tokens
- Avoid hardcoding credentials in the mobile app
- Encrypt credentials in transmission
- Use platform-specific secure storage (iOS Keychain, Android Keystore)
- Require password complexity and avoid short PINs (4 digits)
- Implement session timeouts and remote logout functionality
- Require re-authentication for sensitive operations
- Use platform-supported biometric authentication with secure fallbacks

```swift
// iOS: Secure Authentication with Keychain
import LocalAuthentication
import Security

class UAEAuthManager {
    static let shared = UAEAuthManager()
    private let context = LAContext()
    
    func authenticateUser(completion: @escaping (Bool, Error?) -> Void) {
        var error: NSError?
        
        // Check if biometric authentication is available
        if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) {
            context.evaluatePolicy(
                .deviceOwnerAuthenticationWithBiometrics,
                localizedReason: "Authenticate to access UAE Government Services"
            ) { success, error in
                DispatchQueue.main.async {
                    completion(success, error)
                }
            }
        } else {
            // Fallback to passcode
            context.evaluatePolicy(
                .deviceOwnerAuthentication,
                localizedReason: "Authentication required"
            ) { success, error in
                DispatchQueue.main.async {
                    completion(success, error)
                }
            }
        }
    }
    
    func storeToken(_ token: String) -> Bool {
        guard let data = token.data(using: .utf8) else { return false }
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: "uae_auth_token",
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecUseAuthenticationUI as String: kSecUseAuthenticationUIAllow
        ]
        
        SecItemDelete(query as CFDictionary)
        let status = SecItemAdd(query as CFDictionary, nil)
        return status == errSecSuccess
    }
    
    func retrieveToken() -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: "uae_auth_token",
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        guard status == errSecSuccess,
              let data = result as? Data,
              let token = String(data: data, encoding: .utf8) else {
            return nil
        }
        
        return token
    }
}
```

```kotlin
// Android: Secure Authentication with Keystore
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.biometric.BiometricPrompt
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

class UAEAuthManager(private val activity: FragmentActivity) {
    
    private val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    
    fun authenticateWithBiometric(callback: BiometricAuthCallback) {
        val executor = ContextCompat.getMainExecutor(activity)
        
        val prompt = BiometricPrompt(activity, executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: AuthenticationResult) {
                    callback.onSuccess(result.cryptoObject)
                }
                
                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    callback.onError(errorCode, errString.toString())
                }
                
                override fun onAuthenticationFailed() {
                    callback.onFailed()
                }
            })
        
        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("UAE Government Services")
            .setSubtitle("Authenticate to continue")
            .setNegativeButtonText("Use PIN")
            .setAllowedAuthenticators(
                BIOMETRIC_STRONG or DEVICE_CREDENTIAL
            )
            .build()
        
        val cipher = getCipher()
        val cryptoObject = BiometricPrompt.CryptoObject(cipher)
        prompt.authenticate(promptInfo, cryptoObject)
    }
    
    private fun getCipher(): Cipher {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val key = getOrCreateKey()
        cipher.init(Cipher.ENCRYPT_MODE, key)
        return cipher
    }
    
    private fun getOrCreateKey(): SecretKey {
        return keyStore.getKey("uae_biometric_key", null) as? SecretKey
            ?: generateKey()
    }
    
    private fun generateKey(): SecretKey {
        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            "AndroidKeyStore"
        )
        
        keyGenerator.init(
            KeyGenParameterSpec.Builder(
                "uae_biometric_key",
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setUserAuthenticationRequired(true)
                .setInvalidatedByBiometricEnrollment(true)
                .build()
        )
        
        return keyGenerator.generateKey()
    }
}
```

---

## تخزين البيانات والخصوصية — Data Storage and Privacy

**العربية:**
- شفر البيانات الحساسة باستخدام واجهات برمجة المنصة؛ تجنب التشفير المخصص
- استفد من ميزات الأمان المستندة إلى الأجهزة (Secure Enclave، Strongbox)
- خزن البيانات الخاصة في التخزين الداخلي للجهاز فقط
- قلل من جمع PII إلى الضرورة ونفذ انتهاء صلاحية تلقائي
- تجنب التخزين المؤقت أو التسجيل أو اللقطات الخلفية للبيانات الحساسة
- استخدم دائماً HTTPS للاتصالات الشبكية

**English:**
- Encrypt sensitive data using platform APIs; avoid custom encryption
- Leverage hardware-based security features (Secure Enclave, Strongbox)
- Store private data on device's internal storage only
- Minimize PII collection to necessity and implement automatic expiration
- Avoid caching, logging, or background snapshots of sensitive data
- Always use HTTPS for network communications

```swift
// iOS: Secure Data Storage
import Foundation

class UAESecureStorage {
    static let shared = UAESecureStorage()
    
    func storeSensitiveData(_ data: Data, key: String) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]
        
        SecItemDelete(query as CFDictionary)
        return SecItemAdd(query as CFDictionary, nil) == errSecSuccess
    }
    
    func retrieveSensitiveData(key: String) -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        
        var result: AnyObject?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let data = result as? Data else {
            return nil
        }
        
        return data
    }
    
    func clearSensitiveData(key: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key
        ]
        SecItemDelete(query as CFDictionary)
    }
}
```

```kotlin
// Android: Secure Data Storage with EncryptedSharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

class UAESecureStorage(context: Context) {
    
    private val masterKey = MasterKey.Builder(context)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .build()
    
    private val encryptedPrefs = EncryptedSharedPreferences.create(
        context,
        "uae_secure_prefs",
        masterKey,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )
    
    fun storeEmiratesId(emiratesId: String) {
        encryptedPrefs.edit()
            .putString("emirates_id", emiratesId)
            .apply()
    }
    
    fun retrieveEmiratesId(): String? {
        return encryptedPrefs.getString("emirates_id", null)
    }
    
    fun clearEmiratesId() {
        encryptedPrefs.edit()
            .remove("emirates_id")
            .apply()
    }
}
```

---

## الاتصال الشبكي — Network Communication

**العربية:**
- استخدم HTTPS لجميع الاتصالات الشبكية
- لا تتجاوز التحقق من صلاحية شهادة SSL للشهادات الموقعة ذاتياً
- استخدم مجموعات تشفير قوية ومتوافقة مع المعايير الصناعية مع أطول مفاتيح مناسبة
- استخدم شهادات موقعة من مزودي CA موثوقين
- فكر في تثبيت الشهادات للأمان الإضافي
- شفر البيانات حتى لو تم إرسالها عبر SSL
- تجنب إرسال البيانات الحساسة عبر SMS

**English:**
- Use HTTPS for all network communication
- Do not override SSL certificate validation for self-signed certificates
- Use strong, industry standard cipher suites with appropriate key lengths
- Use certificates signed by trusted CA providers
- Consider certificate pinning for additional security
- Encrypt data even if sent over SSL
- Avoid sending sensitive data via SMS

```swift
// iOS: Certificate Pinning
import Foundation

class UAEPinningDelegate: NSObject, URLSessionDelegate {
    
    private let pinnedHashes: [String]
    
    init(pinnedHashes: [String]) {
        self.pinnedHashes = pinnedHashes
    }
    
    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        guard let serverTrust = challenge.protectionSpace.serverTrust,
              let certificateChain = SecTrustCopyCertificateChain(serverTrust) as? [SecCertificate],
              let serverCertificate = certificateChain.first else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        
        // Get certificate data
        guard let serverCertificateData = SecCertificateCopyData(serverCertificate) as Data? else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        
        // Calculate hash
        let hash = sha256(data: serverCertificateData)
        
        // Verify against pinned hashes
        if pinnedHashes.contains(hash) {
            let credential = URLCredential(trust: serverTrust)
            completionHandler(.useCredential, credential)
        } else {
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }
    
    private func sha256(data: Data) -> String {
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        data.withUnsafeBytes {
            _ = CC_SHA256($0.baseAddress, CC_LONG(data.count), &hash)
        }
        return Data(hash).base64EncodedString()
    }
}
```

---

## جودة الكود ونزاهته — Code Quality and Integrity

**العربية:**
- استخدم أدوات التحليل الثابت لتحديد الثغرات
- اجعل الأمان نقطة محورية أثناء مراجعات الكود
- حافظ على جميع المكتبات محدثة لتصحيح الثغرات المعروفة
- عطل التصحيح في بنيات الإنتاج
- ضمّن كود للتحقق من نزاهة كود التطبيق
- قم بتشويش الثنائي التطبيقي
- نفذ ضوابط مكافحة العبث في وقت التشغيل

**English:**
- Use static analysis tools to identify vulnerabilities
- Make security a focal point during code reviews
- Keep all libraries up to date to patch known vulnerabilities
- Disable debugging in production builds
- Include code to validate integrity of application code
- Obfuscate the app binary
- Implement runtime anti-tampering controls

```kotlin
// Android: Runtime Security Checks
class UAESecurityChecks {
    
    fun isDeviceSecure(): Boolean {
        return !isRooted() && !isEmulator() && !isDebuggable()
    }
    
    private fun isRooted(): Boolean {
        val paths = arrayOf(
            "/system/app/Superuser.apk",
            "/sbin/su",
            "/system/bin/su",
            "/system/xbin/su",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/system/sd/xbin/su",
            "/system/bin/failsafe/su",
            "/data/local/su"
        )
        
        return paths.any { File(it).exists() }
    }
    
    private fun isEmulator(): Boolean {
        return (Build.FINGERPRINT.startsWith("generic") ||
                Build.FINGERPRINT.startsWith("unknown") ||
                Build.MODEL.contains("google_sdk") ||
                Build.MODEL.contains("Emulator") ||
                Build.MODEL.contains("Android SDK built for x86") ||
                Build.MANUFACTURER.contains("Genymotion") ||
                Build.BRAND.startsWith("generic") && Build.DEVICE.startsWith("generic") ||
                "google_sdk" == Build.PRODUCT)
    }
    
    private fun isDebuggable(): Boolean {
        return (applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0
    }
    
    fun verifyAppSignature(context: Context): Boolean {
        try {
            val packageInfo = context.packageManager.getPackageInfo(
                context.packageName,
                PackageManager.GET_SIGNATURES
            )
            
            val signatures = packageInfo.signatures
            // Verify against expected signature hash
            // This would be compared against a known good value
            return signatures?.isNotEmpty() == true
        } catch (e: Exception) {
            return false
        }
    }
}
```

---

## الأمان الخاص بالمنصة — Platform-Specific Security

### أمان Android

**العربية:**
- استخدم ProGuard الخاص بـ Android لتشويش الكود
- تجنب تخزين البيانات الحساسة في SharedPreferences
- عطل وضع النسخ الاحتياطي لمنع البيانات الحساسة في النسخ الاحتياطية
- استخدم Android Keystore مع دعم الأجهزة (TEE أو StrongBox)
- نفذ Google Play Integrity API لفحوصات نزاهة الجهاز والتطبيق

**English:**
- Use Android's ProGuard for code obfuscation
- Avoid storing sensitive data in SharedPreferences
- Disable backup mode to prevent sensitive data in backups
- Use Android Keystore with hardware backing (TEE or StrongBox)
- Implement Google's Play Integrity API for device and app integrity checks

```kotlin
// Android: Play Integrity API
class UAEIntegrityChecker(private val context: Context) {
    
    private val integrityManager = IntegrityManagerFactory.create(context)
    
    fun checkIntegrity(nonce: String, callback: IntegrityCallback) {
        val request = IntegrityTokenRequest.builder()
            .setNonce(nonce)
            .build()
        
        integrityManager.requestIntegrityToken(request)
            .addOnSuccessListener { response ->
                val token = response.token()
                // Send token to server for verification
                verifyTokenOnServer(token, callback)
            }
            .addOnFailureListener { exception ->
                callback.onError(exception)
            }
    }
    
    private fun verifyTokenOnServer(token: String, callback: IntegrityCallback) {
        // Server-side verification
        // This would call your backend to verify the token with Google
    }
}
```

### أمان iOS

**العربية:**
- اضبط أذونات الاختصارات لتتطلب فتح الجهاز للإجراءات الحساسة
- اضبط `requiresUserAuthentication` لـ Siri intent على true للوظائف الحساسة
- نفذ فحوصات المصادقة على نقاط نهاية الروابط العميقة
- استخدم منطق شرطي لإخفاء محتوى الودجات الحساس على شاشة القفل
- خزن البيانات الحساسة في iOS Keychain، ليس في ملفات plist
- استخدم Secure Enclave لتخزين المفاتيح التشفيرية
- نفذ App Attest API للتحقق من نزاهة التطبيق

**English:**
- Configure Shortcuts permissions to require device unlock for sensitive actions
- Set Siri intent `requiresUserAuthentication` to true for sensitive functionality
- Implement authentication checks on deep link endpoints
- Use conditional logic to mask sensitive widget content on lock screen
- Store sensitive data in iOS Keychain, not plist files
- Use Secure Enclave for cryptographic key storage
- Implement App Attest API for app integrity validation

```swift
// iOS: App Attest
import DeviceCheck

class UAEAppAttestManager {
    static let shared = UAEAppAttestManager()
    private let service = DCAppAttestService.shared
    
    func generateAttestation(completion: @escaping (Result<String, Error>) -> Void) {
        guard service.isSupported else {
            completion(.failure(AppAttestError.notSupported))
            return
        }
        
        // Generate challenge from server
        let challenge = generateChallenge()
        
        service.generateKey { keyId, error in
            if let error = error {
                completion(.failure(error))
                return
            }
            
            guard let keyId = keyId else {
                completion(.failure(AppAttestError.keyGenerationFailed))
                return
            }
            
            self.service.attestKey(keyId, clientDataHash: challenge) { attestation, error in
                if let error = error {
                    completion(.failure(error))
                    return
                }
                
                guard let attestation = attestation else {
                    completion(.failure(AppAttestError.attestationFailed))
                    return
                }
                
                // Send attestation to server for verification
                completion(.success(attestation.base64EncodedString()))
            }
        }
    }
    
    private func generateChallenge() -> Data {
        var bytes = [UInt8](repeating: 0, count: 32)
        _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        return Data(bytes)
    }
}
```

---

## الاختبار والمراقبة — Testing and Monitoring

**العربية:**
- نفذ اختبار الاختراق بما في ذلك تقييم الثغرات التشفيرية
- استفد من الاختبارات الآلية لضمان عمل ميزات الأمان كما هو متوقع
- تأكد من أن ميزات الأمان لا تضر بسهولة الاستخدام
- استخدم المراقبة في الوقت الفعلي للكشف عن التهديدات والاستجابة لها
- ضع خطة استجابة للحوادث واضحة
- خطط للتحديثات المنتظمة ونفذ آليات التحديث القسري عند الضرورة

**English:**
- Perform penetration testing including cryptographic vulnerability assessment
- Leverage automated tests to ensure security features work as expected
- Ensure security features do not harm usability
- Use real-time monitoring to detect and respond to threats
- Have a clear incident response plan in place
- Plan for regular updates and implement forced update mechanisms when necessary

---

## التحقق من المدخلات والمخرجات — Input and Output Validation

**العربية:**
- تحقق ونظف جميع مدخلات المستخدم
- تحقق ونظف المخرجات لمنع هجمات الحقن
- أخفِ المعلومات الحساسة في حقول واجهة المستخدم لمنع shoulder surfing
- أبلغ المستخدمين عن الأنشطة المتعلقة بالأمان (تسجيلات الدخول من أجهزة جديدة)

**English:**
- Validate and sanitize all user input
- Validate and sanitize output to prevent injection attacks
- Mask sensitive information on UI fields to prevent shoulder surfing
- Inform users about security-related activities (logins from new devices)

---

## قائمة التحقق — Implementation Checklist

- [ ] المصادقة من جانب الخادم فقط
- [ ] لا كلمات مرور مخزنة على الجهاز
- [ ] رموز وصول قابلة للإبطال
- [ ] لا اعتمادات مُضمنة
- [ ] تشفير أثناء النقل
- [ ] التخزين الآمن للمنصة (Keychain/Keystore)
- [ ] تعقيد كلمة المرور
- [ ] مهلات الجلسة
- [ ] تسجيل الخروج البعيد
- [ ] إعادة المصادقة للعمليات الحساسة
- [ ] المصادقة القياسية الحيوية
- [ ] تشفير البيانات الحساسة
- [ ] ميزات الأمان المستندة إلى الأجهزة
- [ ] تخزين داخلي فقط
- [ ] تقليل جمع PII
- [ ] انتهاء صلاحية تلقائي
- [ ] لا تخزين مؤقت للبيانات الحساسة
- [ ] HTTPS لجميع الاتصالات
- [ ] لا تجاوز للتحقق من SSL
- [ ] تشفير قوي
- [ ] شهادات CA موثوقة
- [ ] تثبيت الشهادات (اختياري)
- [ ] لا SMS للبيانات الحساسة
- [ ] تحليل ثابت
- [ ] مراجعات كود تركز على الأمان
- [ ] مكتبات محدثة
- [ ] تصحيح معطل في الإنتاج
- [ ] التحقق من نزاهة الكود
- [ ] تشويش الثنائي
- [ ] ضوابط مكافحة العبث
- [ ] ProGuard (Android)
- [ ] Play Integrity API (Android)
- [ ] App Attest (iOS)
- [ ] Secure Enclave (iOS)
- [ ] اختبار الاختراق
- [ ] مراقبة في الوقت الفعلي
- [ ] خطة استجابة للحوادث
- [ ] آليات التحديث القسري
- [ ] التحقق من المدخلات
- [ ] تنظيف المخرجات
- [ ] إخفاء الحقول الحساسة
- [ ] إشعارات الأمان للمستخدمين

---

## مراجع — References

- [OWASP Mobile Security Testing Guide](https://owasp.org/www-project-mobile-security-testing-guide/)
- [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/)
- [Android Security Best Practices](https://developer.android.com/topic/security/best-practices)
- [iOS Security Guide](https://support.apple.com/guide/security/welcome/web)
- [UAE Information Assurance Framework](https://www.tra.gov.ae/)
