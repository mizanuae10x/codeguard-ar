---
description: التعامل الآمن بالملفات والتحميلات (التحقق، عزل التخزين، الفحص، التسليم الآمن)
languages:
- c
- go
- java
- javascript
- php
- python
- ruby
- typescript
tags:
- file-upload
- security
- uae
alwaysApply: false
---

# أمان تحميل الملفات — File Upload Security Guidelines

## نظرة عامة — Overview

يقدم هذا القسم إرشادات لممارسات تحميل الملفات الآمنة لمنع هجمات الملفات الضارة وحماية سلامة النظام.

This section advises on secure file upload practices to prevent malicious file attacks and protect system integrity.

---

## التحقق من الامتداد — Extension Validation

**العربية:**
- اذكر الامتدادات المسموح بها فقط للوظائف الحرجة للأعمال.
- تأكد من تطبيق التحقق من المدخلات قبل التحقق من الامتدادات.
- تجنب الامتدادات المزدوجة (مثال: `.jpg.php`) وحقن البايت الفارغ (مثال: `.php%00.jpg`).
- استخدم نهج قائمة السماح بدلاً من قائمة الرفض لامتدادات الملفات.
- تحقق من الامتدادات بعد فك تشفير اسم الملف لمنع محاولات التجاوز.

**English:**
- List allowed extensions only for business-critical functionality.
- Ensure input validation is applied before validating extensions.
- Avoid double extensions (e.g., `.jpg.php`) and null byte injection (e.g., `.php%00.jpg`).
- Use allowlist approach rather than denylist for file extensions.
- Validate extensions after decoding filename to prevent bypass attempts.

```python
# Python File Extension Validation
import os
import re
from pathlib import Path

class UAEFileValidator:
    """
    UAE-compliant file upload validator
    """
    
    # Allowed extensions for government documents
    ALLOWED_EXTENSIONS = {
        'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
        'jpg', 'jpeg', 'png', 'gif', 'bmp', 'tiff',
        'txt', 'csv', 'xml', 'json',
        'zip', 'rar', '7z'
    }
    
    # Dangerous extensions to block
    DANGEROUS_EXTENSIONS = {
        'exe', 'dll', 'bat', 'cmd', 'sh', 'php', 'asp', 'aspx',
        'jsp', 'py', 'rb', 'pl', 'cgi', 'jar', 'war', 'ear'
    }
    
    @classmethod
    def validate_extension(cls, filename: str) -> tuple[bool, str]:
        """
        Validate file extension
        Returns: (is_valid, extension)
        """
        # Decode filename (URL decode, etc.)
        from urllib.parse import unquote
        decoded = unquote(filename)
        
        # Remove null bytes
        decoded = decoded.replace('\x00', '')
        
        # Get extension
        ext = Path(decoded).suffix.lower().lstrip('.')
        
        # Check for double extensions
        if '.' in Path(decoded).stem:
            return False, "double_extension"
        
        # Check against allowlist
        if ext not in cls.ALLOWED_EXTENSIONS:
            return False, f"extension_not_allowed:{ext}"
        
        # Check against denylist (defense in depth)
        if ext in cls.DANGEROUS_EXTENSIONS:
            return False, f"dangerous_extension:{ext}"
        
        return True, ext
    
    @classmethod
    def sanitize_filename(cls, filename: str) -> str:
        """
        Sanitize filename for safe storage
        """
        # Remove path components
        filename = os.path.basename(filename)
        
        # Remove null bytes
        filename = filename.replace('\x00', '')
        
        # Remove leading periods (hidden files)
        filename = filename.lstrip('.')
        
        # Remove sequential periods
        filename = re.sub(r'\.{2,}', '.', filename)
        
        # Remove leading hyphens or spaces
        filename = filename.lstrip('- ')
        
        # Restrict characters
        filename = re.sub(r'[^a-zA-Z0-9._-]', '_', filename)
        
        # Limit length
        if len(filename) > 255:
            name, ext = os.path.splitext(filename)
            filename = name[:250] + ext
        
        return filename
```

---

## التحقق من نوع المحتوى وتوقيع الملف — Content Type and File Signature Validation

**العربية:**
- لا تثق أبداً برؤوس Content-Type المقدمة من العميل لأنه يمكن تزويرها.
- تحقق من توقيعات الملف (أرقام السحر) بالاقتران مع فحص Content-Type.
- نفذ نهج قائمة السماح لأنواع MIME كطبقة حماية سريعة.
- استخدم التحقق من توقيع الملف ولكن ليس كإجراء أمني مستقل.

**English:**
- Never trust client-supplied Content-Type headers as they can be spoofed.
- Validate file signatures (magic numbers) in conjunction with Content-Type checking.
- Implement allowlist approach for MIME types as a quick protection layer.
- Use file signature validation but not as a standalone security measure.

```python
# Python File Signature Validation
import struct
from typing import Dict, Tuple

class UAEFileSignatureValidator:
    """
    Validate file signatures (magic numbers)
    """
    
    # Known file signatures
    SIGNATURES: Dict[str, Tuple[bytes, int]] = {
        'pdf': (b'%PDF', 0),
        'jpg': (b'\xff\xd8\xff', 0),
        'jpeg': (b'\xff\xd8\xff', 0),
        'png': (b'\x89PNG\r\n\x1a\n', 0),
        'gif': (b'GIF87a', 0),
        'gif89a': (b'GIF89a', 0),
        'zip': (b'PK\x03\x04', 0),
        'docx': (b'PK\x03\x04', 0),  # ZIP-based
        'xlsx': (b'PK\x03\x04', 0),  # ZIP-based
    }
    
    MIME_TYPES: Dict[str, str] = {
        'pdf': 'application/pdf',
        'jpg': 'image/jpeg',
        'jpeg': 'image/jpeg',
        'png': 'image/png',
        'gif': 'image/gif',
        'zip': 'application/zip',
        'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    }
    
    @classmethod
    def validate_signature(cls, file_path: str, expected_ext: str) -> tuple[bool, str]:
        """
        Validate file signature matches expected extension
        """
        signature_info = cls.SIGNATURES.get(expected_ext)
        if not signature_info:
            return False, "unknown_extension"
        
        expected_signature, offset = signature_info
        
        with open(file_path, 'rb') as f:
            f.seek(offset)
            actual_signature = f.read(len(expected_signature))
        
        if actual_signature != expected_signature:
            return False, f"signature_mismatch: expected {expected_signature.hex()}, got {actual_signature.hex()}"
        
        return True, "signature_valid"
    
    @classmethod
    def get_mime_type(cls, ext: str) -> str:
        """Get MIME type for extension"""
        return cls.MIME_TYPES.get(ext, 'application/octet-stream')
```

---

## أمان اسم الملف — Filename Security

**العربية:**
- أنشئ أسماء ملفات عشوائية (UUID/GUID) بدلاً من استخدام الأسماء المقدمة من المستخدم.
- إذا كانت أسماء المستخدمين مطلوبة، نفذ حدوداً قصوى للطول.
- قصر الأحرف على الأبجدية الرقمية، الواصلات، المسافات، والنقاط فقط.
- منع النقاط البادئة (الملفات المخفية) والنقاط المتسلسلة (الانتقال عبر الدلائل).
- تجنب الواصلات أو المسافات البادئة لمعالجة سكربت الصدفة بأمان.

**English:**
- Generate random filenames (UUID/GUID) instead of using user-supplied names.
- If user filenames required, implement maximum length limits.
- Restrict characters to alphanumeric, hyphens, spaces, and periods only.
- Prevent leading periods (hidden files) and sequential periods (directory traversal).
- Avoid leading hyphens or spaces for safer shell script processing.

```python
# Python Secure Filename Generation
import uuid
import hashlib
from datetime import datetime

class UAEFilenameGenerator:
    """
    Generate secure filenames for UAE government uploads
    """
    
    @staticmethod
    def generate_uuid_filename(original_ext: str) -> str:
        """Generate UUID-based filename"""
        return f"{uuid.uuid4().hex}.{original_ext}"
    
    @staticmethod
    def generate_hash_filename(file_content: bytes, original_ext: str) -> str:
        """Generate hash-based filename"""
        file_hash = hashlib.sha256(file_content).hexdigest()[:16]
        return f"{file_hash}.{original_ext}"
    
    @staticmethod
    def generate_timestamp_filename(original_ext: str, user_id: str) -> str:
        """Generate timestamp-based filename with user ID"""
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        user_hash = hashlib.sha256(user_id.encode()).hexdigest()[:8]
        return f"{timestamp}_{user_hash}.{original_ext}"
    
    @classmethod
    def generate_secure_filename(cls, file_content: bytes, original_ext: str, user_id: str = None) -> str:
        """
        Generate secure filename with multiple strategies
        """
        # Use content hash for deduplication
        content_hash = hashlib.sha256(file_content).hexdigest()[:16]
        
        # Add timestamp for uniqueness
        timestamp = datetime.utcnow().strftime('%Y%m%d')
        
        # Add user hash if available
        if user_id:
            user_hash = hashlib.sha256(user_id.encode()).hexdigest()[:8]
            return f"{timestamp}_{user_hash}_{content_hash}.{original_ext}"
        
        return f"{timestamp}_{content_hash}.{original_ext}"
```

---

## التحقق من محتوى الملف — File Content Validation

**العربية:**
- للصور، طبق تقنيات إعادة كتابة الصورة لتدمير المحتوى الضار.
- لمستندات Microsoft، استخدم Apache POI للتحقق.
- تجنب ملفات ZIP بسبب متجهات الهجوم العديدة.
- نفذ مراجعة يدوية للملف في بيئات معزولة عندما تسمح الموارد.
- دمج الفحص بمكافحة الفيروسات وتفكيك وإعادة بناء المحتوى (CDR) لأنواع الملفات المطبقة.

**English:**
- For images, apply image rewriting techniques to destroy malicious content.
- For Microsoft documents, use Apache POI for validation.
- Avoid ZIP files due to numerous attack vectors.
- Implement manual file review in sandboxed environments when resources allow.
- Integrate antivirus scanning and Content Disarm & Reconstruct (CDR) for applicable file types.

```python
# Python Image Rewriting for Security
from PIL import Image
import io

def sanitize_image(file_path: str, output_path: str) -> bool:
    """
    Sanitize image by rewriting it
    This destroys embedded malicious content
    """
    try:
        # Open image
        with Image.open(file_path) as img:
            # Convert to RGB (removes alpha channel exploits)
            if img.mode in ('RGBA', 'P'):
                img = img.convert('RGB')
            
            # Save with new format
            img.save(output_path, 'PNG', optimize=True)
        
        return True
    except Exception as e:
        logging.error(f"Image sanitization failed: {e}")
        return False

# Antivirus scanning integration
class UAEAntivirusScanner:
    """
    Integrate with antivirus for file scanning
    """
    
    @staticmethod
    def scan_file(file_path: str) -> tuple[bool, str]:
        """
        Scan file with antivirus
        Returns: (is_clean, message)
        """
        import subprocess
        
        try:
            # Example with ClamAV
            result = subprocess.run(
                ['clamscan', '--no-summary', file_path],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0:
                return True, "clean"
            elif result.returncode == 1:
                return False, f"virus_found: {result.stdout}"
            else:
                return False, f"scan_error: {result.stderr}"
                
        except Exception as e:
            return False, f"scan_failed: {str(e)}"
```

---

## أمان التخزين — Storage Security

**العربية:**
- خزن الملفات على خوادم مختلفة للفصل الكامل عندما يكون ممكناً.
- خزن الملفات خارج webroot مع وصول إداري فقط.
- إذا كان التخزين في webroot، اضبط أذونات الكتابة فقط مع ضوابط وصول مناسبة.
- استخدم معالجات التطبيق التي تعين المعرفات إلى أسماء الملفات للوصول العام.
- فكر في تخزين قاعدة البيانات لحالات استخدام محددة مع خبرة DBA.

**English:**
- Store files on different servers for complete segregation when possible.
- Store files outside webroot with administrative access only.
- If storing in webroot, set write-only permissions with proper access controls.
- Use application handlers that map IDs to filenames for public access.
- Consider database storage for specific use cases with DBA expertise.

```python
# Python Secure File Storage
import os
import shutil
from pathlib import Path

class UAESecureStorage:
    """
    Secure file storage for UAE government uploads
    """
    
    def __init__(self, base_path: str, web_root: str):
        self.base_path = Path(base_path)
        self.web_root = Path(web_root)
        
        # Ensure base path is outside web root
        if self.base_path.resolve().is_relative_to(self.web_root.resolve()):
            raise SecurityError("Storage path must be outside web root")
    
    def store_file(self, file_content: bytes, secure_filename: str, user_id: str) -> str:
        """
        Store file securely
        Returns: file_id for retrieval
        """
        # Generate file ID
        file_id = hashlib.sha256(
            f"{secure_filename}:{user_id}:{datetime.utcnow().isoformat()}".encode()
        ).hexdigest()[:16]
        
        # Create user-specific directory
        user_dir = self.base_path / hashlib.sha256(user_id.encode()).hexdigest()[:8]
        user_dir.mkdir(parents=True, exist_ok=True)
        
        # Set restrictive permissions
        user_dir.chmod(0o700)
        
        # Store file
        file_path = user_dir / secure_filename
        with open(file_path, 'wb') as f:
            f.write(file_content)
        
        # Set file permissions
        file_path.chmod(0o600)
        
        # Store metadata
        metadata = {
            'file_id': file_id,
            'original_name': secure_filename,
            'stored_path': str(file_path),
            'user_id': user_id,
            'uploaded_at': datetime.utcnow().isoformat(),
            'size': len(file_content),
        }
        
        self._store_metadata(file_id, metadata)
        
        return file_id
    
    def retrieve_file(self, file_id: str, user_id: str) -> bytes:
        """
        Retrieve file securely
        """
        metadata = self._get_metadata(file_id)
        
        # Verify ownership
        if metadata['user_id'] != user_id:
            raise PermissionError("Access denied")
        
        file_path = Path(metadata['stored_path'])
        
        if not file_path.exists():
            raise FileNotFoundError("File not found")
        
        with open(file_path, 'rb') as f:
            return f.read()
    
    def _store_metadata(self, file_id: str, metadata: dict):
        """Store file metadata"""
        metadata_path = self.base_path / 'metadata' / f"{file_id}.json"
        metadata_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f)
    
    def _get_metadata(self, file_id: str) -> dict:
        """Get file metadata"""
        metadata_path = self.base_path / 'metadata' / f"{file_id}.json"
        
        with open(metadata_path, 'r') as f:
            return json.load(f)
```

---

## التحكم بالوصول والمصادقة — Access Control and Authentication

**العربية:**
- اشترط مصادقة المستخدم قبل السماح بتحميل الملفات.
- نفذ مستويات تفويض مناسبة للوصول إلى الملفات والتعديل.
- اضبط أذونات نظام الملفات على مبدأ أقل الامتياز.
- افحص الملفات قبل التنفيذ إذا كان إذن التنفيذ مطلوباً.

**English:**
- Require user authentication before allowing file uploads.
- Implement proper authorization levels for file access and modification.
- Set filesystem permissions on principle of least privilege.
- Scan files before execution if execution permission is required.

---

## حدود التحميل والتنزيل — Upload and Download Limits

**العربية:**
- اضبط حدود حجم ملف مناسبة لحماية التحميل.
- فكر في حدود الحجم بعد فك الضغط للملفات المضغوطة.
- نفذ حدود الطلب لخدمات التنزيل لمنع هجمات DoS.
- استخدم طرق آمنة لحساب أحجام ملفات ZIP.

**English:**
- Set proper file size limits for upload protection.
- Consider post-decompression size limits for compressed files.
- Implement request limits for download services to prevent DoS attacks.
- Use secure methods to calculate ZIP file sizes safely.

```python
# Python Upload Limits
class UAEUploadLimits:
    """
    Upload limits for UAE government systems
    """
    
    # Maximum file sizes by type (bytes)
    MAX_SIZES = {
        'document': 10 * 1024 * 1024,      # 10 MB
        'image': 5 * 1024 * 1024,          # 5 MB
        'spreadsheet': 10 * 1024 * 1024,   # 10 MB
        'archive': 50 * 1024 * 1024,       # 50 MB
        'general': 10 * 1024 * 1024,       # 10 MB
    }
    
    # Maximum decompressed size for archives
    MAX_DECOMPRESSED_SIZE = 100 * 1024 * 1024  # 100 MB
    
    @classmethod
    def check_size(cls, file_size: int, file_type: str) -> tuple[bool, str]:
        """Check if file size is within limits"""
        max_size = cls.MAX_SIZES.get(file_type, cls.MAX_SIZES['general'])
        
        if file_size > max_size:
            return False, f"file_too_large: max {max_size} bytes"
        
        return True, "size_ok"
    
    @classmethod
    def check_archive_size(cls, archive_path: str) -> tuple[bool, str]:
        """Check decompressed archive size"""
        import zipfile
        
        try:
            with zipfile.ZipFile(archive_path, 'r') as zf:
                total_size = sum(info.file_size for info in zf.infolist())
                
                if total_size > cls.MAX_DECOMPRESSED_SIZE:
                    return False, f"archive_too_large: {total_size} bytes"
                
                return True, "archive_size_ok"
        except Exception as e:
            return False, f"archive_error: {str(e)}"
```

---

## تدابير أمان إضافية — Additional Security Measures

**العربية:**
- حماية نقاط نهاية تحميل الملفات من هجمات CSRF.
- حافظ على جميع مكتبات معالجة الملفات مُكوَّنة بأمان ومُحدَّثة.
- نفذ التسجيل والمراقبة لأنشطة التحميل.
- قدم آليات إبلاغ المستخدمين عن المحتوى غير القانوني.
- استخدم طرق استخراج آمنة للملفات المضغوطة.

**English:**
- Protect file upload endpoints from CSRF attacks.
- Keep all file processing libraries securely configured and updated.
- Implement logging and monitoring for upload activities.
- Provide user reporting mechanisms for illegal content.
- Use secure extraction methods for compressed files.

---

## قائمة التحقق — Implementation Checklist

- [ ] قائمة سماح للامتدادات
- [ ] التحقق من توقيع الملف
- [ ] التحقق من نوع MIME
- [ ] أسماء ملفات عشوائية (UUID)
- [ ] تطهير اسم الملف
- [ ] التحقق من محتوى الملف
- [ ] إعادة كتابة الصور
- [ ] فحص مكافحة الفيروسات
- [ ] CDR للمستندات
- [ ] تخزين خارج webroot
- [ ] أذونات صارمة
- [ ] مصادقة مطلوبة
- [ ] تفويض مناسب
- [ ] حدود حجم الملف
- [ ] حدود فك الضغط
- [ ] حماية CSRF
- [ ] التسجيل والمراقبة
- [ ] استخراج آمن للأرشيفات

---

## مراجع — References

- [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)
- [OWASP Unrestricted File Upload](https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload)
- [CWE-434: Unrestricted Upload of File with Dangerous Type](https://cwe.mitre.org/data/definitions/434.html)
- [UAE Information Assurance Framework](https://www.tra.gov.ae/)
