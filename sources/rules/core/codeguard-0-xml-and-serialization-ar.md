---
description: أمان XML وإزالة التسلسل الآمنة (تقوية DTD/XXE، التحقق من المخطط، لا إزالة تسلسل أصلية غير آمنة)
languages:
- c
- go
- java
- php
- python
- ruby
- xml
tags:
- xml
- serialization
- xxe
- uae
alwaysApply: false
---

# تقوية XML والتسلسل — XML & Serialization Hardening

## نظرة عامة — Overview

تحليل ومعالجة آمنة لبيانات XML والمسلسلة؛ منع XXE، وتوسع الكيانات، وSSRF، وDoS، وإزالة التسلسل غير الآمنة عبر المنصات.

Secure parsing and processing of XML and serialized data; prevent XXE, entity expansion, SSRF, DoS, and unsafe deserialization across platforms.

---

## تقوية محلل XML — XML Parser Hardening

**العربية:**
- عطل DTDs والكيانات الخارجية افتراضياً؛ ارفض إعلانات DOCTYPE.
- تحقق بصرامة من XSDs محلية وموثوقة؛ اضبط حدود صريحة (الحجم، العمق، عدد العناصر).
- عزل أو احجز وصول المحلل؛ لا جلب شبكي أثناء التحليل؛ راقب نشاط DNS غير متوقع.

**English:**
- Disable DTDs and external entities by default; reject DOCTYPE declarations.
- Validate strictly against local, trusted XSDs; set explicit limits (size, depth, element counts).
- Sandbox or block resolver access; no network fetches during parsing; monitor for unexpected DNS activity.

---

## Java

**العربية:**
محللات Java لديها XXE مفعل افتراضياً.

**English:**
Java parsers have XXE enabled by default.

```java
// Java - Secure XML Parsing for UAE
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.XMLConstants;
import org.xml.sax.SAXException;

public class UAEXMLParser {
    
    public DocumentBuilderFactory createSecureFactory() {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        String FEATURE = null;
        
        try {
            // PRIMARY defense - disallow DTDs completely
            FEATURE = "http://apache.org/xml/features/disallow-doctype-decl";
            dbf.setFeature(FEATURE, true);
            dbf.setXIncludeAware(false);
        } catch (ParserConfigurationException e) {
            logger.warning("ParserConfigurationException: Feature '" + FEATURE 
                + "' not supported by XML processor");
        }
        
        // Additional security features
        dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        
        return dbf;
    }
    
    // If DTDs cannot be completely disabled
    public DocumentBuilderFactory createRestrictedFactory() {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        String[] featuresToDisable = {
            "http://xml.org/sax/features/external-general-entities",
            "http://xml.org/sax/features/external-parameter-entities",
            "http://apache.org/xml/features/nonvalidating/load-external-dtd"
        };
        
        for (String feature : featuresToDisable) {
            try {
                dbf.setFeature(feature, false);
            } catch (ParserConfigurationException e) {
                logger.warning("Feature '" + feature + "' not supported");
            }
        }
        
        dbf.setXIncludeAware(false);
        dbf.setExpandEntityReferences(false);
        dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        
        return dbf;
    }
}
```

---

## .NET

```csharp
// .NET - Secure XML Reading
using System.Xml;

public class UAEXMLReader
{
    public XmlReader CreateSecureReader(Stream stream)
    {
        var settings = new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null,
            MaxCharactersFromEntities = 1024,
            MaxCharactersInDocument = 10000000
        };
        
        return XmlReader.Create(stream, settings);
    }
}
```

---

## Python

```python
# Python - Secure XML Parsing
from defusedxml import ElementTree as ET
from lxml import etree

class UAEXMLParser:
    """Secure XML parser for UAE applications"""
    
    @staticmethod
    def parse_with_defusedxml(xml_file):
        """Parse XML using defusedxml (recommended)"""
        return ET.parse(xml_file)
    
    @staticmethod
    def parse_with_lxml(xml_file):
        """Parse XML using lxml with secure settings"""
        parser = etree.XMLParser(
            resolve_entities=False,
            no_network=True,
            strip_cdata=False,
            remove_blank_text=False
        )
        return etree.parse(xml_file, parser)
    
    @staticmethod
    def validate_against_schema(xml_file, xsd_file):
        """Validate XML against XSD schema"""
        with open(xsd_file, 'rb') as f:
            schema_root = etree.XML(f.read())
        
        schema = etree.XMLSchema(schema_root)
        
        with open(xml_file, 'rb') as f:
            xml_doc = etree.parse(f)
        
        schema.assertValid(xml_doc)
        return True
```

---

## استخدام XSLT/Transformer الآمن — Secure XSLT/Transformer Usage

**العربية:**
- اضبط `ACCESS_EXTERNAL_DTD` و`ACCESS_EXTERNAL_STYLESHEET` على فارغ؛ تجنب تحميل موارد بعيدة.

**English:**
- Set `ACCESS_EXTERNAL_DTD` and `ACCESS_EXTERNAL_STYLESHEET` to empty; avoid loading remote resources.

```java
// Java - Secure XSLT
import javax.xml.transform.TransformerFactory;

TransformerFactory tf = TransformerFactory.newInstance();
tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
```

---

## أمان إزالة التسلسل — Deserialization Safety

**العربية:**
- لا تُزل تسلسل كائنات أصلية غير موثوقة أبداً. فضّل JSON مع التحقق من المخطط.
- افرض حدود الحجم/الهيكل قبل التحليل. ارفض الأنواع متعددة الأشكال ما لم تكن في قائمة سماح صارمة.

**English:**
- Never deserialize untrusted native objects. Prefer JSON with schema validation.
- Enforce size/structure limits before parsing. Reject polymorphic types unless strictly allow-listed.

### PHP

```php
<?php
// ❌ Unsafe - never use with untrusted data
$data = unserialize($untrusted_input);

// ✅ Safe - use JSON instead
$data = json_decode($json_input, true);

// Validate JSON schema
$schema = json_decode(file_get_contents('schema.json'));
$validator = new JsonSchema\Validator();
$validator->validate($data, $schema);

if (!$validator->isValid()) {
    throw new Exception("Invalid data structure");
}
```

### Python

```python
# Python - Safe Deserialization
import json
import yaml
from marshmallow import Schema, fields, ValidationError

class UAEUserSchema(Schema):
    """Schema for UAE user data validation"""
    emirates_id = fields.String(required=True, validate=lambda x: len(x) == 15)
    name = fields.String(required=True, validate=lambda x: len(x) <= 100)
    email = fields.Email(required=True)
    department = fields.String(required=True)

class UAEDeserializer:
    """Safe deserializer for UAE applications"""
    
    @staticmethod
    def from_json(json_data):
        """Deserialize from JSON with schema validation"""
        try:
            data = json.loads(json_data)
            schema = UAEUserSchema()
            result = schema.load(data)
            return result
        except (json.JSONDecodeError, ValidationError) as e:
            raise ValueError(f"Invalid data: {e}")
    
    @staticmethod
    def from_yaml(yaml_data):
        """Deserialize from YAML safely"""
        # ❌ Never use yaml.load() - unsafe!
        # data = yaml.load(yaml_data)  # DANGEROUS!
        
        # ✅ Use safe_load only
        data = yaml.safe_load(yaml_data)
        
        schema = UAEUserSchema()
        result = schema.load(data)
        return result
    
    @staticmethod
    def from_pickle(data):
        """❌ NEVER use pickle with untrusted data"""
        raise SecurityError("Pickle deserialization is not allowed")
```

### Java

```java
// Java - Secure Deserialization
import java.io.*;
import java.util.Set;

public class UAESecureObjectInputStream extends ObjectInputStream {
    
    private static final Set<String> ALLOWED_CLASSES = Set.of(
        "com.uae.model.User",
        "com.uae.model.Department",
        "java.util.ArrayList",
        "java.lang.String"
    );
    
    public UAESecureObjectInputStream(InputStream in) throws IOException {
        super(in);
    }
    
    @Override
    protected Class<?> resolveClass(ObjectStreamClass desc) 
            throws IOException, ClassNotFoundException {
        String className = desc.getName();
        
        if (!ALLOWED_CLASSES.contains(className)) {
            throw new SecurityException("Class not allowed for deserialization: " + className);
        }
        
        return super.resolveClass(desc);
    }
}

// Usage
public class UAEDeserializer {
    public Object deserialize(byte[] data) throws IOException, ClassNotFoundException {
        try (InputStream is = new ByteArrayInputStream(data);
             ObjectInputStream ois = new UAESecureObjectInputStream(is)) {
            return ois.readObject();
        }
    }
}
```

### .NET

```csharp
// .NET - Secure Deserialization
using System.Text.Json;

public class UAEDeserializer
{
    private readonly JsonSerializerOptions _options = new JsonSerializerOptions
    {
        PropertyNameCaseInsensitive = true,
        // ❌ Never use TypeNameHandling.All or TypeNameHandling.Auto
        // TypeNameHandling = TypeNameHandling.None (default)
    };
    
    public T Deserialize<T>(string json)
    {
        return JsonSerializer.Deserialize<T>(json, _options);
    }
    
    // ❌ Avoid BinaryFormatter
    // public object DeserializeBinary(byte[] data)
    // {
    //     var formatter = new BinaryFormatter(); // DANGEROUS!
    //     ...
    // }
}
```

---

## التوقيع والتحقق — Signing and Verification

**العربية:**
- وقّع وتحقق من الحمولات المسلسلة حيثما ينطبق؛ سجل وحذّر على فشل إزالة التسلسل والشذوذات.

**English:**
- Sign and verify serialized payloads where applicable; log and alert on deserialization failures and anomalies.

```python
# Python - Sign and Verify Serialized Data
import hmac
import hashlib
import json

class UAEDataSigner:
    """Sign and verify serialized data"""
    
    def __init__(self, secret_key: str):
        self.secret_key = secret_key.encode()
    
    def sign(self, data: dict) -> str:
        """Sign JSON data"""
        json_data = json.dumps(data, sort_keys=True)
        signature = hmac.new(
            self.secret_key,
            json_data.encode(),
            hashlib.sha256
        ).hexdigest()
        
        return f"{signature}.{json_data}"
    
    def verify(self, signed_data: str) -> dict:
        """Verify and return data"""
        try:
            signature, json_data = signed_data.split('.', 1)
            
            expected_signature = hmac.new(
                self.secret_key,
                json_data.encode(),
                hashlib.sha256
            ).hexdigest()
            
            if not hmac.compare_digest(signature, expected_signature):
                raise SecurityError("Invalid signature")
            
            return json.loads(json_data)
        except (ValueError, json.JSONDecodeError) as e:
            raise SecurityError(f"Invalid data format: {e}")
```

---

## قائمة التحقق — Implementation Checklist

- [ ] DTDs معطلة؛ الكيانات الخارجية معطلة؛ التحقق من المخطط صارم؛ حدود المحلل مضبوطة
- [ ] لا وصول شبكي أثناء التحليل؛ المحللات مقيدة؛ التدقيق قائم
- [ ] لا إزالة تسلسل أصلية غير آمنة؛ قوائم سماح صارمة والتحقق من المخطط للتنسيقات المدعومة
- [ ] تحديثات منتظمة للمكتبات واختبارات مع حمولات XXE/إزالة التسلسل
- [ ] توقيع وتحقق من الحمولات المسلسلة
- [ ] تسجيل وحذّر على فشل إزالة التسلسل
- [ ] مراقبة نشاط DNS غير متوقع
- [ ] حدود صريحة على حجم XML وعمقه وعدد العناصر

---

## مراجع — References

- [OWASP XML External Entity (XXE) Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
- [OWASP Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)
- [CWE-611: Improper Restriction of XXE](https://cwe.mitre.org/data/definitions/611.html)
- [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
- [defusedxml Python Library](https://pypi.org/project/defusedxml/)
- [UAE Information Assurance Framework](https://www.tra.gov.ae/)
