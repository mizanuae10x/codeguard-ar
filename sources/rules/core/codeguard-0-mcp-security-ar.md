---
description: أمان MCP (Model Context Protocol) بناءً على إرشادات CoSAI MCP Security
languages:
- python
- javascript
- typescript
- go
- rust
- java
tags:
- mcp
- ai
- security
- uae
alwaysApply: false
---

# أمان MCP (Model Context Protocol) — MCP Security Guidelines

## نظرة عامة — Overview

**لا تنشر** خوادم أو عملاء MCP دون تنفيذ ضوابط أمان مناسبة.

NEVER deploy MCP servers or clients without implementing proper security controls.

---

## هوية حمل العمل والمصادقة — Workload Identity and Authentication

**العربية:**
- استخدم SPIFFE/SPIRE لهويات حمل عمل تشفيرية.
- SPIFFE (Secure Production Identity Framework For Everyone) يوفر معياراً لهوية الخدمة.
- SPIRE (SPIFFE Runtime Environment) يصدر ويدير هويات تشفيرية قصيرة العمر (SVIDs).

**English:**
- Use SPIFFE/SPIRE for cryptographic workload identities.
- SPIFFE provides a standard for service identity.
- SPIRE issues and rotates short-lived cryptographic identities (SVIDs).

```yaml
# SPIRE Agent Configuration for UAE
agent {
  trust_domain = "uae.gov.ae"
  data_dir = "/opt/spire/data"
  log_level = "INFO"
  
  plugins {
    NodeAttestor "join_token" {
      plugin_data {}
    }
    
    KeyManager "memory" {
      plugin_data {}
    }
    
    WorkloadAttestor "unix" {
      plugin_data {}
    }
  }
}
```

---

## تطهير المدخلات والبيانات — Input and Data Sanitization

**العربية:**
- تحقق من **جميع** المدخلات باستخدام قوائم السماح عند كل حدود الثقة.
- نظف مسارات الملفات من خلال التوحيد القياسي.
- استخدم استعلامات معاملات لعمليات قاعدة البيانات.
- طبق ترميز المخرجات المدرك للسياق (SQL، shell، HTML).
- نظف مخرجات الأدوات: أرجع فقط الحقول الدنيا، اكتب جميع PII والبيانات الحساسة.
- عامل **جميع** المدخلات، ومخططات الأدوات، والبيانات الوصفية، والموجهات، ومحتوى الموارد كمدخلات غير موثوقة.
- انشر أنظمة كشف حقن الموجهات.
- استخدم مخططات JSON صارمة للحفاظ على الحدود بين التعليمات والبيانات.

**English:**
- Validate ALL inputs using allowlists at every trust boundary.
- Sanitize file paths through canonicalization.
- Use parameterized queries for database operations.
- Apply context-aware output encoding (SQL, shell, HTML).
- Sanitize tool outputs: return only minimum fields, redact all PII and sensitive data.
- Treat ALL inputs, tool schemas, metadata, prompts, and resource content as untrusted input.
- Deploy prompt injection detection systems.
- Use strict JSON schemas to maintain boundaries between instructions and data.

```python
# Python MCP Input Validation
import re
import json
from typing import Any, Dict, List

class UAEMCPValidator:
    """
    Validate MCP inputs for UAE compliance
    """
    
    # Allowed characters for file paths
    PATH_PATTERN = re.compile(r'^[a-zA-Z0-9_\-\./]+$')
    
    # Blocked commands
    BLOCKED_COMMANDS = [
        'rm', 'del', 'format', 'mkfs',
        'dd', 'fdisk', 'parted',
        'wget', 'curl', 'nc', 'netcat',
    ]
    
    @classmethod
    def validate_path(cls, path: str) -> bool:
        """Validate file path"""
        if not path:
            return False
        
        # Check against allowed pattern
        if not cls.PATH_PATTERN.match(path):
            return False
        
        # Check for path traversal
        normalized = os.path.normpath(path)
        if '..' in normalized:
            return False
        
        return True
    
    @classmethod
    def sanitize_tool_output(cls, output: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize tool output - remove PII"""
        sensitive_fields = [
            'password', 'token', 'secret', 'key',
            'emirates_id', 'passport', 'visa',
            'credit_card', 'iban', 'salary',
        ]
        
        sanitized = {}
        for key, value in output.items():
            if any(field in key.lower() for field in sensitive_fields):
                sanitized[key] = '[REDACTED]'
            else:
                sanitized[key] = value
        
        return sanitized
    
    @classmethod
    def validate_command(cls, command: str) -> bool:
        """Validate shell command"""
        parts = command.split()
        if not parts:
            return False
        
        # Check if command is in blocked list
        if parts[0] in cls.BLOCKED_COMMANDS:
            return False
        
        return True
```

---

## العزل والحماية — Sandboxing and Isolation

**العربية:**
- صمم خوادم MCP للتنفيذ بأقل الامتيازات.
- خوادم MCP التي تتفاعل مع بيئة المضيف (الملفات، الأوامر، الشبكة) **يجب** أن تنفذ ضوابط العزل.
- كود مولد بواسطة LLM **يجب ألا** يعمل بامتيازات المستخدم الكاملة.
- نفذ طبقات عزل إضافية: gVisor، Kata Containers، SELinux sandboxes.

**English:**
- Design MCP servers to execute with least privilege.
- MCP servers interacting with host environment MUST implement sandboxing controls.
- LLM-generated code MUST NOT run with full user privileges.
- Implement additional sandboxing layers: gVisor, Kata Containers, SELinux sandboxes.

```yaml
# Docker Compose with gVisor Sandbox
version: '3.8'

services:
  mcp-server:
    image: uae-mcp-server:latest
    runtime: runsc  # gVisor runtime
    read_only: true
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE
    tmpfs:
      - /tmp:noexec,nosuid,size=100m
    volumes:
      - type: bind
        source: ./allowed-data
        target: /data
        read_only: true
    network_mode: none  # No network access
    user: "1000:1000"
    
  # SELinux labels
    labels:
      - "selinux.type=mcp_server_t"
      - "selinux.level=s0"
```

---

## التحقق التشفيري من الموارد — Cryptographic Verification of Resources

**العربية:**
- قدم توقيعات تشفيرية وSBOMs لجميع كود الخادم.
- نفذ التحقق من التوقيعات في عميل MCP قبل تحميل الخوادم.
- استخدم TLS لجميع البيانات أثناء النقل.
- نفذ قدرات التصديق البعيد للتحقق من أن الخوادم تعمل الكود المتوقع.

**English:**
- Provide cryptographic signatures and SBOMs for all server code.
- Implement signature verification in your MCP client before loading servers.
- Use TLS for ALL data in transit.
- Implement remote attestation capabilities to verify servers are running expected code.

```python
# Python Signature Verification
import hashlib
import subprocess
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

class UAEMCPVerifier:
    """
    Verify MCP server signatures
    """
    
    @staticmethod
    def verify_sbom_signature(sbom_path: str, signature_path: str, public_key_path: str) -> bool:
        """Verify SBOM signature"""
        # Load public key
        with open(public_key_path, 'rb') as f:
            public_key = serialization.load_pem_public_key(f.read())
        
        # Load SBOM and signature
        with open(sbom_path, 'rb') as f:
            sbom_data = f.read()
        
        with open(signature_path, 'rb') as f:
            signature = f.read()
        
        # Verify signature
        try:
            public_key.verify(
                signature,
                sbom_data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False
    
    @staticmethod
    def generate_sbom_hash(sbom_path: str) -> str:
        """Generate SHA-256 hash of SBOM"""
        with open(sbom_path, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()
```

---

## أمان طبقة النقل — Transport Layer Security

### نقل stdio (الخوادم المحلية)

**العربية:**
- **موصى به بشدة** لـ MCP المحلي للقضاء على مخاطر DNS rebinding.
- تواصل مباشر قائم على الأنابيب.
- نفذ عزل لمنع تصعيد الامتيازات.

**English:**
- STRONGLY RECOMMENDED for local MCP to eliminate DNS rebinding risks.
- Direct pipe-based stream communication.
- Implement sandbox to prevent privilege escalation.

### نقل HTTP Streaming (الخوادم البعيدة)

**العربية:**
ضوابط أمان مطلوبة:
- حدود الحمولة (منع DoS بالحمولة الكبيرة والمتكررة)
- تحديد المعدل لاستدعاءات الأدوات وطلبات النقل
- مصادقة/تفويض العميل-الخادم
- مصادقة TLS المتبادلة
- تشفير TLS
- حماية CORS
- حماية CSRF
- فحوصات النزاهة (منع الإعادة، والتزييف، والاستجابات المسمومة)

**English:**
Required security controls:
- Payload Limits (prevent large payload and recursive payload DoS)
- Rate limiting for tool calls and transport requests
- Client-Server Authentication/Authorization
- Mutual TLS Authentication
- TLS Encryption
- CORS Protection
- CSRF Protection
- Integrity Checks (prevent replay, spoofing, poisoned responses)

```python
# Python MCP Server with Security Controls
from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter
from slowapi.util import get_remote_address
import ssl

app = FastAPI()
security = HTTPBearer()
limiter = Limiter(key_func=get_remote_address)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://tamkeenai.ae", "https://ciso.tamkeenai.ae"],
    allow_credentials=True,
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)

# Rate limiting
@app.post("/tools/execute")
@limiter.limit("10/minute")
async def execute_tool(
    request: ToolRequest,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Execute MCP tool with security controls"""
    # Verify JWT token
    if not verify_jwt(credentials.credentials):
        raise HTTPException(status_code=401, detail="Invalid token")
    
    # Validate request size
    if len(request.parameters) > 10000:
        raise HTTPException(status_code=413, detail="Payload too large")
    
    # Execute tool with sandboxing
    result = await execute_sandboxed(request)
    
    # Sanitize output
    return sanitize_output(result)

# mTLS configuration
ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
ssl_context.verify_mode = ssl.CERT_REQUIRED
ssl_context.load_cert_chain('server.crt', 'server.key')
ssl_context.load_verify_locations('ca.crt')
```

---

## تصميم أدوات وUX آمن — Secure Tool and UX Design

**العربية:**
- أنشئ أدوات ذات غرض واحد مع حدود صريحة؛ تجنب أدوات "افعل أي شيء".
- لا تعتمد على LLM لقرارات التحقق أو التفويض.
- استخدم التزام ثنائي المرحلة للإجراءات عالية التأثير: مسودة/معاينة أولاً، التزام صريح مع تأكيد ثانياً.
- قدم مسارات التراجع/التراجع (معرفات المسودات، لقطات، إجراءات قابلة للعكس) والالتزامات المحددة بوقت عندما يكون ممكناً.

**English:**
- Create single-purpose tools with explicit boundaries; avoid "do anything" tools.
- Do not rely on the LLM for validation or authorization decisions.
- Use two-stage commit for high-impact actions: draft/preview first, explicit commit with confirmation second.
- Provide rollback/undo paths (draft IDs, snapshots, reversible actions) and time-bound commits when possible.

```typescript
// TypeScript MCP Tool with Two-Stage Commit
interface ToolRequest {
  action: string;
  parameters: Record<string, any>;
  confirmation?: string;
}

class UAEMCPTool {
  async execute(request: ToolRequest): Promise<ToolResult> {
    // Stage 1: Draft/Preview
    if (!request.confirmation) {
      const preview = await this.generatePreview(request);
      return {
        status: 'preview',
        preview,
        confirmationRequired: true,
        confirmationToken: this.generateToken(),
      };
    }
    
    // Stage 2: Execute with confirmation
    if (!this.verifyConfirmation(request.confirmation)) {
      throw new Error('Invalid confirmation');
    }
    
    // Create snapshot for rollback
    const snapshot = await this.createSnapshot();
    
    try {
      const result = await this.executeAction(request);
      return {
        status: 'success',
        result,
        rollbackToken: snapshot.id,
      };
    } catch (error) {
      // Auto-rollback on failure
      await this.rollback(snapshot);
      throw error;
    }
  }
  
  private generateToken(): string {
    return crypto.randomUUID();
  }
  
  private verifyConfirmation(token: string): boolean {
    // Verify against stored token
    return this.pendingConfirmations.has(token);
  }
}
```

---

## الإنسان في الحلقة — Human-in-the-Loop

**العربية:**
- نفذ موجهات تأكيد للعمليات الخطرة في خادم MCP.
- استخدم الاستعلام على جانب خادم MCP لطلب تأكيد المستخدم للإجراءات الخطرة.
- رسائل الأمان ذات الصلة **يجب** أن تشير بوضوح إلى الآثار المترتبة.
- **لا** تعتمد فقط على الموافقة البشرية (يمكن للمستخدمين أن يتعبوا).

**English:**
- Implement confirmation prompts for risky operations in your MCP server.
- Use elicitation on MCP server side to request user confirmation of risky actions.
- Security-relevant messages MUST clearly indicate implications.
- Do NOT rely solely on human approval (users can become fatigued).

---

## التسجيل والمراقبة — Logging and Observability

**العربية:**
- نفذ التسجيل في خوادم وعملاء MCP.
- سجل: الأدوات التي تم استخدامها، المعاملات، الموجه الأصلي.
- استخدم OpenTelemetry لقابلية الربط الشاملة للإجراءات.
- حافظ على سجلات غير قابلة للتغيير للإجراءات والتفويضات.

**English:**
- Implement logging in your MCP servers and clients.
- Log: tools that were used, parameters, originating prompt.
- Use OpenTelemetry for end-to-end linkability of actions.
- Maintain immutable records of actions and authorizations.

```python
# Python MCP Logging with OpenTelemetry
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
import structlog

# Configure OpenTelemetry
trace.set_tracer_provider(TracerProvider())
tracer = trace.get_tracer("mcp-server")

# Configure structlog
structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer()
    ]
)
logger = structlog.get_logger()

class UAE MCPLogger:
    """
    Secure MCP logging for UAE compliance
    """
    
    @staticmethod
    def log_tool_execution(
        tool_name: str,
        parameters: Dict[str, Any],
        prompt: str,
        user_id: str
    ):
        """Log tool execution with full context"""
        with tracer.start_as_current_span("tool_execution") as span:
            span.set_attribute("tool.name", tool_name)
            span.set_attribute("user.id", user_id)
            span.set_attribute("prompt.hash", hashlib.sha256(prompt.encode()).hexdigest())
            
            logger.info(
                "tool_executed",
                tool=tool_name,
                parameters=parameters,
                user_id=user_id,
                timestamp=datetime.utcnow().isoformat(),
            )
    
    @staticmethod
    def log_authorization(
        user_id: str,
        action: str,
        authorized: bool,
        reason: str
    ):
        """Log authorization decisions"""
        logger.info(
            "authorization_decision",
            user_id=user_id,
            action=action,
            authorized=authorized,
            reason=reason,
        )
```

---

## أنماط النشر الآمنة — Deployment Pattern Security

### كل شيء محلي (stdio أو http)

**العربية:**
- الأمان يعتمد كلياً على وضع نظام المضيف.
- استخدم نقل `stdio` لتجنب مخاطر DNS rebinding.
- استخدم العزل للحد من هجمات تصعيد الامتيازات.
- مناسب للتطوير والاستخدام الشخصي.

**English:**
- Security depends entirely on host system posture.
- Use `stdio` transport to avoid DNS rebinding risks.
- Use sandboxing to limit privilege escalation attacks.
- Appropriate for development and personal use.

### مستأجر واحد بعيد (http)

**العربية:**
- المصادقة بين العميل والخادم **مطلوبة**.
- استخدم تخزين اعتمادات آمن (سلاسل مفاتيح OS، مديرو الأسرار).
- التواصل **يجب** أن يكون مصادقاً ومشفراً.
- عملاء المؤسسات يجب أن يفرضوا اكتشاف خادم مصادق مع قوائم سماح صريحة.

**English:**
- Authentication between client and server is REQUIRED.
- Use secure credential storage (OS keychains, secret managers).
- Communication MUST be authenticated and encrypted.
- Enterprise clients should enforce authenticated server discovery with explicit allowlists.

### متعدد المستأجرين بعيد (http)

**العربية:**
- اشترط عزل قوي للمستأجرين، وهوية، وتحكم بالوصول.
- نفذ ضوابط متعددة المستأجرين قوية (تشفير لكل مستأجر، تحكم بالوصول المبني على الأدوار).
- فضّل خوادم MCP مستضافة مباشرة من مزود الخدمة.
- قدم تصديقاً بعيداً عندما يكون ممكناً.

**English:**
- Require robust tenant isolation, identity, and access control.
- Implement strong multi-tenancy controls (per-tenant encryption, role-based access control).
- Prefer MCP servers hosted directly by service provider.
- Provide remote attestation when possible.

---

## قائمة التحقق — Implementation Checklist

- [ ] هويات SPIFFE/SPIRE مكونة
- [ ] قوائم سماح للمدخلات عند كل حدود الثقة
- [ ] تطهير مسارات الملفات
- [ ] استعلامات معاملات لقواعد البيانات
- [ ] ترميز مخرجات مدرك للسياق
- [ ] مخرجات الأدوات مُطهَّرة (PII مكتوب)
- [ ] كشف حقن الموجهات منشور
- [ ] مخططات JSON صارمة
- [ ] خوادم MCP تعمل بأقل الامتيازات
- [ ] عزل مفعل (gVisor/Kata/SELinux)
- [ ] توقيعات تشفيرية وSBOMs
- [ ] التحقق من التوقيعات قبل التحميل
- [ ] TLS لجميع البيانات أثناء النقل
- [ ] حدود حمولة
- [ ] تحديد المعدل
- [ ] مصادقة متبادلة TLS
- [ ] حماية CORS
- [ ] حماية CSRF
- [ ] فحوصات نزاهة
- [ ] أدوات ذات غرض واحد
- [ ] التزام ثنائي المرحلة للإجراءات عالية التأثير
- [ ] مسارات تراجع/تراجع
- [ ] موجهات تأكيد للعمليات الخطرة
- [ ] تسجيل شامل مع OpenTelemetry
- [ ] سجلات غير قابلة للتغيير

---

## مراجع — References

- [CoSAI MCP Security Guidelines](https://github.com/cosai-oasis/project-mcp-security)
- [SPIFFE/SPIRE Documentation](https://spiffe.io/)
- [gVisor Documentation](https://gvisor.dev/)
- [OpenTelemetry](https://opentelemetry.io/)
- [OWASP MCP Security](https://owasp.org/www-project-mcp-security/)
- [UAE Information Assurance Framework](https://www.tra.gov.ae/)
