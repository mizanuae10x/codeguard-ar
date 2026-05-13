---
description: DevOps، CI/CD، والحاويات (تصليب خط الأنابيب، المكونات، صور Docker/K8s، الترقيع الافتراضي، سلسلة الأدوات)
languages:
- docker
- javascript
- powershell
- shell
- xml
- yaml
tags:
- infrastructure
- devops
- containers
- uae
alwaysApply: false
---

# DevOps، CI/CD، والحاويات — DevOps, CI/CD, and Containers

## نظرة عامة — Overview

أمن سلسلة البناء والتعبئة والنشر: حماية خطوط الأنابيب والمكونات، تصليب الحاويات، واستخدام الترقيع الافتراضي وأعلام سلسلة الأدوات عند الضرورة.

Secure the build, packaging, and deployment supply chain: protect pipelines and artifacts, harden containers, and use virtual patching and toolchain flags when necessary.

---

## أمان خط الأنابيب CI/CD — CI/CD Pipeline Security

**العربية:**
- المستودعات: فروع محمية؛ مراجعات إلزامية؛ التزامات موقعة.
- الأسرار: لا تُضمن مطلقاً؛ جلبها في وقت التشغيل من خزنة/KMS؛ إخفاؤها في السجلات.
- أقل امتياز: عدائين مؤقتين معزولين بأقل أذونات.
- بوابات أمان في CI: SAST، SCA، DAST، فحص IaC؛ الحظر عند الحرج.
- التبعيات: تثبيت عبر ملفات القفل؛ التحقق من النزاهة؛ استخدام السجلات الخاصة.
- وقع كل شيء: الالتزامات والمكونات (حاويات/jars) والتحقق قبل النشر؛ اعتماد مصدر SLSA.

**English:**
- Repos: protected branches; mandatory reviews; signed commits.
- Secrets: never hardcode; fetch at runtime from vault/KMS; mask in logs.
- Least privilege: ephemeral, isolated runners with minimal permissions.
- Security gates in CI: SAST, SCA, DAST, IaC scanning; block on criticals.
- Dependencies: pin via lockfiles; verify integrity; use private registries.
- Sign everything: commits and artifacts; verify prior to deploy; adopt SLSA provenance.

```yaml
# GitHub Actions CI/CD Pipeline for UAE
name: UAE Secure CI/CD

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

env:
  REGISTRY: uae.gov.ae
  IMAGE_NAME: uae-app

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      # Secret scanning
      - name: Secret Detection
        uses: trufflesecurity/trufflehog@main
        with:
          path: ./
          base: main
          head: HEAD

      # SAST
      - name: Static Analysis
        uses: returntocorp/semgrep-action@v1
        with:
          config: >-
            p/security-audit
            p/owasp-top-ten
            p/cwe-top-25

      # Dependency scanning
      - name: Dependency Check
        uses: snyk/actions/node@master
        with:
          args: --severity-threshold=high
        env:
          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}

      # IaC scanning
      - name: IaC Security
        uses: checkmarx/kics-github-action@v1
        with:
          path: terraform/
          fail_on: high,medium

  build:
    needs: security-scan
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write
      id-token: write
    steps:
      - uses: actions/checkout@v4

      # Build with BuildKit
      - name: Build Image
        uses: docker/build-push-action@v5
        with:
          context: .
          push: false
          tags: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.sha }}
          cache-from: type=gha
          cache-to: type=gha,mode=max
          secrets: |
            "npm_token=${{ secrets.NPM_TOKEN }}"

      # Sign image with Cosign
      - name: Sign Image
        uses: sigstore/cosign-installer@v3
      - run: |
          cosign sign --yes \
            ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.sha }}

  deploy:
    needs: build
    runs-on: ubuntu-latest
    environment: production
    steps:
      - name: Verify Image Signature
        run: |
          cosign verify \
            --certificate-identity-regexp="^https://github.com/${{ github.repository }}" \
            --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
            ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.sha }}

      - name: Deploy to Kubernetes
        run: |
          kubectl set image deployment/uae-app \
            app=${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.sha }}
```

---

## تصليب Docker والحاويات — Docker and Container Hardening

**العربية:**
- المستخدم: تشغيل غير جذري؛ ضبط `USER` في Dockerfile.
- استخدم `--security-opt=no-new-privileges` لمنع تصعيد الامتيازات.
- القدرات: `--cap-drop all` وأضف فقط ما تحتاجه؛ لا `--privileged` أبداً.
- مأخذ البرنامج الخفي: لا تركب `/var/run/docker.sock` أبداً.
- لا تُمكّن مأخذ TCP للبرنامج الخفي بدون TLS.
- أنظمة الملفات: جذر للقراءة فقط، tmpfs للكتابة المؤقتة؛ حدود الموارد (CPU/ذاكرة).
- الشبكات: تجنب شبكة المضيف؛ عرّف شبكات مخصصة؛ قصر المنافذ المكشوفة.
- الصور: قاعدة دنيا (distroless/alpine)، ثبّت الوسوم والمُلخَّصات؛ أزل مديري الحزم والأدوات من الصورة النهائية؛ أضف `HEALTHCHECK`.
- الأسرار: أسرار Docker/Kubernetes؛ لا في الطبقات/البيئة؛ ركّب عبر أسرار وقت التشغيل.
- الفحص: افحص الصور عند البناء والقبول؛ احجب الثغرات عالية الخطورة.

**English:**
- User: run as non-root; set `USER` in Dockerfile.
- Use `--security-opt=no-new-privileges`.
- Capabilities: `--cap-drop all` and add only what you need; never `--privileged`.
- Daemon socket: never mount `/var/run/docker.sock`.
- DO NOT enable TCP Docker daemon socket without TLS.
- Filesystems: read-only root, tmpfs for temp write; resource limits.
- Networks: avoid host network; define custom networks; limit exposed ports.
- Images: minimal base (distroless/alpine), pin tags and digests; remove package managers; add `HEALTHCHECK`.
- Secrets: never in layers/env; mount via runtime secrets.
- Scanning: scan images on build and admission; block high-severity vulns.

```dockerfile
# Multi-stage Dockerfile for UAE Application
# Build stage
FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev --ignore-scripts
COPY . .
RUN npm run build

# Production stage - minimal image
FROM gcr.io/distroless/nodejs20-debian11

# Non-root user
USER nonroot:nonroot

# Set working directory
WORKDIR /app

# Copy only necessary files
COPY --from=builder --chown=nonroot:nonroot /app/dist ./dist
COPY --from=builder --chown=nonroot:nonroot /app/node_modules ./node_modules
COPY --from=builder --chown=nonroot:nonroot /app/package.json ./

# Read-only filesystem
# tmpfs mounted at /tmp for temporary writes

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD ["/nodejs/bin/node", "-e", "require('http').get('http://localhost:8080/health', (r) => r.statusCode === 200 ? process.exit(0) : process.exit(1))"]

# Expose port
EXPOSE 8080

# Run application
CMD ["dist/main.js"]
```

```yaml
# Kubernetes Deployment with Security Context
apiVersion: apps/v1
kind: Deployment
metadata:
  name: uae-app
  namespace: uae-production
spec:
  replicas: 3
  selector:
    matchLabels:
      app: uae-app
  template:
    metadata:
      labels:
        app: uae-app
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 65534  # nobody
        runAsGroup: 65534
        fsGroup: 65534
        seccompProfile:
          type: RuntimeDefault
      containers:
      - name: app
        image: uae.gov.ae/uae-app:v1.0.0
        imagePullPolicy: Always
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop:
            - ALL
        resources:
          limits:
            cpu: "500m"
            memory: "512Mi"
          requests:
            cpu: "100m"
            memory: "128Mi"
        ports:
        - containerPort: 8080
        volumeMounts:
        - name: tmp
          mountPath: /tmp
        - name: cache
          mountPath: /cache
      volumes:
      - name: tmp
        emptyDir: {}
      - name: cache
        emptyDir:
          sizeLimit: 100Mi
```

---

## Node.js في الحاويات — Node.js in Containers

**العربية:**
- بناءات حتمية: `npm ci --omit=dev`؛ ثبّت الصورة الأساسية بالمُلخَّص.
- بيئة الإنتاج: `ENV NODE_ENV=production`.
- غير جذري: انسخ مع ملكية صحيحة وانتقل إلى `USER node`.
- الإشارات: استخدم init (مثل `dumb-init`) ونفّذ معالجات إيقاف أنيقة.
- بناء متعدد المراحل: افصل البناء ووقت التشغيل؛ ركّب الأسرار عبر BuildKit؛ استخدم `.dockerignore`.

**English:**
- Deterministic builds: `npm ci --omit=dev`; pin base image with digest.
- Production env: `ENV NODE_ENV=production`.
- Non-root: copy with correct ownership and drop to `USER node`.
- Signals: use an init (e.g., `dumb-init`) and implement graceful shutdown handlers.
- Multi-stage builds: separate build and runtime; mount secrets via BuildKit; use `.dockerignore`.

```dockerfile
# Node.js Dockerfile with Best Practices
FROM node:20-alpine@sha256:abc123... AS builder

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies (production only)
RUN npm ci --omit=dev --ignore-scripts

# Copy source
COPY . .

# Build application
RUN npm run build

# Production stage
FROM node:20-alpine@sha256:abc123...

# Install dumb-init for signal handling
RUN apk add --no-cache dumb-init

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001

WORKDIR /app

# Copy built application
COPY --from=builder --chown=nodejs:nodejs /app/dist ./dist
COPY --from=builder --chown=nodejs:nodejs /app/node_modules ./node_modules
COPY --from=builder --chown=nodejs:nodejs /app/package.json ./

# Set environment
ENV NODE_ENV=production
ENV PORT=8080

# Switch to non-root user
USER nodejs

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s \
  CMD node -e "require('http').get('http://localhost:8080/health', (r) => process.exit(r.statusCode === 200 ? 0 : 1))"

# Use dumb-init for proper signal handling
ENTRYPOINT ["dumb-init", "--"]
CMD ["node", "dist/main.js"]
```

---

## الترقيع الافتراضي (تخفيف مؤقت) — Virtual Patching

**العربية:**
- استخدم WAF/IPS/ModSecurity للحماية الفورية عندما لا تكون إصلاحات الكود ممكنة بعد.
- فضّل قواعد الأمان الإيجابية (قائمة السماح) للدقة؛ تجنب التوقيعات الخاصة بالاستغلال.
- العملية: حضّر الأدوات مسبقاً؛ حلّل CVEs؛ نفّذ الترقيعات في وضع السجل أولاً، ثم فرضها؛ تتبع وإحلال بعد إصلاح الكود.

**English:**
- Use WAF/IPS/ModSecurity for immediate protection when code fixes are not yet possible.
- Prefer positive security rules (allow-list) for accuracy; avoid exploit-specific signatures.
- Process: prepare tooling in advance; analyze CVEs; implement patches in log-only first, then enforce; track and retire after code fix.

```yaml
# ModSecurity Virtual Patching Example
SecRuleEngine DetectionOnly  # Start in log-only mode

# Virtual patch for CVE-2024-XXXXX
SecRule REQUEST_URI|ARGS "@rx (?i)union\s+select" \
    "id:1001,\
    phase:2,\
    deny,\
    status:403,\
    msg:'Virtual Patch: SQL Injection Attempt',\
    logdata:'Matched Data: %{MATCHED_VAR} found within %{MATCHED_VAR_NAME}',\
    tag:'virtual-patch',\
    tag:'CVE-2024-XXXXX'"

# Transition to enforcement after validation
# SecRuleEngine On
```

---

## تصليب سلسلة أدوات C/C++ — C/C++ Toolchain Hardening

**العربية:**
- المترجم: `-Wall -Wextra -Wconversion`، `-fstack-protector-all`، PIE (`-fPIE`/`-pie`)، `_FORTIFY_SOURCE=2`، CFI (`-fsanitize=cfi` مع LTO).
- الرابط: RELRO/now، noexecstack، NX/DEP و ASLR.
- تصحيح الأخطاء مقابل الإصدار: فعّل المطهرات في التصحيح؛ فعّل أعلام التصليب في الإصدار؛ assert في التصحيح فقط.
- فحوصات CI: تحقق من الأعلام (`checksec`) وأفشل البناء إذا كانت الحمايات مفقودة.

**English:**
- Compiler: `-Wall -Wextra -Wconversion`, `-fstack-protector-all`, PIE, `_FORTIFY_SOURCE=2`, CFI.
- Linker: RELRO/now, noexecstack, NX/DEP and ASLR.
- Debug vs Release: enable sanitizers in debug; enable hardening flags in release; assert in debug only.
- CI checks: verify flags (`checksec`) and fail builds if protections missing.

```makefile
# Makefile with Security Hardening
CC = gcc
CFLAGS = -Wall -Wextra -Wconversion -O2 \
         -fstack-protector-all \
         -fPIE -pie \
         -D_FORTIFY_SOURCE=2 \
         -Wformat -Wformat-security

LDFLAGS = -Wl,-z,relro,-z,now \
          -Wl,-z,noexecstack

# Debug build with sanitizers
debug: CFLAGS += -g -O0 -fsanitize=address,undefined
debug: LDFLAGS += -fsanitize=address,undefined
debug: app

# Release build with hardening
release: CFLAGS += -DNDEBUG
release: app

app: main.o
	$(CC) $(LDFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

# Verify security features
check:
	checksec --file=./app
```

---

## قائمة التحقق — Implementation Checklist

- [ ] خط الأنابيب: الأسرار في الخزنة؛ عدائين مؤقتين؛ فحوصات أمان؛ مكونات موقعة مع مصدر.
- [ ] الحاويات: غير جذري، أقل امتياز، نظام ملفات للقراءة فقط، حدود الموارد؛ لا تركيب لمأخذ البرنامج الخفي.
- [ ] الصور: دنيا، مثبتة، مفحوصة؛ فحوصات صحية؛ `.dockerignore` محافظ عليه.
- [ ] صور Node: `npm ci`، `NODE_ENV=production`، init مناسب وإيقاف.
- [ ] الترقيع الافتراضي: عملية محددة؛ قواعد دقيقة؛ سجلات؛ إحلال بعد الإصلاح.
- [ ] البناء الأصلي: أعلام التصليب مُفعلة ومُتحقَّة في CI.

---

## مراجع — References

- [OWASP CI/CD Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/CI_CD_Security_Cheat_Sheet.html)
- [Docker Security Best Practices](https://docs.docker.com/develop/security-best-practices/)
- [SLSA Framework](https://slsa.dev/)
- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker)
- [UAE DESC Cloud Security Standard](https://desc.gov.ae/)
