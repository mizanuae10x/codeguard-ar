---
description: تصليب Kubernetes (RBAC، سياسات القبول، سياسات الشبكة، الأسرار، سلسلة التوريد)
languages:
- javascript
- yaml
- python
- bash
tags:
- infrastructure
- kubernetes
- uae
alwaysApply: false
---

# السحابة والتنسيق (Kubernetes) — Cloud & Orchestration

## نظرة عامة — Overview

تصليب مجموعة Kubernetes وأعباء العمل: الهوية، السياسة، الشبكة، الأسرار، وضوابط سلسلة التوريد.

Kubernetes cluster and workload hardening: identity, policy, networking, secrets, and supply chain controls.

---

## الضوابط — Controls

### الهوية و RBAC — Identity & RBAC

**العربية:**
- أقل امتياز للمستخدمين وحسابات الخدمة
- مساحات أسماء منفصلة
- اربط فقط الأدوار المطلوبة
- لا تستخدم حسابات المسؤول الافتراضية

**English:**
- Least privilege for users and service accounts
- Separate namespaces
- Bind only needed roles
- Do not use default admin accounts

```yaml
# Kubernetes RBAC for UAE Government
apiVersion: v1
kind: Namespace
metadata:
  name: uae-production
  labels:
    environment: production
    compliance: desc
    data-classification: confidential
---
# Service Account with minimal permissions
apiVersion: v1
kind: ServiceAccount
metadata:
  name: uae-app-sa
  namespace: uae-production
automountServiceAccountToken: false  # Disable auto-mount
---
# Role with specific permissions
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: uae-app-role
  namespace: uae-production
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list", "watch"]
- apiGroups: [""]
  resources: ["configmaps"]
  verbs: ["get"]
  resourceNames: ["app-config"]
---
# RoleBinding
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: uae-app-binding
  namespace: uae-production
subjects:
- kind: ServiceAccount
  name: uae-app-sa
  namespace: uae-production
roleRef:
  kind: Role
  name: uae-app-role
  apiGroup: rbac.authorization.k8s.io
```

---

### السياسة — Policy

**العربية:**
- ضوابط قبول (OPA/Gatekeeper/Kyverno)
- مصادر الصور، القدرات، الجذر، سياسات الشبكة
- تسميات/تعليقات مطلوبة

**English:**
- Admission controls (OPA/Gatekeeper/Kyverno)
- Image sources, capabilities, root, network policies
- Required labels/annotations

```yaml
# Kyverno Policy for UAE Compliance
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: uae-security-policy
spec:
  validationFailureAction: enforce
  background: true
  rules:
  # Require non-root containers
  - name: require-non-root
    match:
      resources:
        kinds:
        - Pod
    validate:
      message: "Containers must run as non-root"
      pattern:
        spec:
          securityContext:
            runAsNonRoot: true
          containers:
          - securityContext:
              allowPrivilegeEscalation: false
              readOnlyRootFilesystem: true
              capabilities:
                drop:
                - ALL
  # Require resource limits
  - name: require-resource-limits
    match:
      resources:
        kinds:
        - Pod
    validate:
      message: "Containers must have resource limits"
      pattern:
        spec:
          containers:
          - resources:
              limits:
                memory: "?*"
                cpu: "?*"
  # Require UAE labels
  - name: require-uae-labels
    match:
      resources:
        kinds:
        - Pod
    validate:
      message: "UAE compliance labels are required"
      pattern:
        metadata:
          labels:
            app.kubernetes.io/name: "?*"
            compliance.uae.gov.ae/classification: "?*"
            compliance.uae.gov.ae/owner: "?*"
```

---

### الشبكة — Networking

**العربية:**
- الرفض افتراضياً مع سياسات الشبكة
- قوائم سماح صريحة للإخراج
- هوية الخدمة/mTLS داخل الشبكة

**English:**
- Default-deny with network policies
- Explicit egress allow-lists
- Service identity/mTLS within mesh

```yaml
# Kubernetes Network Policy (Default Deny)
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: uae-production
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
---
# Allow specific ingress
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-ingress
  namespace: uae-production
spec:
  podSelector:
    matchLabels:
      app: uae-api
  policyTypes:
  - Ingress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: ingress-nginx
    ports:
    - protocol: TCP
      port: 8080
  - from:
    - podSelector:
        matchLabels:
          app: uae-monitoring
    ports:
    - protocol: TCP
      port: 9090
---
# Allow specific egress
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-egress
  namespace: uae-production
spec:
  podSelector:
    matchLabels:
      app: uae-api
  policyTypes:
  - Egress
  egress:
  - to:
    - podSelector:
        matchLabels:
          app: uae-database
    ports:
    - protocol: TCP
      port: 5432
  - to:
    - namespaceSelector:
        matchLabels:
          name: kube-system
      podSelector:
        matchLabels:
          k8s-app: kube-dns
    ports:
    - protocol: UDP
      port: 53
  - to:
    - ipBlock:
        cidr: 10.0.0.0/8  # Internal only
    ports:
    - protocol: TCP
      port: 443
```

---

### الأسرار — Secrets

**العربية:**
- استخدم موفري KMS
- تجنب النص الصريح في manifests
- تدوير بانتظام
- قصر مسارات تركيب السر

**English:**
- Use KMS providers
- Avoid plaintext in manifests
- Rotate regularly
- Restrict secret mount paths

```yaml
# Kubernetes Secret with External Secrets Operator
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: uae-db-credentials
  namespace: uae-production
spec:
  refreshInterval: 1h
  secretStoreRef:
    kind: ClusterSecretStore
    name: azure-keyvault
  target:
    name: uae-db-credentials
    creationPolicy: Owner
    template:
      type: Opaque
      data:
        username: "{{ .username }}"
        password: "{{ .password }}"
        host: "{{ .host }}"
  data:
  - secretKey: username
    remoteRef:
      key: uae-db-username
  - secretKey: password
    remoteRef:
      key: uae-db-password
  - secretKey: host
    remoteRef:
      key: uae-db-host
---
# Pod using secret
apiVersion: v1
kind: Pod
metadata:
  name: uae-app
  namespace: uae-production
spec:
  containers:
  - name: app
    image: uae.gov.ae/app:v1.0.0
    env:
    - name: DB_USERNAME
      valueFrom:
        secretKeyRef:
          name: uae-db-credentials
          key: username
    - name: DB_PASSWORD
      valueFrom:
        secretKeyRef:
          name: uae-db-credentials
          key: password
    volumeMounts:
    - name: secrets
      mountPath: /etc/secrets
      readOnly: true
  volumes:
  - name: secrets
    csi:
      driver: secrets-store.csi.k8s.io
      readOnly: true
      volumeAttributes:
        secretProviderClass: uae-secrets
```

---

### العقد — Nodes

**العربية:**
- نظام تشغيل مُصلَّب
- تحديثات تلقائية
- سطح هجومي أدنى
- عزل أعباء العمل الحساسة

**English:**
- Hardened OS
- Auto-updates
- Minimal attack surface
- Isolate sensitive workloads

```yaml
# Node Hardening with Kube-bench
apiVersion: v1
kind: ConfigMap
metadata:
  name: kube-bench-config
  namespace: kube-system
data:
  config.yaml: |
    ---
    node:
      files:
      - path: /etc/kubernetes/kubelet.conf
        permissions: "0644"
      - path: /etc/kubernetes/pki/ca.crt
        permissions: "0644"
      - path: /var/lib/kubelet/config.yaml
        permissions: "0644"
    ---
# Pod Security Standard
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: uae-restricted
spec:
  privileged: false
  allowPrivilegeEscalation: false
  requiredDropCapabilities:
    - ALL
  volumes:
    - 'configMap'
    - 'emptyDir'
    - 'projected'
    - 'secret'
    - 'downwardAPI'
    - 'persistentVolumeClaim'
  runAsUser:
    rule: 'MustRunAsNonRoot'
  seLinux:
    rule: 'RunAsAny'
  fsGroup:
    rule: 'RunAsAny'
```

---

### سلسلة التوريد — Supply Chain

**العربية:**
- تحقق من توقيعات الصور
- فرض مصدر (SLSA/Sigstore) في القبول
- مسح الصور للثغرات

**English:**
- Verify image signatures
- Enforce provenance (SLSA/Sigstore) in admission
- Scan images for vulnerabilities

```yaml
# Cosign Image Verification
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sVerifiedImage
metadata:
  name: verify-uae-images
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
    namespaces: ["uae-production"]
  parameters:
    allowed_registries:
      - "uae.gov.ae"
      - "registry.uae.gov.ae"
    required_signatures:
      - keyless:
          issuer: "https://accounts.uae.gov.ae"
          subject: "*.uae.gov.ae"
---
# Image Scanning with Trivy
apiVersion: batch/v1
kind: CronJob
metadata:
  name: image-scan
  namespace: uae-security
spec:
  schedule: "0 2 * * *"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: trivy
            image: aquasec/trivy:latest
            command:
            - trivy
            - image
            - --severity
            - HIGH,CRITICAL
            - --exit-code
            - "1"
            - uae.gov.ae/app:v1.0.0
          restartPolicy: OnFailure
```

---

## قائمة التحقق — Checklist

- [ ] مساحات أسماء لكل فريق/تطبيق
- [ ] أدوار RBAC ذات نطاق
- [ ] تسجيل المراجعة مُمكّن
- [ ] سياسات القبول تفرض مصدر الصورة
- [ ] تشغيل غير جذري
- [ ] إسقاط القدرات
- [ ] نظام ملفات الجذر للقراءة فقط
- [ ] وجود سياسة الشبكة
- [ ] سياسات الشبكة للدخول/الخروج
- [ ] حسابات الخدمة ذات نطاق لكل نشر
- [ ] توقيعات الصور مُتحقَّقة
- [ ] الأسرار في KMS
- [ ] العقد مُصلَّبة
- [ ] اختبار النسخ الاحتياطي والاسترداد

---

## التحقق — Verification

- [ ] فحوصات مطابقة المجموعة ومعايير CIS
- [ ] اختبارات السياسة في CI
- [ ] اختبارات القبول الجافة الدورية
- [ ] مسح الثغرات للصور
- [ ] مراجعة RBAC

---

## الاستعداد للحوادث — Incident Readiness

**العربية:**
- فعّل سجلات المراجعة ومركزها
- قصر الوصول إلى etcd
- اختبر النسخ الاحتياطي والاسترداد
- عرّف أدوار الطوارئ مع MFA وموافقات محدودة الوقت

**English:**
- Enable audit logs and centralize
- Restrict access to etcd
- Backup/restore tested
- Define break-glass roles with MFA and time-bound approvals

```yaml
# Audit Logging
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
- level: RequestResponse
  resources:
  - group: ""
    resources: ["pods", "secrets", "configmaps"]
- level: Metadata
  resources:
  - group: "rbac.authorization.k8s.io"
    resources: ["roles", "rolebindings"]
- level: Request
  verbs: ["create", "update", "delete"]
  resources:
  - group: ""
    resources: ["services", "deployments"]
```

---

## مراجع — References

- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)
- [NIST SP 800-190 - Container Security](https://csrc.nist.gov/publications/detail/sp/800-190/final)
- [Kubernetes Security Best Practices](https://kubernetes.io/docs/concepts/security/)
- [UAE DESC Cloud Security Standard](https://desc.gov.ae/)
