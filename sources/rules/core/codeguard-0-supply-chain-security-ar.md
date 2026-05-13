---
description: أمان التبعيات وسلسلة التوريد (التثبيت، SBOM، المصدر، النزاهة، السجلات الخاصة)
languages:
- docker
- javascript
- yaml
- python
- bash
tags:
- supply-chain
- dependencies
- uae
alwaysApply: false
---

# أمان التبعيات وسلسلة التوريد — Dependency & Supply Chain Security

## نظرة عامة — Overview

تحكم في مخاطر الطرف الثالث عبر الأنظمة البيئية، من الاختيار والتثبيت إلى المصدر والفحص والاستجابة السريعة.

Control third-party risk across ecosystems, from selection and pinning to provenance, scanning, and rapid response.

---

## السياسة والحوكمة — Policy and Governance

**العربية:**
- حافظ على سجلات ونطاقات مدرجة في قائمة السماح؛ امنع التثبيت المباشر من مصادر غير موثوقة.
- اشترط ملفات القفل وتثبيت الإصدار؛ فضّل تثبيت المُلخَّص للصور والأصول المُضمَّنة.
- أنشئ SBOMs للتطبيقات/الصور؛ خزنها مع المكونات؛ صدِّق على المصدر (SLSA، Sigstore).

**English:**
- Maintain allow-listed registries and scopes; disallow direct installs from untrusted sources.
- Require lockfiles and version pinning; prefer digest pinning for images and vendored assets.
- Generate SBOMs for apps/images; store with artifacts; attest provenance (SLSA, Sigstore).

```yaml
# .npmrc - npm Configuration for UAE
registry=https://registry.uae.gov.ae/npm
@uae:registry=https://registry.uae.gov.ae/npm

# Enable integrity verification
package-lock=true
save-exact=true

# Disable scripts on install (security)
ignore-scripts=true

# Audit settings
audit-level=moderate

# Private registry authentication
//registry.uae.gov.ae/npm/:_authToken=${NPM_TOKEN}
```

---

## نظافة الحزم — Package Hygiene

**العربية:**
- فحص وإصلاح بانتظام (`npm audit`، SCA للنظام البيئي)؛ فرض اتفاقيات مستوى الخدمة حسب الخطورة.
- استخدم بناءات حتمية: `npm ci` (ليس `npm install`) في CI/CD؛ حافظ على تناسق ملف القفل.
- تجنب سكربتات التثبيت التي تنفذ عند التثبيت عندما يكون ممكناً؛ راجع المخاطر.
- استخدم `.npmrc` لتحديد نطاق السجلات الخاصة؛ تجنب السجلات البدلية؛ فعّل التحقق من النزاهة.
- فعّل 2FA للحساب للنشر.

**English:**
- Regularly audit (`npm audit`, ecosystem SCA) and patch; enforce SLAs by severity.
- Use deterministic builds: `npm ci` (not `npm install`) in CI/CD; maintain lockfile consistency.
- Avoid install scripts that execute on install when possible; review for risk.
- Use `.npmrc` to scope private registries; avoid wildcard registries; enable integrity verification.
- Enable account 2FA for publishing.

```bash
#!/bin/bash
# UAE Dependency Audit Script

# Run npm audit
npm audit --audit-level=moderate

# If critical vulnerabilities found, fail the build
if [ $? -ne 0 ]; then
    echo "Critical vulnerabilities found. Blocking build."
    exit 1
fi

# Check for outdated packages
npm outdated

# Generate SBOM
cyclonedx-npm --output-file sbom.json

# Verify signatures
npm audit signatures
```

---

## ممارسات التطوير — Development Practices

**العربية:**
- قلل من بصمة التبعية؛ أزل الحزم غير المستخدمة؛ فضّل stdlib/الطرف الأول للمهام البسيطة.
- احمِ ضد typosquatting وprotestware: ثبّت المشرفين، راقب الإصدارات، واستخدم فحوصات المصدر.
- بناءات محكمة: لا شبكة في مراحل الترجمة/التعبئة ما لم يكن مطلوباً؛ خزن مؤقتاً مع فحوصات أصالة.

**English:**
- Minimize dependency footprint; remove unused packages; prefer stdlib/first-party for trivial tasks.
- Protect against typosquatting and protestware: pin maintainers, monitor releases, and use provenance checks.
- Hermetic builds: no network in compile/packaging stages unless required; cache with authenticity checks.

```python
# Python Dependency Checker
import json
import subprocess
from typing import List, Dict

class UAEDependencyChecker:
    """
    Check dependencies for UAE compliance
    """
    
    ALLOWED_REGISTRIES = [
        "https://pypi.uae.gov.ae",
        "https://pypi.org",
    ]
    
    BLOCKED_PACKAGES = [
        "malicious-package",
        "typosquat-example",
    ]
    
    @classmethod
    def check_dependencies(cls, requirements_file: str) -> List[Dict]:
        """Check dependencies for issues"""
        issues = []
        
        # Parse requirements
        with open(requirements_file, 'r') as f:
            requirements = f.readlines()
        
        for req in requirements:
            req = req.strip()
            if not req or req.startswith('#'):
                continue
            
            # Check for blocked packages
            package_name = req.split('==')[0].split('>=')[0].strip()
            if package_name in cls.BLOCKED_PACKAGES:
                issues.append({
                    'package': package_name,
                    'issue': 'BLOCKED_PACKAGE',
                    'severity': 'CRITICAL'
                })
            
            # Check for version pinning
            if '==' not in req and '>=' not in req:
                issues.append({
                    'package': package_name,
                    'issue': 'UNPINNED_VERSION',
                    'severity': 'WARNING'
                })
        
        return issues
    
    @classmethod
    def generate_sbom(cls, project_path: str) -> Dict:
        """Generate Software Bill of Materials"""
        result = subprocess.run(
            ['pip', 'list', '--format=json'],
            capture_output=True,
            text=True,
            cwd=project_path
        )
        
        packages = json.loads(result.stdout)
        
        sbom = {
            'bomFormat': 'CycloneDX',
            'specVersion': '1.4',
            'components': []
        }
        
        for pkg in packages:
            sbom['components'].append({
                'type': 'library',
                'name': pkg['name'],
                'version': pkg['version'],
                'purl': f"pkg:pypi/{pkg['name']}@{pkg['version']}"
            })
        
        return sbom
```

---

## التكامل مع CI/CD — CI/CD Integration

**العربية:**
- فحوصات SCA، SAST، IaC في البوابات؛ الفشل عند الحرج؛ اشترط موافقات للتجاوز مع ضوابط تعويضية.
- وقع المكونات؛ تحقق من التوقيعات عند النشر؛ فرض السياسة في القبول.

**English:**
- SCA, SAST, IaC scans in gates; fail on criticals; require approvals for overrides with compensating controls.
- Sign artifacts; verify signatures at deploy; enforce policy in admission.

```yaml
# GitHub Actions Supply Chain Security
name: Supply Chain Security

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  dependency-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      # Setup Node.js
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'npm'
      
      # Install dependencies (deterministic)
      - run: npm ci --ignore-scripts
      
      # Run npm audit
      - name: npm audit
        run: |
          npm audit --audit-level=moderate
          if [ $? -ne 0 ]; then
            echo "Vulnerabilities found"
            exit 1
          fi
      
      # Generate SBOM
      - name: Generate SBOM
        run: npx @cyclonedx/cyclonedx-npm --output-file sbom.json
      
      # Upload SBOM
      - uses: actions/upload-artifact@v4
        with:
          name: sbom
          path: sbom.json
      
      # Sign SBOM
      - name: Sign SBOM
        uses: sigstore/cosign-installer@v3
      - run: |
          cosign sign-blob --yes sbom.json \
            --output-signature sbom.json.sig
      
      # Verify signatures
      - name: Verify signatures
        run: npm audit signatures
```

---

## إدارة الثغرات — Vulnerability Management

**العربية:**
- للثغرات المُصلَّحة: اختبر وانشر التحديثات؛ وثّق أي تغييرات كاسرة للـ API.
- للثغرات غير المُصلَّحة: نفذ ضوابط تعويضية (التحقق من المدخلات، الأغلفة) بناءً على نوع CVE؛ فضّل إصلاحات التبعية المباشرة على الحلول البديلة العابرة.
- وثّق قرارات المخاطر؛ صعّد القبول إلى السلطة المناسبة مع تبرير عملي.

**English:**
- For patched vulnerabilities: test and deploy updates; document any API breaking changes.
- For unpatched vulnerabilities: implement compensating controls (input validation, wrappers) based on CVE type; prefer direct dependency fixes over transitive workarounds.
- Document risk decisions; escalate acceptance to appropriate authority with business justification.

```python
# Python Vulnerability Management
from datetime import datetime, timedelta
from typing import Dict, List, Optional

class UAEVulnerabilityManager:
    """
    Manage vulnerabilities with UAE SLA requirements
    """
    
    # SLA by severity (days)
    SLA = {
        'CRITICAL': 7,
        'HIGH': 30,
        'MEDIUM': 90,
        'LOW': 180,
    }
    
    @classmethod
    def assess_vulnerability(cls, cve_id: str, severity: str, package: str) -> Dict:
        """Assess vulnerability and determine action"""
        
        # Check if patch available
        patch_available = cls._check_patch_available(package, cve_id)
        
        if patch_available:
            # Schedule update
            sla_days = cls.SLA.get(severity, 30)
            due_date = datetime.utcnow() + timedelta(days=sla_days)
            
            return {
                'action': 'PATCH',
                'due_date': due_date.isoformat(),
                'sla_days': sla_days,
                'priority': severity,
            }
        else:
            # Need compensating controls
            return {
                'action': 'MITIGATE',
                'compensating_controls': cls._suggest_controls(cve_id),
                'risk_acceptance_required': severity in ['CRITICAL', 'HIGH'],
            }
    
    @classmethod
    def _check_patch_available(cls, package: str, cve_id: str) -> bool:
        """Check if patch is available"""
        # Implementation would check vulnerability databases
        # For now, return True for demonstration
        return True
    
    @classmethod
    def _suggest_controls(cls, cve_id: str) -> List[str]:
        """Suggest compensating controls"""
        # This would be based on CVE analysis
        return [
            'input_validation',
            'network_segmentation',
            'monitoring',
        ]
```

---

## الاستجابة للحوادث — Incident Response

**العربية:**
- حافظ على استرجاع سريع؛ عزل الحزم المخترقة؛ خنفث عمليات النشر؛ أبلغ أصحاب المصلحة.
- راقب تدفقات الاستخبارات عن التهديدات (مثل، npm advisories)؛ افتح تذاكر تلقائياً للـ CVEs الحرجة.

**English:**
- Maintain rapid rollback; isolate compromised packages; throttle rollouts; notify stakeholders.
- Monitor threat intel feeds (e.g., npm advisories); auto-open tickets for critical CVEs.

```yaml
# Incident Response Playbook
incident_response:
  detection:
    - Monitor npm advisories
    - Monitor CVE databases
    - Monitor dependency scans
  
  containment:
    - Isolate compromised packages
    - Block vulnerable versions
    - Throttle rollouts
  
  eradication:
    - Remove compromised packages
    - Update to patched versions
    - Verify integrity
  
  recovery:
    - Restore from known-good state
    - Re-deploy with fixes
    - Monitor for re-infection
  
  lessons_learned:
    - Document incident
    - Update procedures
    - Improve detection
```

---

## قائمة التحقق — Implementation Checklist

- [ ] ملفات القفل موجودة
- [ ] فحوصات النزاهة مفعلة
- [ ] السجلات الخاصة مُكوَّنة
- [ ] SBOM + مصدر مخزن
- [ ] التوقيعات مُتحقَّقة قبل النشر
- [ ] تحديثات التبعيات الآلية مع اختبارات وبوابات مراجعة
- [ ] الثغرات عالية الخطورة مُعالَجة ضمن اتفاقية مستوى الخدمة أو مُخفَّفة ومُوثَّقة
- [ ] 2FA مفعل للنشر
- [ ] فحوصات المصدر مفعلة
- [ ] بناءات محكمة
- [ ] تخزين مؤقت مع فحوصات أصالة

---

## مراجع — References

- [OWASP Software Component Verification Standard](https://owasp.org/www-project-software-component-verification-standard/)
- [SLSA Framework](https://slsa.dev/)
- [Sigstore](https://www.sigstore.dev/)
- [CycloneDX SBOM](https://cyclonedx.org/)
- [UAE Information Assurance Framework](https://www.tra.gov.ae/)
