/**
 * Security Analyzer - Analyzes code against CodeGuard Arabic rules
 */

import { Rule, SecurityCheck, AnalysisResult } from './types.js';
import { RuleLoader } from './rule-loader.js';

interface SecretPattern {
  name: string;
  pattern: RegExp;
  severity: 'critical' | 'high' | 'medium';
  message: string;
}

export class SecurityAnalyzer {
  private secretPatterns: SecretPattern[] = [
    // AWS
    { name: 'AWS Access Key', pattern: /AKIA[0-9A-Z]{16}/g, severity: 'critical', message: 'AWS Access Key detected' },
    { name: 'AWS Secret Key', pattern: new RegExp("['\"`]([0-9a-zA-Z/+]{40})['\"`].*?(aws|secret|key)", "gi"), severity: 'critical', message: 'Potential AWS Secret Key' },
    
    // Stripe
    { name: 'Stripe Live Key', pattern: /sk_live_[a-zA-Z0-9]{20,}/gi, severity: 'critical', message: 'Stripe Live Secret Key detected' },
    { name: 'Stripe Test Key', pattern: /sk_test_[a-zA-Z0-9]{20,}/gi, severity: 'high', message: 'Stripe Test Key detected' },
    
    // Google
    { name: 'Google API Key', pattern: /AIza[0-9A-Za-z_-]{20,}/gi, severity: 'high', message: 'Google API Key detected' },
    
    // GitHub
    { name: 'GitHub Token', pattern: /gh[pousr]_[A-Za-z0-9_]{36,}/g, severity: 'critical', message: 'GitHub Token detected' },
    
    // Generic tokens
    { name: 'Bearer Token', pattern: new RegExp("['\"`]Bearer\\s+[a-zA-Z0-9_\\-\\.]+['\"`]", "g"), severity: 'high', message: 'Bearer token hardcoded' },
    { name: 'JWT Token', pattern: /eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*/g, severity: 'high', message: 'JWT token detected' },
    
    // Database
    { name: 'Database Password', pattern: new RegExp('(password|passwd|pwd)\\s*[:=]\\s*["\'`][^"\'`]{4,}["\'`]', 'gi'), severity: 'critical', message: 'Database password hardcoded' },
    { name: 'Connection String', pattern: new RegExp('(mongodb|mysql|postgres|redis)://[^:]+:[^@]+@', 'gi'), severity: 'critical', message: 'Database connection string with credentials' },
    
    // API Keys
    { name: 'API Key', pattern: /(api[_-]?key|apikey)\s*[:=]\s*['"`][a-zA-Z0-9_\-]{16,}['"`]/gi, severity: 'high', message: 'API Key hardcoded' },
    { name: 'Secret Key', pattern: /(secret[_-]?key|secretkey)\s*[:=]\s*['"`][a-zA-Z0-9_\-]{8,}['"`]/gi, severity: 'critical', message: 'Secret key hardcoded' },
    
    // Private Keys
    { name: 'Private Key', pattern: /-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g, severity: 'critical', message: 'Private key detected' },
    
    // Common passwords
    { name: 'Weak Password', pattern: /['"`][a-z]*password\d*['"`]/gi, severity: 'medium', message: 'Weak/common password pattern' },
    { name: 'Default Admin', pattern: /admin['"`]?\s*[:=]\s*['"`][^'"`]+['"`]/gi, severity: 'medium', message: 'Potential admin credential' },
  ];

  private sqlPatterns: SecretPattern[] = [
    { name: 'SQL Concatenation', pattern: new RegExp("['\"`]\\s*(SELECT|INSERT|UPDATE|DELETE)\\s+.*\\+\\s*['\"`]", "gi"), severity: 'critical', message: 'SQL query concatenation detected' },
    { name: 'Dynamic SQL', pattern: /(execute|query|exec)\s*\(\s*['"`].*\$\{.*\}/gi, severity: 'critical', message: 'Dynamic SQL with template literals' },
    { name: 'String Interpolation SQL', pattern: /['"`]\s*(SELECT|INSERT|UPDATE|DELETE)\s+.*\$\{.*\}/gi, severity: 'critical', message: 'SQL with string interpolation' },
  ];

  private xssPatterns: SecretPattern[] = [
    { name: 'innerHTML', pattern: /\.innerHTML\s*=\s*[^;]+/g, severity: 'high', message: 'innerHTML assignment detected' },
    { name: 'document.write', pattern: /document\.write\s*\(/g, severity: 'high', message: 'document.write usage detected' },
    { name: 'eval', pattern: /eval\s*\(/g, severity: 'critical', message: 'eval() usage detected' },
    { name: 'dangerouslySetInnerHTML', pattern: /dangerouslySetInnerHTML/g, severity: 'high', message: 'React dangerouslySetInnerHTML detected' },
  ];

  private cryptoPatterns: SecretPattern[] = [
    { name: 'MD5', pattern: /['"`]md5['"`]|\.createHash\(['"`]md5['"`]\)/gi, severity: 'high', message: 'Weak hash algorithm MD5 detected' },
    { name: 'SHA1', pattern: /['"`]sha1['"`]|\.createHash\(['"`]sha1['"`]\)/gi, severity: 'high', message: 'Weak hash algorithm SHA1 detected' },
    { name: 'DES', pattern: /['"`]des['"`]/gi, severity: 'high', message: 'Weak encryption DES detected' },
    { name: 'RC4', pattern: /['"`]rc4['"`]/gi, severity: 'high', message: 'Weak encryption RC4 detected' },
    { name: 'ECB Mode', pattern: /['"`]ecb['"`]/gi, severity: 'high', message: 'Insecure ECB mode detected' },
  ];

  constructor(private ruleLoader: RuleLoader) {}

  async analyzeCode(code: string, language: string, filePath: string = 'unknown'): Promise<AnalysisResult> {
    const checks: SecurityCheck[] = [];
    
    // Get relevant rules for this language
    const rules = this.ruleLoader.getRulesByLanguage(language);
    
    // Also get permanent rules (always apply)
    const permanentRules = this.ruleLoader.getRulesByCategory('permanent')
      .filter(r => r.alwaysApply);
    
    const allRules = [...rules, ...permanentRules];
    
    for (const rule of allRules) {
      const ruleChecks = await this.checkRule(code, rule, language);
      checks.push(...ruleChecks);
    }

    // Summary
    const summary = {
      critical: checks.filter(c => c.severity === 'critical').length,
      high: checks.filter(c => c.severity === 'high').length,
      medium: checks.filter(c => c.severity === 'medium').length,
      low: checks.filter(c => c.severity === 'low').length,
      info: checks.filter(c => c.severity === 'info').length,
      total: checks.length
    };

    return {
      filePath,
      language,
      checks,
      summary
    };
  }

  async checkSecrets(code: string, filePath: string = 'unknown'): Promise<AnalysisResult> {
    const checks: SecurityCheck[] = [];
    const lines = code.split('\n');

    // Check all secret patterns
    for (const pattern of this.secretPatterns) {
      const matches = this.findMatches(code, pattern.pattern);
      for (const match of matches) {
        const lineNumber = this.getLineNumber(code, match.index);
        const lineContent = lines[lineNumber - 1] || '';
        
        // Skip false positives (environment variable assignments, comments)
        if (this.isFalsePositive(lineContent, pattern.name)) {
          continue;
        }

        checks.push({
          ruleId: 'codeguard-1-hardcoded-credentials',
          ruleName: 'No Hardcoded Credentials',
          severity: pattern.severity,
          message: `${pattern.message}: ${match.text.substring(0, 30)}...`,
          recommendation: this.getSecretRecommendation(pattern.name),
          codeExample: lineContent.trim(),
          lineNumber
        });
      }
    }

    // Check SQL injection patterns
    for (const pattern of this.sqlPatterns) {
      const matches = this.findMatches(code, pattern.pattern);
      for (const match of matches) {
        const lineNumber = this.getLineNumber(code, match.index);
        const lineContent = lines[lineNumber - 1] || '';
        
        checks.push({
          ruleId: 'codeguard-0-input-validation-injection',
          ruleName: 'Input Validation & Injection Defense',
          severity: pattern.severity,
          message: `${pattern.message}: ${match.text.substring(0, 50)}...`,
          recommendation: 'Use parameterized queries or prepared statements. Never concatenate user input into SQL queries.',
          codeExample: lineContent.trim(),
          lineNumber
        });
      }
    }

    // Check XSS patterns
    for (const pattern of this.xssPatterns) {
      const matches = this.findMatches(code, pattern.pattern);
      for (const match of matches) {
        const lineNumber = this.getLineNumber(code, match.index);
        const lineContent = lines[lineNumber - 1] || '';
        
        checks.push({
          ruleId: 'codeguard-0-client-side-web-security',
          ruleName: 'Client-side Web Security',
          severity: pattern.severity,
          message: `${pattern.message}: ${match.text.substring(0, 50)}...`,
          recommendation: 'Use textContent instead of innerHTML. Sanitize all user input before DOM insertion.',
          codeExample: lineContent.trim(),
          lineNumber
        });
      }
    }

    // Check crypto patterns
    for (const pattern of this.cryptoPatterns) {
      const matches = this.findMatches(code, pattern.pattern);
      for (const match of matches) {
        const lineNumber = this.getLineNumber(code, match.index);
        const lineContent = lines[lineNumber - 1] || '';
        
        // Skip comments
        if (lineContent.trim().startsWith('//') || lineContent.trim().startsWith('#') || lineContent.trim().startsWith('*')) {
          continue;
        }

        checks.push({
          ruleId: 'codeguard-1-crypto-algorithms',
          ruleName: 'Cryptographic Security Guidelines',
          severity: pattern.severity,
          message: `${pattern.message}: ${match.text.substring(0, 50)}...`,
          recommendation: 'Use modern algorithms: AES-GCM, ChaCha20-Poly1305, SHA-256+, RSA 2048+ or ECDSA P-256+.',
          codeExample: lineContent.trim(),
          lineNumber
        });
      }
    }

    const summary = {
      critical: checks.filter(c => c.severity === 'critical').length,
      high: checks.filter(c => c.severity === 'high').length,
      medium: checks.filter(c => c.severity === 'medium').length,
      low: checks.filter(c => c.severity === 'low').length,
      info: checks.filter(c => c.severity === 'info').length,
      total: checks.length
    };

    return {
      filePath,
      language: 'javascript',
      checks,
      summary
    };
  }

  private findMatches(code: string, pattern: RegExp): Array<{text: string, index: number}> {
    const matches: Array<{text: string, index: number}> = [];
    let match;
    
    // Reset regex
    pattern.lastIndex = 0;
    
    while ((match = pattern.exec(code)) !== null) {
      matches.push({
        text: match[0],
        index: match.index
      });
      
      // Prevent infinite loops for zero-length matches
      if (match.index === pattern.lastIndex) {
        pattern.lastIndex++;
      }
    }
    
    return matches;
  }

  private isFalsePositive(line: string, patternName: string): boolean {
    const trimmed = line.trim();
    
    // Skip comments
    if (trimmed.startsWith('//') || trimmed.startsWith('#') || trimmed.startsWith('*') || trimmed.startsWith('/*')) {
      return true;
    }
    
    // Skip environment variable references
    if (trimmed.includes('process.env') || trimmed.includes('os.environ') || trimmed.includes('System.getenv')) {
      return true;
    }
    
    // Skip config file references
    if (trimmed.includes('config.get') || trimmed.includes('Config::get')) {
      return true;
    }
    
    // Skip placeholder examples
    if (trimmed.includes('example') || trimmed.includes('placeholder') || trimmed.includes('your_')) {
      return true;
    }
    
    // Skip empty strings
    if (trimmed.includes("''") || trimmed.includes('""') || trimmed.includes('``')) {
      return true;
    }
    
    return false;
  }

  private getSecretRecommendation(secretType: string): string {
    const recommendations: Record<string, string> = {
      'AWS Access Key': 'Use AWS IAM roles or environment variables. Never hardcode AWS credentials.',
      'AWS Secret Key': 'Use AWS Secrets Manager or IAM roles. Rotate credentials regularly.',
      'Stripe Live Key': 'Use Stripe CLI or environment variables. Use test keys in development.',
      'Google API Key': 'Use Google Cloud Secret Manager or environment variables. Restrict API key usage.',
      'GitHub Token': 'Use GitHub CLI or environment variables. Use fine-grained tokens with minimal permissions.',
      'Database Password': 'Use environment variables or a secret manager (AWS Secrets Manager, Azure Key Vault, HashiCorp Vault).',
      'Connection String': 'Store connection strings in environment variables or secret managers. Use managed identities when possible.',
      'API Key': 'Use environment variables or secret managers. Implement key rotation policies.',
      'Secret Key': 'Use environment variables or secret managers. Never commit secrets to version control.',
      'Private Key': 'Store private keys in HSM/KMS or secure key stores. Never commit to version control.',
      'Bearer Token': 'Use OAuth flows or token managers. Implement token refresh mechanisms.',
      'JWT Token': 'Use secure token storage. Implement token expiration and refresh.',
    };
    
    return recommendations[secretType] || 'Use environment variables or a secure secret manager to store credentials.';
  }

  private async checkRule(code: string, rule: Rule, language: string): Promise<SecurityCheck[]> {
    // For now, use the secret checker for hardcoded credentials rule
    if (rule.id.includes('hardcoded-credentials')) {
      const result = await this.checkSecrets(code);
      return result.checks.filter(c => c.ruleId === 'codeguard-1-hardcoded-credentials');
    }
    
    return [];
  }

  private getLineNumber(code: string, index: number): number {
    return code.substring(0, index).split('\n').length;
  }
}
