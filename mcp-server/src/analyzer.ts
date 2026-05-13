/**
 * Security Analyzer - Analyzes code against CodeGuard Arabic rules
 */

import { Rule, SecurityCheck, AnalysisResult } from './types.js';
import { RuleLoader } from './rule-loader.js';

export class SecurityAnalyzer {
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

  private async checkRule(code: string, rule: Rule, language: string): Promise<SecurityCheck[]> {
    const checks: SecurityCheck[] = [];
    const lines = code.split('\n');

    // Pattern-based checks based on rule content
    const patterns = this.extractPatterns(rule);
    
    for (const pattern of patterns) {
      const regex = new RegExp(pattern, 'gi');
      let match;
      
      while ((match = regex.exec(code)) !== null) {
        const lineNumber = this.getLineNumber(code, match.index);
        const lineContent = lines[lineNumber - 1] || '';
        
        checks.push({
          ruleId: rule.id,
          ruleName: rule.name,
          severity: this.determineSeverity(rule, lineContent),
          message: this.generateMessage(rule, lineContent),
          recommendation: this.generateRecommendation(rule),
          codeExample: lineContent.trim(),
          lineNumber
        });
      }
    }

    return checks;
  }

  private extractPatterns(rule: Rule): string[] {
    const patterns: string[] = [];
    
    // Extract forbidden functions/patterns from rule content
    // This is a simplified version - in production, you'd want more sophisticated parsing
    
    if (rule.id.includes('hardcoded-credentials')) {
      patterns.push(
        'password\\s*=\\s*["\'][^"\']+["\']',
        'api_key\\s*=\\s*["\'][^"\']+["\']',
        'secret\\s*=\\s*["\'][^"\']+["\']',
        'token\\s*=\\s*["\'][^"\']+["\']',
        'AKIA[0-9A-Z]{16}',
        'sk_live_[a-zA-Z0-9]{24,}',
        'AIza[0-9A-Za-z_-]{35}'
      );
    }
    
    if (rule.id.includes('input-validation')) {
      patterns.push(
        'eval\\s*\\(',
        'exec\\s*\\(',
        'system\\s*\\(',
        'innerHTML\\s*=',
        'document\\.write\\s*\\('
      );
    }
    
    if (rule.id.includes('sql-injection')) {
      patterns.push(
        'SELECT\\s+.*\\s+FROM\\s+.*\\+',
        'INSERT\\s+INTO\\s+.*\\+',
        'UPDATE\\s+.*\\s+SET\\s+.*\\+',
        'DELETE\\s+FROM\\s+.*\\+'
      );
    }
    
    if (rule.id.includes('crypto')) {
      patterns.push(
        'MD5',
        'SHA1',
        'DES',
        'RC4',
        'AES\\.new\\s*\\(',
        'Crypto\\.Cipher'
      );
    }
    
    if (rule.id.includes('authentication')) {
      patterns.push(
        'password\\s*=\\s*["\'][^"\']{1,7}["\']',
        'admin\\s*=\\s*["\'][^"\']+["\']',
        '123456',
        'password'
      );
    }

    return patterns;
  }

  private getLineNumber(code: string, index: number): number {
    return code.substring(0, index).split('\n').length;
  }

  private determineSeverity(rule: Rule, lineContent: string): 'critical' | 'high' | 'medium' | 'low' | 'info' {
    if (rule.id.includes('hardcoded-credentials')) {
      if (lineContent.includes('password') || lineContent.includes('secret')) return 'critical';
      return 'high';
    }
    
    if (rule.id.includes('input-validation') || rule.id.includes('sql-injection')) {
      return 'critical';
    }
    
    if (rule.id.includes('crypto')) {
      return 'high';
    }
    
    if (rule.alwaysApply) {
      return 'high';
    }
    
    return 'medium';
  }

  private generateMessage(rule: Rule, lineContent: string): string {
    if (rule.id.includes('hardcoded-credentials')) {
      return `Potential hardcoded credential detected: ${lineContent.trim().substring(0, 50)}`;
    }
    
    if (rule.id.includes('input-validation')) {
      return `Unsafe input handling detected: ${lineContent.trim().substring(0, 50)}`;
    }
    
    if (rule.id.includes('sql-injection')) {
      return `Potential SQL injection vulnerability: ${lineContent.trim().substring(0, 50)}`;
    }
    
    if (rule.id.includes('crypto')) {
      return `Weak cryptographic algorithm detected: ${lineContent.trim().substring(0, 50)}`;
    }
    
    return `Security issue detected by rule: ${rule.name}`;
  }

  private generateRecommendation(rule: Rule): string {
    if (rule.id.includes('hardcoded-credentials')) {
      return 'Use environment variables or a secure secret manager (AWS Secrets Manager, Azure Key Vault, HashiCorp Vault) to store credentials.';
    }
    
    if (rule.id.includes('input-validation')) {
      return 'Use parameterized queries, input validation libraries, and context-aware output encoding.';
    }
    
    if (rule.id.includes('sql-injection')) {
      return 'Use prepared statements or ORM query builders. Never concatenate user input into SQL queries.';
    }
    
    if (rule.id.includes('crypto')) {
      return 'Use modern cryptographic algorithms: AES-GCM, ChaCha20-Poly1305, SHA-256+, RSA 2048+ or ECDSA P-256+.';
    }
    
    return `Review rule ${rule.id} for specific recommendations.`;
  }
}
