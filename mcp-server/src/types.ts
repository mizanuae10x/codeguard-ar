/**
 * Types for CodeGuard Arabic MCP Server
 */

export interface Rule {
  id: string;
  name: string;
  description: string;
  category: 'core' | 'gulf' | 'permanent';
  languages: string[];
  tags: string[];
  alwaysApply: boolean;
  content: string;
  filePath: string;
}

export interface RuleMatch {
  rule: Rule;
  relevance: number; // 0-1
  matchedLanguages: string[];
  matchedTags: string[];
}

export interface SecurityCheck {
  ruleId: string;
  ruleName: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  message: string;
  recommendation: string;
  codeExample?: string;
  lineNumber?: number;
}

export interface AnalysisResult {
  filePath: string;
  language: string;
  checks: SecurityCheck[];
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    total: number;
  };
}

export interface ComplianceFramework {
  id: string;
  name: string;
  description: string;
  region: string;
  rules: string[]; // Rule IDs
}

export interface UAEComplianceContext {
  framework: string;
  regulation: string;
  requirement: string;
  severity: string;
}
