/**
 * Rule Loader Tests
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { RuleLoader } from '../rule-loader.js';

describe('RuleLoader', () => {
  let ruleLoader: RuleLoader;

  beforeAll(async () => {
    ruleLoader = new RuleLoader();
    await ruleLoader.initialize();
  });

  it('should load all rules', () => {
    const rules = ruleLoader.getAllRules();
    expect(rules.length).toBeGreaterThan(0);
  });

  it('should load core rules', () => {
    const rules = ruleLoader.getRulesByCategory('core');
    expect(rules.length).toBeGreaterThan(0);
  });

  it('should load gulf rules', () => {
    const rules = ruleLoader.getRulesByCategory('gulf');
    expect(rules.length).toBeGreaterThan(0);
  });

  it('should get rule by id', () => {
    const rule = ruleLoader.getRuleById('codeguard-0-cbuae-encryption');
    expect(rule).toBeDefined();
    expect(rule?.id).toBe('codeguard-0-cbuae-encryption');
  });

  it('should return undefined for unknown rule', () => {
    const rule = ruleLoader.getRuleById('non-existent-rule');
    expect(rule).toBeUndefined();
  });

  it('should filter by language', () => {
    const rules = ruleLoader.getRulesByLanguage('javascript');
    expect(rules.length).toBeGreaterThan(0);
  });

  it('should filter by tag', () => {
    const rules = ruleLoader.getRulesByTag('uae');
    expect(rules.length).toBeGreaterThan(0);
  });

  it('should search rules', () => {
    const rules = ruleLoader.searchRules('تشفير');
    expect(rules.length).toBeGreaterThan(0);
  });

  it('should get UAE specific rules', () => {
    const rules = ruleLoader.getUAESpecificRules();
    expect(rules.length).toBeGreaterThan(0);
    expect(rules.some(r => r.id.includes('cbuae'))).toBe(true);
  });

  it('should have bilingual content', () => {
    const rules = ruleLoader.getAllRules();
    const rule = rules[0];
    expect(rule.content).toContain('##');
  });
});
