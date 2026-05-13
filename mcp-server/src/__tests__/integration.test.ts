/**
 * Integration Tests for CodeGuard Arabic MCP Server
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { SecurityAnalyzer } from '../analyzer.js';
import { RuleLoader } from '../rule-loader.js';

describe('Integration Tests', () => {
  let analyzer: SecurityAnalyzer;

  beforeAll(async () => {
    const ruleLoader = new RuleLoader();
    await ruleLoader.initialize();
    analyzer = new SecurityAnalyzer(ruleLoader);
  });

  describe('Real-world scenarios', () => {
    it('should analyze a complete JavaScript file', async () => {
      const code = `
const express = require('express');
const app = express();

// ❌ Hardcoded credentials
const dbPassword = 'SuperSecret123!';
const apiKey = 'sk_live_51Hx1234567890abcdef';

// ❌ SQL Injection
app.get('/users', (req, res) => {
  const query = "SELECT * FROM users WHERE id = " + req.query.id;
  db.query(query, (err, results) => {
    res.json(results);
  });
});

// ❌ XSS
app.post('/comment', (req, res) => {
  const comment = req.body.comment;
  res.send('<div>' + comment + '</div>');
});

// ❌ Weak crypto
const hash = require('crypto').createHash('md5').update(data).digest('hex');

// ✅ Secure - Environment variables
const securePassword = process.env.DB_PASSWORD;

// ✅ Secure - Parameterized query
app.get('/secure-users', (req, res) => {
  db.query('SELECT * FROM users WHERE id = ?', [req.query.id], (err, results) => {
    res.json(results);
  });
});
`;

      const result = await analyzer.checkSecrets(code);
      
      expect(result.checks.length).toBeGreaterThan(0);
      expect(result.summary.critical).toBeGreaterThan(0);
      expect(result.summary.high).toBeGreaterThan(0);
      
      // Should detect hardcoded credentials
      expect(result.checks.some(c => c.message.includes('password'))).toBe(true);
      
      // Should detect security issues
      expect(result.checks.length).toBeGreaterThan(0);
    });

    it('should analyze Python code', async () => {
      const code = `
import hashlib

# ❌ Hardcoded secret
API_KEY = "sk_live_1234567890abcdef"

# ❌ Weak hash
password_hash = hashlib.md5(password.encode()).hexdigest()

# ❌ SQL Injection
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

# ✅ Secure
import os
secure_key = os.environ.get('API_KEY')
`;

      const result = await analyzer.checkSecrets(code);
      
      expect(result.checks.length).toBeGreaterThan(0);
    });

    it('should analyze configuration files', async () => {
      const code = `
DATABASE_URL=mongodb://admin:secret123@localhost:27017/mydb
STRIPE_KEY=sk_live_51Hx1234567890abcdef
AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE
`;

      const result = await analyzer.checkSecrets(code);
      
      expect(result.checks.some(c => c.message.includes('connection string'))).toBe(true);
      expect(result.checks.some(c => c.message.includes('Stripe') || c.message.includes('API'))).toBe(true);
      expect(result.checks.some(c => c.message.includes('AWS'))).toBe(true);
    });
  });

  describe('Edge cases', () => {
    it('should handle empty code', async () => {
      const result = await analyzer.checkSecrets('');
      expect(result.checks.length).toBe(0);
    });

    it('should handle code with only comments', async () => {
      const code = `// This is a comment\n/* Another comment */`;
      const result = await analyzer.checkSecrets(code);
      expect(result.checks.length).toBe(0);
    });

    it('should handle code with environment variables', async () => {
      const code = `
const dbPassword = process.env.DB_PASSWORD;
const apiKey = process.env.STRIPE_KEY;
const secret = config.get('secret');
`;
      const result = await analyzer.checkSecrets(code);
      expect(result.checks.length).toBe(0);
    });

    it('should handle multiple secrets on same line', async () => {
      const code = `const a = "sk_live_123", b = "AKIAIOSFODNN7EXAMPLE";`;
      const result = await analyzer.checkSecrets(code);
      expect(result.checks.length).toBeGreaterThanOrEqual(1);
    });
  });

  describe('Performance', () => {
    it('should analyze large files quickly', async () => {
      const code = `
const password = "secret";
`.repeat(1000);

      const start = Date.now();
      const result = await analyzer.checkSecrets(code);
      const duration = Date.now() - start;

      expect(duration).toBeLessThan(5000); // Should complete in under 5 seconds
      expect(result.checks.length).toBeGreaterThan(0);
    });
  });
});
