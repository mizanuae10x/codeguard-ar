/**
 * Rule Loader - Loads and parses CodeGuard Arabic rules
 */

import { readFileSync, readdirSync, existsSync } from 'fs';
import { join, resolve } from 'path';
import { Rule } from './types.js';

const RULES_DIR = resolve(process.cwd(), '../sources/rules');

export class RuleLoader {
  private rules: Map<string, Rule> = new Map();
  private initialized = false;

  async initialize(): Promise<void> {
    if (this.initialized) return;

    await this.loadRulesFromDirectory('core', join(RULES_DIR, 'core'));
    await this.loadRulesFromDirectory('gulf', join(RULES_DIR, 'gulf'));
    
    this.initialized = true;
    console.error(`[CodeGuard AR] Loaded ${this.rules.size} rules`);
  }

  private async loadRulesFromDirectory(category: 'core' | 'gulf' | 'permanent', dir: string): Promise<void> {
    if (!existsSync(dir)) {
      console.error(`[CodeGuard AR] Directory not found: ${dir}`);
      return;
    }

    const files = readdirSync(dir).filter(f => f.endsWith('.md'));
    
    for (const file of files) {
      // Skip non-Arabic rules (original English versions)
      if (!file.includes('-ar.md') && category === 'core') continue;
      
      const filePath = join(dir, file);
      const content = readFileSync(filePath, 'utf-8');
      
      const rule = this.parseRule(content, file, category, filePath);
      if (rule) {
        this.rules.set(rule.id, rule);
      }
    }
  }

  private parseRule(content: string, filename: string, category: 'core' | 'gulf' | 'permanent', filePath: string): Rule | null {
    try {
      // Extract frontmatter
      const frontmatterMatch = content.match(/^---\n([\s\S]*?)\n---/);
      if (!frontmatterMatch) return null;

      const frontmatter = frontmatterMatch[1];
      
      // Parse YAML frontmatter
      const description = this.extractField(frontmatter, 'description') || '';
      const languages = this.extractList(frontmatter, 'languages');
      const tags = this.extractList(frontmatter, 'tags');
      const alwaysApply = frontmatter.includes('alwaysApply: true');

      // Extract rule ID from filename
      const id = filename.replace('.md', '');
      
      // Extract name from first heading
      const nameMatch = content.match(/^#+\s+(.+)$/m);
      const name = nameMatch ? nameMatch[1].trim() : id;

      return {
        id,
        name,
        description,
        category,
        languages,
        tags,
        alwaysApply,
        content,
        filePath
      };
    } catch (error) {
      console.error(`[CodeGuard AR] Failed to parse rule ${filename}:`, error);
      return null;
    }
  }

  private extractField(frontmatter: string, field: string): string | null {
    const match = frontmatter.match(new RegExp(`^${field}:\s*(.+)$`, 'm'));
    return match ? match[1].trim() : null;
  }

  private extractList(frontmatter: string, field: string): string[] {
    const regex = new RegExp(`^${field}:\\s*\\n((?:\\s*-\\s*.+\\n?)*)`, 'm');
    const match = frontmatter.match(regex);
    
    if (match) {
      return match[1]
        .split('\n')
        .map(line => line.trim())
        .filter(line => line.startsWith('- '))
        .map(line => line.substring(2).trim());
    }
    
    // Try single-line format: field: [item1, item2]
    const singleLineMatch = frontmatter.match(new RegExp(`^${field}:\\s*\\[(.*?)\\]`, 'm'));
    if (singleLineMatch) {
      return singleLineMatch[1]
        .split(',')
        .map(item => item.trim().replace(/['"]/g, ''))
        .filter(Boolean);
    }
    
    return [];
  }

  getAllRules(): Rule[] {
    return Array.from(this.rules.values());
  }

  getRuleById(id: string): Rule | undefined {
    return this.rules.get(id);
  }

  getRulesByLanguage(language: string): Rule[] {
    return this.getAllRules().filter(rule => 
      rule.languages.includes(language.toLowerCase())
    );
  }

  getRulesByTag(tag: string): Rule[] {
    return this.getAllRules().filter(rule => 
      rule.tags.includes(tag.toLowerCase())
    );
  }

  getRulesByCategory(category: 'core' | 'gulf' | 'permanent'): Rule[] {
    return this.getAllRules().filter(rule => rule.category === category);
  }

  searchRules(query: string): Rule[] {
    const lowerQuery = query.toLowerCase();
    return this.getAllRules().filter(rule =>
      rule.name.toLowerCase().includes(lowerQuery) ||
      rule.description.toLowerCase().includes(lowerQuery) ||
      rule.tags.some(tag => tag.toLowerCase().includes(lowerQuery)) ||
      rule.content.toLowerCase().includes(lowerQuery)
    );
  }

  getUAESpecificRules(): Rule[] {
    return this.getAllRules().filter(rule =>
      rule.tags.includes('uae') ||
      rule.tags.includes('cbuae') ||
      rule.tags.includes('desc') ||
      rule.tags.includes('uae-ia') ||
      rule.id.includes('cbuae') ||
      rule.id.includes('desc') ||
      rule.id.includes('uaeia')
    );
  }
}
