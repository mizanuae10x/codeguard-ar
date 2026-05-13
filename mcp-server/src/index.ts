/**
 * CodeGuard Arabic MCP Server
 * AI-powered secure coding assistant for UAE/GCC compliance
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { RuleLoader } from "./rule-loader.js";
import { SecurityAnalyzer } from "./analyzer.js";
import { Rule, AnalysisResult } from "./types.js";

class CodeGuardARServer {
  private server: Server;
  private ruleLoader: RuleLoader;
  private analyzer: SecurityAnalyzer;

  constructor() {
    this.ruleLoader = new RuleLoader();
    this.analyzer = new SecurityAnalyzer(this.ruleLoader);

    this.server = new Server(
      {
        name: "codeguard-ar",
        version: "1.0.0",
      },
      {
        capabilities: {
          tools: {},
        },
      }
    );

    this.setupToolHandlers();
  }

  private setupToolHandlers() {
    // List available tools
    this.server.setRequestHandler(ListToolsRequestSchema, async () => {
      return {
        tools: [
          {
            name: "analyze_code",
            description: "Analyze code for security vulnerabilities using CodeGuard Arabic rules (UAE/GCC compliance)",
            inputSchema: {
              type: "object",
              properties: {
                code: {
                  type: "string",
                  description: "Source code to analyze",
                },
                language: {
                  type: "string",
                  description: "Programming language (javascript, python, java, csharp, php, go, ruby, swift, kotlin, c, cpp)",
                },
                filePath: {
                  type: "string",
                  description: "Optional file path for context",
                },
              },
              required: ["code", "language"],
            },
          },
          {
            name: "get_rule",
            description: "Get a specific security rule by ID",
            inputSchema: {
              type: "object",
              properties: {
                ruleId: {
                  type: "string",
                  description: "Rule ID (e.g., codeguard-0-authentication-mfa-ar)",
                },
              },
              required: ["ruleId"],
            },
          },
          {
            name: "list_rules",
            description: "List all available security rules",
            inputSchema: {
              type: "object",
              properties: {
                category: {
                  type: "string",
                  description: "Filter by category: core, gulf, permanent",
                },
                language: {
                  type: "string",
                  description: "Filter by programming language",
                },
                tag: {
                  type: "string",
                  description: "Filter by tag (e.g., uae, cbuae, desc, web, api)",
                },
              },
            },
          },
          {
            name: "search_rules",
            description: "Search rules by keyword",
            inputSchema: {
              type: "object",
              properties: {
                query: {
                  type: "string",
                  description: "Search query",
                },
              },
              required: ["query"],
            },
          },
          {
            name: "get_uae_compliance",
            description: "Get UAE-specific compliance rules (CBUAE, DESC, UAE IA)",
            inputSchema: {
              type: "object",
              properties: {
                framework: {
                  type: "string",
                  description: "Framework: cbuae, desc, uae-ia, or all",
                },
              },
            },
          },
          {
            name: "check_hardcoded_secrets",
            description: "Check code for hardcoded secrets and credentials",
            inputSchema: {
              type: "object",
              properties: {
                code: {
                  type: "string",
                  description: "Source code to check",
                },
              },
              required: ["code"],
            },
          },
          {
            name: "get_secure_example",
            description: "Get secure code example for a specific vulnerability",
            inputSchema: {
              type: "object",
              properties: {
                vulnerability: {
                  type: "string",
                  description: "Vulnerability type (sql-injection, xss, hardcoded-credentials, weak-crypto, etc.)",
                },
                language: {
                  type: "string",
                  description: "Programming language",
                },
              },
              required: ["vulnerability", "language"],
            },
          },
        ],
      };
    });

    // Handle tool calls
    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;

      try {
        switch (name) {
          case "analyze_code":
            return await this.handleAnalyzeCode(args as { code: string; language: string; filePath?: string });

          case "get_rule":
            return await this.handleGetRule(args as { ruleId: string });

          case "list_rules":
            return await this.handleListRules(args as { category?: string; language?: string; tag?: string });

          case "search_rules":
            return await this.handleSearchRules(args as { query: string });

          case "get_uae_compliance":
            return await this.handleGetUAECompliance(args as { framework?: string });

          case "check_hardcoded_secrets":
            return await this.handleCheckSecrets(args as { code: string });

          case "get_secure_example":
            return await this.handleGetSecureExample(args as { vulnerability: string; language: string });

          default:
            throw new Error(`Unknown tool: ${name}`);
        }
      } catch (error) {
        return {
          content: [
            {
              type: "text",
              text: `Error: ${error instanceof Error ? error.message : String(error)}`,
            },
          ],
          isError: true,
        };
      }
    });
  }

  private async handleAnalyzeCode(args: { code: string; language: string; filePath?: string }) {
    await this.ruleLoader.initialize();
    const result = await this.analyzer.analyzeCode(args.code, args.language, args.filePath);

    const formattedResult = this.formatAnalysisResult(result);

    return {
      content: [
        {
          type: "text",
          text: formattedResult,
        },
      ],
    };
  }

  private async handleGetRule(args: { ruleId: string }) {
    await this.ruleLoader.initialize();
    const rule = this.ruleLoader.getRuleById(args.ruleId);

    if (!rule) {
      return {
        content: [
          {
            type: "text",
            text: `Rule not found: ${args.ruleId}`,
          },
        ],
      };
    }

    return {
      content: [
        {
          type: "text",
          text: this.formatRule(rule),
        },
      ],
    };
  }

  private async handleListRules(args: { category?: string; language?: string; tag?: string }) {
    await this.ruleLoader.initialize();
    let rules = this.ruleLoader.getAllRules();

    if (args.category) {
      rules = rules.filter((r) => r.category === args.category);
    }

    if (args.language) {
      rules = rules.filter((r) =>
        r.languages.includes(args.language!.toLowerCase())
      );
    }

    if (args.tag) {
      rules = rules.filter((r) =>
        r.tags.includes(args.tag!.toLowerCase())
      );
    }

    const formatted = rules.map((r) => `- ${r.id}: ${r.name}`).join("\n");

    return {
      content: [
        {
          type: "text",
          text: `Found ${rules.length} rules:\n\n${formatted}`,
        },
      ],
    };
  }

  private async handleSearchRules(args: { query: string }) {
    await this.ruleLoader.initialize();
    const rules = this.ruleLoader.searchRules(args.query);

    const formatted = rules
      .map((r) => `- ${r.id}: ${r.name}\n  ${r.description}`)
      .join("\n\n");

    return {
      content: [
        {
          type: "text",
          text: `Found ${rules.length} rules for "${args.query}":\n\n${formatted}`,
        },
      ],
    };
  }

  private async handleGetUAECompliance(args: { framework?: string }) {
    await this.ruleLoader.initialize();
    let rules = this.ruleLoader.getUAESpecificRules();

    if (args.framework && args.framework !== "all") {
      rules = rules.filter((r) =>
        r.id.includes(args.framework!.toLowerCase()) ||
        r.tags.includes(args.framework!.toLowerCase())
      );
    }

    const formatted = rules
      .map((r) => `- ${r.id}: ${r.name}\n  ${r.description}`)
      .join("\n\n");

    return {
      content: [
        {
          type: "text",
          text: `UAE Compliance Rules (${args.framework || "all"}):\n\n${formatted}`,
        },
      ],
    };
  }

  private async handleCheckSecrets(args: { code: string }) {
    await this.ruleLoader.initialize();
    const result = await this.analyzer.checkSecrets(args.code);

    if (result.checks.length === 0) {
      return {
        content: [
          {
            type: "text",
            text: "✅ No hardcoded secrets detected!",
          },
        ],
      };
    }

    const formatted = result.checks
      .map(
        (c) =>
          `${c.severity === 'critical' ? '🔴' : c.severity === 'high' ? '🟠' : '🟡'} [${c.severity.toUpperCase()}] ${c.message}\n   Line ${c.lineNumber}: ${c.codeExample}\n   Recommendation: ${c.recommendation}`
      )
      .join("\n\n");

    return {
      content: [
        {
          type: "text",
          text: `Found ${result.checks.length} potential secrets:\n\n${formatted}`,
        },
      ],
    };
  }

  private async handleGetSecureExample(args: {
    vulnerability: string;
    language: string;
  }) {
    const examples: Record<string, Record<string, string>> = {
      "sql-injection": {
        javascript: `// ❌ Vulnerable
const query = "SELECT * FROM users WHERE id = " + userId;

// ✅ Secure - Use parameterized queries
const query = "SELECT * FROM users WHERE id = ?";
db.query(query, [userId]);`,
        python: `# ❌ Vulnerable
query = f"SELECT * FROM users WHERE id = {user_id}"

# ✅ Secure - Use parameterized queries
query = "SELECT * FROM users WHERE id = %s"
cursor.execute(query, (user_id,))`,
        java: `// ❌ Vulnerable
String query = "SELECT * FROM users WHERE id = " + userId;

// ✅ Secure - Use PreparedStatement
String query = "SELECT * FROM users WHERE id = ?";
PreparedStatement stmt = conn.prepareStatement(query);
stmt.setInt(1, userId);`,
      },
      xss: {
        javascript: `// ❌ Vulnerable
element.innerHTML = userInput;

// ✅ Secure - Use textContent
element.textContent = userInput;

// Or use a sanitization library
import DOMPurify from 'dompurify';
element.innerHTML = DOMPurify.sanitize(userInput);`,
      },
      "hardcoded-credentials": {
        javascript: `// ❌ Vulnerable
const password = "SuperSecret123!";

// ✅ Secure - Use environment variables
const password = process.env.DB_PASSWORD;`,
        python: `# ❌ Vulnerable
password = "SuperSecret123!"

# ✅ Secure - Use environment variables
import os
password = os.environ['DB_PASSWORD']`,
      },
      "weak-crypto": {
        javascript: `// ❌ Vulnerable - MD5
const hash = crypto.createHash('md5').update(data).digest('hex');

// ✅ Secure - Use SHA-256
const hash = crypto.createHash('sha256').update(data).digest('hex');`,
        python: `# ❌ Vulnerable - MD5
import hashlib
hash = hashlib.md5(data).hexdigest()

# ✅ Secure - Use SHA-256
import hashlib
hash = hashlib.sha256(data).hexdigest()`,
      },
    };

    const vulnExamples = examples[args.vulnerability];
    if (!vulnExamples) {
      return {
        content: [
          {
            type: "text",
            text: `No example available for "${args.vulnerability}". Available: ${Object.keys(examples).join(", ")}`,
          },
        ],
      };
    }

    const example = vulnExamples[args.language] || vulnExamples["javascript"];

    return {
      content: [
        {
          type: "text",
          text: `Secure example for ${args.vulnerability} in ${args.language}:\n\n${example}`,
        },
      ],
    };
  }

  private formatAnalysisResult(result: AnalysisResult): string {
    const { summary, checks, filePath, language } = result;

    let output = `🔍 Security Analysis Results\n`;
    output += `========================\n\n`;
    output += `File: ${filePath}\n`;
    output += `Language: ${language}\n`;
    output += `Summary: ${summary.total} issues found\n`;
    output += `  - Critical: ${summary.critical}\n`;
    output += `  - High: ${summary.high}\n`;
    output += `  - Medium: ${summary.medium}\n`;
    output += `  - Low: ${summary.low}\n`;
    output += `  - Info: ${summary.info}\n\n`;

    if (checks.length > 0) {
      output += `Issues:\n`;
      output += `-------\n\n`;

      for (const check of checks) {
        const icon =
          check.severity === "critical"
            ? "🔴"
            : check.severity === "high"
            ? "🟠"
            : check.severity === "medium"
            ? "🟡"
            : "🔵";

        output += `${icon} [${check.severity.toUpperCase()}] ${check.ruleName}\n`;
        output += `   Line ${check.lineNumber}: ${check.message}\n`;
        output += `   Recommendation: ${check.recommendation}\n`;
        if (check.codeExample) {
          output += `   Code: ${check.codeExample}\n`;
        }
        output += `\n`;
      }
    } else {
      output += `✅ No security issues detected!\n`;
    }

    return output;
  }

  private formatRule(rule: Rule): string {
    return `# ${rule.name}\n\n` +
      `**ID:** ${rule.id}\n` +
      `**Category:** ${rule.category}\n` +
      `**Languages:** ${rule.languages.join(", ") || "All"}\n` +
      `**Tags:** ${rule.tags.join(", ") || "None"}\n` +
      `**Always Apply:** ${rule.alwaysApply ? "Yes" : "No"}\n\n` +
      `**Description:** ${rule.description}\n\n` +
      `---\n\n` +
      `${rule.content}`;
  }

  async run() {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    console.error("CodeGuard Arabic MCP Server running on stdio");
  }
}

// Start the server
const server = new CodeGuardARServer();
server.run().catch(console.error);
