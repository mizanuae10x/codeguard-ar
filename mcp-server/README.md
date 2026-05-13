# CodeGuard Arabic MCP Server

MCP Server for CodeGuard Arabic - AI-powered secure coding assistant for UAE/GCC compliance.

## Features

- 🔍 **Code Analysis**: Analyze code for security vulnerabilities using CodeGuard Arabic rules
- 📋 **Rule Management**: Access 26+ security rules (20 core + 3 Gulf + 3 permanent)
- 🇦🇪 **UAE Compliance**: Specialized rules for CBUAE, DESC, and UAE IA frameworks
- 🔐 **Secret Detection**: Check code for hardcoded secrets and credentials
- 💡 **Secure Examples**: Get secure code examples for common vulnerabilities
- 🌐 **Bilingual**: Rules available in Arabic and English

## Installation

```bash
npm install
npm run build
```

## Usage

### With Claude Desktop

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "codeguard-ar": {
      "command": "node",
      "args": ["/path/to/codeguard-ar/mcp-server/dist/index.js"]
    }
  }
}
```

### With OpenClaw

```bash
mcporter add codeguard-ar --command "node /path/to/codeguard-ar/mcp-server/dist/index.js"
```

## Available Tools

| Tool | Description |
|------|-------------|
| `analyze_code` | Analyze code for security vulnerabilities |
| `get_rule` | Get a specific security rule by ID |
| `list_rules` | List all available security rules |
| `search_rules` | Search rules by keyword |
| `get_uae_compliance` | Get UAE-specific compliance rules |
| `check_hardcoded_secrets` | Check code for hardcoded secrets |
| `get_secure_example` | Get secure code examples |

## Examples

### Analyze Code

```json
{
  "code": "const password = 'SuperSecret123!';\nconst query = 'SELECT * FROM users WHERE id = ' + userId;",
  "language": "javascript"
}
```

### Get UAE Compliance Rules

```json
{
  "framework": "cbuae"
}
```

### Get Secure Example

```json
{
  "vulnerability": "sql-injection",
  "language": "javascript"
}
```

## Rule Categories

### Core Rules (20)
- API Web Services, Authentication, Authorization
- Client-Side Security, Cloud/Kubernetes
- Data Storage, CI/CD, File Uploads
- Input Validation, Logging, Mobile Apps
- Privacy, Session Management, Supply Chain
- IaC Security, Cryptography, Framework Guides
- MCP Security, C/C++ Safety, XML/Serialization

### Gulf Rules (3)
- CBUAE Encryption Requirements
- DESC Cloud Security
- UAE IA Governance

### Permanent Rules (3)
- Cryptographic Algorithms (Post-Quantum)
- Digital Certificates
- Hardcoded Credentials

## License

MIT
