# Agent Skills

Curated plugins for Claude Code - skills, hooks, and tools.

## Installation

```bash
# Add the marketplace (once)
/plugin marketplace add andreasasprou/agent-skills

# Install plugins you want
/plugin install oracle@agent-skills
/plugin install safety-net@agent-skills

# Restart Claude Code to load plugins
```

## Available Plugins

### Oracle

GPT-5.2 strategic technical advisor with deep reasoning capabilities.

**What it does:**
- Consults GPT-5.2 with `xhigh` reasoning for architecture decisions, security analysis, and complex debugging
- Read-only sandbox - can explore your codebase but cannot modify anything
- Structured tiered responses (Essential → Expanded → Edge Cases)

**Use when:** You need a second opinion on technical decisions.

```bash
/plugin install oracle@agent-skills
```

### Safety Net

Block destructive shell commands before execution.

**What it blocks:**
- `rm -rf /`, `rm -rf ~`, `rm -rf .`
- `git reset --hard`, `git push --force`, `git clean -f`
- `aws ec2 terminate-instances`, `s3 rb --force`, `rds delete-db-instance`

**Decisions:**
- `deny` - Command blocked
- `warn` - User prompted to confirm
- `allow` - Command executes normally

**Prerequisites:** Requires [Bun](https://bun.sh) installed.

```bash
curl -fsSL https://bun.sh/install | bash
/plugin install safety-net@agent-skills
```

## Updating Plugins

```bash
# Update marketplace
/plugin marketplace update agent-skills

# Reinstall to get latest
/plugin uninstall oracle@agent-skills
/plugin install oracle@agent-skills
```

## License

MIT
