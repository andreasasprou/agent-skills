# Agent Skills

Curated plugins for Claude Code - skills, hooks, and tools.

## Installation

```bash
# Add the marketplace (once)
/plugin marketplace add https://github.com/andreasasprou/agent-skills

# Install plugins
/plugin install oracle@andreas-agent-skills
/plugin install safety-net@andreas-agent-skills
/plugin install opensrc@andreas-agent-skills
```

## Plugins

### Oracle

GPT-5.2 strategic advisor with deep reasoning.

- Consults GPT-5.2 with `xhigh` reasoning effort
- Read-only sandbox (can explore but not modify)
- Use for architecture decisions, security analysis, complex debugging

```bash
/plugin install oracle@andreas-agent-skills
```

### Safety Net

Block destructive shell commands before execution.

**Blocks:**
- Filesystem: `rm -rf /`, `rm -rf ~`
- Git: `git reset --hard`, `git push --force`
- AWS: `terminate-instances`, `delete-db-instance`, `s3 rb --force`
- Pulumi: `pulumi destroy`, `pulumi stack rm --force`
- Stripe: `stripe delete --live`, `stripe refunds create --live`
- System: `kill -9 1`, `killall -9`

**Requires [Bun](https://bun.sh):**
```bash
curl -fsSL https://bun.sh/install | bash
/plugin install safety-net@andreas-agent-skills
```

### opensrc

Fetch npm package source code for implementation analysis.

- Use when types/docs aren't enough
- Explore how libraries work internally
- Debug unexpected behavior

```bash
/plugin install opensrc@andreas-agent-skills

# Usage (via skill)
npx opensrc ai zod @anthropic-ai/sdk
```

## Updating

```bash
/plugin marketplace update andreas-agent-skills
```

## License

MIT
