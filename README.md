# Agent Skills

Curated plugins for Claude Code - skills, hooks, and tools.

## Quick Start

```bash
# Add the marketplace (once)
/plugin marketplace add https://github.com/andreasasprou/agent-skills

# Install plugins
/plugin install oracle@andreas-agent-skills
/plugin install safety-net@andreas-agent-skills
/plugin install opensrc@andreas-agent-skills
```

## How It Works

Claude Code plugins extend the agent with **skills** (new capabilities) and **hooks** (intercept actions).

| Type | Purpose | Example |
|------|---------|---------|
| **Skill** | Add new commands/capabilities | Oracle adds `/oracle` for consulting GPT-5.2 |
| **Hook** | Intercept and validate actions | Safety-net blocks destructive commands |

---

## Plugins

### Oracle

A strategic technical advisor powered by GPT-5.2 with deep reasoning (`xhigh` effort).

**When to use:**
- Architecture decisions
- Complex debugging
- Security analysis
- Trade-off evaluation
- When you want a second expert opinion

**Features:**
- Uses [Codex TypeScript SDK](https://github.com/openai/codex/tree/main/sdk/typescript) with streaming output
- Read-only sandbox (can explore but not modify your codebase)
- Real-time progress indicators

**Usage:**
```bash
/oracle "What's the best approach for implementing rate limiting?"
```

**Response Structure:**

Oracle uses a tiered response format for actionable advice:

```
### Essential (Always Include)
- **Bottom Line**: Direct answer in 1-2 sentences
- **Action Plan**: Concrete next steps (numbered)
- **Effort Estimate**: Quick (<1h) | Short (1-4h) | Medium (1-2d) | Large (3d+)

### Expanded (When Relevant)
- **Reasoning**: Why this approach over alternatives
- **Trade-offs**: What you gain vs what you sacrifice
- **Dependencies**: External factors or prerequisites

### Edge Cases (When Applicable)
- **Escalation Triggers**: When to reconsider this approach
- **Alternatives**: Backup options if primary fails
- **Gotchas**: Common mistakes to avoid
```

**Philosophy:**
- Bias toward simplicity - the right solution is typically the least complex
- Leverage existing code/patterns before adding dependencies
- Prioritize developer experience over theoretical optimization

---

### Safety Net

A PreToolUse hook that intercepts destructive commands before execution. **200+ dangerous patterns** across 14 categories.

**How it works:**
1. Intercepts every `Bash` tool call
2. Analyzes the command for destructive patterns
3. Blocks (`deny`) or warns (`warn`) based on severity
4. Safe commands pass through silently

**Coverage:**

| Category | Blocked Examples |
|----------|-----------------|
| **Filesystem** | `rm -rf /`, `rm -rf ~`, `find -delete` |
| **Git** | `git reset --hard`, `git push --force`, `git clean -fd`, `git stash clear` |
| **Docker** | `docker system prune`, `docker volume prune`, `docker rm -f`, `docker-compose down -v` |
| **Kubernetes** | `kubectl delete namespace`, `kubectl delete --all`, `kubectl drain`, `helm uninstall` |
| **Terraform** | `terraform destroy`, `terraform apply -auto-approve`, `terraform state rm` |
| **AWS** | `terminate-instances`, `delete-db-instance`, `s3 rb --force`, `s3 rm --recursive` |
| **Google Cloud** | `gcloud projects delete`, `gcloud compute instances delete`, `gsutil rm -r` |
| **Azure** | `az group delete`, `az vm delete`, `az storage account delete` |
| **Databases** | `DROP DATABASE`, `DROP TABLE`, `DELETE` without WHERE, `FLUSHALL` |
| **Pulumi** | `pulumi destroy`, `pulumi stack rm --force` |
| **Stripe** | `stripe delete --live`, `stripe refunds create --live` |
| **GitHub CLI** | `gh repo delete`, `gh release delete`, `gh secret delete` |
| **System** | `kill -9 1`, `dd of=/dev/sda`, `mkfs`, `chmod 777`, `shutdown` |
| **APIs** | Linear GraphQL mutations, Datadog DELETE requests |

**Cloud Provider Coverage:**

<details>
<summary>AWS (verb-based classification)</summary>

Instead of maintaining allowlists, safety-net classifies AWS commands by verb:

| Verb Type | Examples | Decision |
|-----------|----------|----------|
| Read-only | `describe-*`, `get-*`, `list-*` | allow |
| Mutation | `create-*`, `update-*`, `run-*`, `stop-*` | warn |
| Destructive | `delete-*`, `terminate-*`, `purge-*` | deny |

**S3 Direction Awareness:**
- `aws s3 cp s3://bucket ./local` → allow (download)
- `aws s3 cp ./local s3://bucket` → warn (upload)
- `aws s3 sync --delete` → deny (destructive)

</details>

<details>
<summary>Google Cloud (gcloud, gsutil)</summary>

| Command | Decision |
|---------|----------|
| `gcloud projects delete` | deny (catastrophic) |
| `gcloud compute instances delete` | deny |
| `gcloud sql instances delete` | deny |
| `gsutil rm -r` | deny |
| `gsutil rb -f` | deny |

</details>

<details>
<summary>Azure CLI</summary>

| Command | Decision |
|---------|----------|
| `az group delete` | deny (removes ALL resources) |
| `az vm delete` | deny/warn |
| `az storage account delete` | deny/warn |
| `az aks delete` | deny/warn |

</details>

**Container & Orchestration:**

<details>
<summary>Docker / Podman</summary>

| Command | Decision |
|---------|----------|
| `docker system prune -a --volumes` | deny |
| `docker volume prune` | deny |
| `docker rm -f` | warn |
| `docker-compose down -v` | deny |

</details>

<details>
<summary>Kubernetes (kubectl, helm)</summary>

| Command | Decision |
|---------|----------|
| `kubectl delete namespace` | deny |
| `kubectl delete --all-namespaces` | deny |
| `kubectl delete --all` | deny |
| `kubectl drain --force` | deny |
| `helm uninstall` | warn |

</details>

**Infrastructure as Code:**

<details>
<summary>Terraform</summary>

| Command | Decision |
|---------|----------|
| `terraform destroy` | deny |
| `terraform apply -auto-approve` | warn |
| `terraform state rm` | warn |
| `terraform force-unlock` | deny |

</details>

**Databases:**

<details>
<summary>PostgreSQL, MySQL, MongoDB, Redis</summary>

| Pattern | Decision |
|---------|----------|
| `DROP DATABASE` | deny |
| `DROP TABLE` | deny |
| `TRUNCATE` | deny |
| `DELETE` without `WHERE` | deny |
| `FLUSHALL` / `FLUSHDB` | deny |
| `dropdb` | deny |

</details>

**API Mutation Detection:**

Catches `curl` commands to known APIs:

| API | Read | Write | Delete |
|-----|------|-------|--------|
| Linear (`api.linear.app`) | GraphQL query → allow | GraphQL mutation → warn | - |
| Datadog (`api.datadoghq.com`) | GET → allow | POST/PUT → warn | DELETE → deny |

**Configuration:**
```bash
# Disable specific rule sets
SAFETY_NET_DISABLE_AWS=1
SAFETY_NET_DISABLE_GIT=1
SAFETY_NET_DISABLE_DOCKER=1
SAFETY_NET_DISABLE_KUBERNETES=1
SAFETY_NET_DISABLE_TERRAFORM=1
SAFETY_NET_DISABLE_GCLOUD=1
SAFETY_NET_DISABLE_AZURE=1
SAFETY_NET_DISABLE_DATABASE=1
SAFETY_NET_DISABLE_GITHUB=1

# Paranoid mode (escalate warnings to denials)
SAFETY_NET_PARANOID=1
SAFETY_NET_PARANOID_AWS=1
SAFETY_NET_PARANOID_DOCKER=1
```

**Requires [Bun](https://bun.sh):**
```bash
curl -fsSL https://bun.sh/install | bash
```

---

### opensrc

Fetch npm package source code for deep implementation analysis.

**When to use:**
- Types/docs aren't enough
- Need to understand HOW a library works internally
- Debugging unexpected behavior

**Usage:**
```bash
# Fetch packages
npx opensrc ai zod @anthropic-ai/sdk

# Check what's fetched
cat opensrc/sources.json

# Explore (many are monorepos)
ls opensrc/ai/packages/

# Clean up when done
rm -rf opensrc/ai
```

**Common Packages:**

| Package | Structure |
|---------|-----------|
| `ai` | Monorepo: `packages/anthropic/`, `packages/openai/` |
| `@anthropic-ai/sdk` | Single package: `src/` |
| `zod` | Single package: `src/types/` |

---

## Updating

```bash
/plugin marketplace update andreas-agent-skills
```

## License

MIT
