---
name: oracle
description: Strategic technical advisor with two modes. Use for second opinions, architecture decisions, debugging, security analysis, and research. REPO MODE explores your codebase autonomously (finds gaps, reviews code, traces bugs). WEB MODE researches external info (current best practices, library comparisons, docs). Run both in parallel when comparing your implementation against current standards.
allowed-tools: Bash, TaskOutput, AskUserQuestion
---

# Oracle - Unified Technical Advisor

Two complementary modes for different types of questions.

## Routing Decision

**Ask: "Is the truth external, or is it in our code?"**

| Truth Location | Mode | Model |
|----------------|------|-------|
| In our code | Repo | `gpt-5.2` xhigh via Codex SDK |
| External (docs, standards, comparisons) | Web | `5.2 Thinking` (default) |
| Complex research needing web synthesis | Web | `gpt-5.2-pro` (escalation) |
| Both (compare impl vs standards) | Parallel | Run both modes |

## Commands

**Script root**: `${CLAUDE_PLUGIN_ROOT}/skills/oracle/scripts`

### Repo Oracle (codebase exploration)

```bash
bun ${CLAUDE_PLUGIN_ROOT}/skills/oracle/scripts/oracle.ts "question"
```

Capabilities: Explores files, runs commands, searches web (read-only sandbox).

### Web Oracle (external research)

```bash
# Default: 5.2 Thinking (extended reasoning)
npx -y @steipete/oracle --engine browser --model "5.2 Thinking" -p "question"

# Escalation: gpt-5.2-pro (Deep Research - for complex multi-source research)
npx -y @steipete/oracle --engine browser --model gpt-5.2-pro -p "question"

# Include repo context (curated files)
npx -y @steipete/oracle --engine browser --model "5.2 Thinking" \
  --file "src/auth/**/*.ts" \
  --file "!**/*.test.ts" \
  -p "question with context"
```

### Parallel Execution

Run both with `run_in_background=true`, poll with TaskOutput, synthesize results.

## When to Use Each Mode

### Repo Oracle

Questions where the answer is **in the codebase**:

- "What's causing this race condition in the queue processor?"
- "Audit the blast radius before I refactor the payment service"
- "Why are tests flaky on CI? Investigate the test setup"
- "Map how a request flows from API route to database"
- "Review the uncommitted changes for issues"

### Web Oracle (5.2 Thinking - default)

Questions needing **external knowledge**:

- "Drizzle vs Prisma for heavy read loads - what are teams saying?"
- "Current security gotchas with Google OAuth?"
- "Is it worth migrating Next.js pages router to app router now?"
- "Compare Socket.io vs Ably vs Pusher for a team of 3"

### Web Oracle (gpt-5.2-pro - escalation)

**Complex research** requiring multi-source synthesis:

- "Comprehensive analysis of auth patterns for B2B SaaS in 2026"
- "Migration path from Redis to Valkey - gather all community experiences"
- "Full competitive analysis of state management solutions"

### Both in Parallel

When comparing **your code against current standards**:

- "Is our auth middleware following current OWASP guidelines?"
- "Does our error handling match RFC 7807? Review our impl"
- "Are we using this library correctly per current docs?"

## Routing When Unclear

If the question type isn't obvious, use AskUserQuestion:

```
What kind of help do you need?
- Find issues in the current implementation (Repo)
- Research best practices and patterns (Web)
- Compare our implementation against current standards (Both)
```

## Second Opinion Workflow

Best practice from developer research: **review diffs and tests, not raw code**.

```
1. Generate changes (primary agent writes code)
2. Package context for review (diff + key files + test results)
3. Review with oracle (critique: bugs, edge cases, missing tests)
4. Apply fixes + run tests
5. Repeat until critique converges
```

Effective review questions:
- "Review the current diff for security issues"
- "What edge cases am I missing in these uncommitted changes?"
- "At the end of this phase, review my work"

## Response Format

Both modes return structured responses:

### Essential
- **Bottom Line**: Direct answer (1-2 sentences)
- **Action Plan**: Numbered next steps
- **Effort Estimate**: Quick (<1h) | Short (1-4h) | Medium (1-2d) | Large (3d+)

### Expanded (when relevant)
- **Reasoning**: Why this approach
- **Trade-offs**: Gains vs sacrifices
- **Dependencies**: Prerequisites

### Edge Cases (when applicable)
- **Escalation Triggers**: When to reconsider
- **Alternatives**: Backup options
- **Gotchas**: Common mistakes

## Background Execution

For deep analysis, run in background:

```bash
# Start (use run_in_background=true)
bun ${CLAUDE_PLUGIN_ROOT}/skills/oracle/scripts/oracle.ts "Audit this codebase for security issues"

# Poll
TaskOutput with block=false

# Get result (avoid context flooding)
tail -100 /path/to/output
```

## Model Selection Summary

| Mode | Model | Use When |
|------|-------|----------|
| Repo | `gpt-5.2` xhigh | Codebase questions, finding gaps, code review |
| Web (default) | `5.2 Thinking` | External research, best practices, comparisons |
| Web (escalation) | `gpt-5.2-pro` | Complex multi-source research, deep synthesis |
