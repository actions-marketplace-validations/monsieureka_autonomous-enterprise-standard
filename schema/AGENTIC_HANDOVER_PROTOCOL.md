---
name: agentic-handover-state
description: Generates a deterministic, zero-entropy machine-state JSON contract (agent_state.json) for seamless handovers between AI agents (Antigravity -> Claude Code / Cursor / Codex).
---

# Agentic Handover State Protocol (Zero-Entropy Handshake)

When finishing an engineering session or handing off work to another LLM/agent (e.g. Claude Code, Cursor, Codex), **never rely exclusively on natural language prose**. LLMs suffer from narrative drift, attention dilution, and hallucination on large text files.

Instead, compile and persist a typed, deterministic JSON state file: `docs/agent_state.json` (or `docs/claude_state.json`).

## The Standard Schema

```json
{
  "protocol": "PROJECT-NAME-v1.0",
  "meta": {
    "founder": "Human Principal Name",
    "directive": "Core non-negotiable philosophy (e.g., The machine works for us autonomously).",
    "timestamp": "ISO-8601",
    "handover_from": "Agent A (Antigravity)",
    "handover_to": "Agent B (Claude Code)"
  },
  "git_state": {
    "repository_a": {
      "path": "/absolute/path/to/repo",
      "branch": "active-feature-branch",
      "head_commit": "short_hash",
      "status": "clean, pushed to origin"
    }
  },
  "architecture_pillars": {
    "pillar_name": {
      "files": ["path/to/critical/files"],
      "mechanism": "1-sentence deterministic description of the contract/logic."
    }
  },
  "economic_or_functional_engine": {
    "revenue_or_output_streams": [
      "Stream 1",
      "Stream 2"
    ]
  },
  "pending_tasks": [
    {
      "step": 1,
      "task": "Action title",
      "targets": ["files/to/modify/or/merge"],
      "verification": "Deterministic test or curl command to validate success."
    }
  ]
}
```

## The 1-Line Resumption Pattern

In the target agent terminal or prompt, instruct the receiving model with a single command:

```bash
cat docs/agent_state.json
```

This ensures:
1. **0% hallucination rate** on file paths, branch names, and commit hashes.
2. **Immediate task pickup** in priority order without asking the user repetitive questions.
3. **Continuous state persistence** across distinct agent environments.
