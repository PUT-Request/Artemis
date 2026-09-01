---
description: Launch a dynamic workflow for the given objective
agent: plan
subtask: false
---

Run a high-effort dynamic workflow with multi-agent orchestration, verification, and synthesis.

Objective: $ARGUMENTS

Use the dynamic_workflow_run tool with:
- objective: the user's goal
- background: true (default)
- effort: "high" (default)
- Include a stopping_condition if the user specified a verifiable end state.
- Use template if the objective matches a known pattern (deep-research, codebase-audit, large-migration, test-generation, documentation-update).
- Apply skills (security-first, test-driven, strict-types, docs-required) if relevant.

If the user says "--dry-run", "preview", "plan only", or similar, add dry_run: true to preview the workflow plan without executing.

After starting, report the workflow ID and tell the user they can check status in .opencode/dynamic-workflows/runs/<id>/.
