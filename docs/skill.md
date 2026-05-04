---
title: CyberOwl AI Skill
---

# CyberOwl AI Skill

Scans your project and tells you which security alerts actually affect your stack. Updated daily from 10 CERTs worldwide.

Works with **Claude Code**, **Cursor**, **GitHub Copilot**, **Windsurf**, **JetBrains AI**, and any tool that supports custom instructions.

---

## Setup

### Claude Code

```bash
mkdir -p .claude/skills/cyberowlai && curl -o .claude/skills/cyberowlai/SKILL.md https://cyberowlai.com/skill/SKILL.md
```

Then run:

```
/cyberowlai
```

### Cursor

```bash
mkdir -p .cursor/rules && curl -o .cursor/rules/cyberowlai.mdc https://cyberowlai.com/skill/SKILL.md
```

Then ask: *"check cyberowlai"* or *"any new CVEs for my stack?"*

### GitHub Copilot

Works in VS Code, JetBrains, and the Copilot CLI.

```bash
mkdir -p .github/instructions && curl -o .github/instructions/cyberowlai.instructions.md https://cyberowlai.com/skill/SKILL.md
```

Automatically included in all Copilot Chat interactions within the workspace.

### Windsurf

```bash
mkdir -p .windsurf/rules && curl -o .windsurf/rules/cyberowlai.md https://cyberowlai.com/skill/SKILL.md
```

Automatically included by Cascade in every session.

### JetBrains AI Assistant

Works in IntelliJ, PyCharm, WebStorm, and all JetBrains IDEs.

```bash
mkdir -p .aiassistant/rules && curl -o .aiassistant/rules/cyberowlai.md https://cyberowlai.com/skill/SKILL.md
```

Automatically included in all AI Assistant interactions.

### Other tools

Download [SKILL.md](https://cyberowlai.com/skill/SKILL.md) and place it wherever your tool reads custom instructions from.

---

## How it works

1. Reads your dependencies, Dockerfiles, CI configs, infra files
2. Fetches the latest alerts from [cyberowlai.com/alerts.json](https://cyberowlai.com/alerts.json)
3. Shows only what matches your stack + critical zero-days

---

## API

```
GET https://cyberowlai.com/alerts.json
```

JSON feed with ~90 alerts from 10 sources, updated daily. Use it to build your own integrations.
