# ENDGAME Community Plugins

Community plugins for the [ENDGAME C2](https://github.com/endgamec2framework/endgame) framework.

## Installation

### From the C2 GUI (recommended)

Open **Settings → Plugins → Marketplace**, find the plugin and click **⬇ Instalar**.

### Manual

```bash
cp -r <plugin-id>/ /path/to/endgame/data/plugins/<plugin-id>/
chmod 700 data/plugins/<plugin-id>/ data/plugins/<plugin-id>/run.py
chmod 600 data/plugins/<plugin-id>/plugin.json
```

Then reload modules from Settings → Plugins → ⟳ Reload modules.

## Available plugins

| Plugin | Type | Description |
|---|---|---|
| [ad-scan](ad-scan/) | collector | AD enumeration via LDAP (users, Kerberoast, AS-REP, trusts) |
| [ad-analyzer](ad-analyzer/) | analyzer | BloodHound graph analysis for quick wins |
| [agent-report](agent-report/) | reporter | Agent inventory with privilege summary |

## Plugin structure

Each plugin is a directory with:

```
<plugin-id>/
├── plugin.json   ← manifest (id, name, version, type, permissions, input_fields…)
└── run.py        ← entrypoint (reads JSON from stdin, writes JSON to stdout)
```

### Manifest fields

```json
{
  "id": "my-plugin",
  "name": "My Plugin",
  "version": "0.1.0",
  "api_version": 1,
  "type": "collector",
  "description": "...",
  "license": "MIT",
  "entrypoint": "run.py",
  "permissions": ["tenant.read", "report.write"],
  "max_runtime_seconds": 60,
  "ui": { "tab": "My Plugin" },
  "input_fields": [
    {"id": "target", "label": "Target", "type": "text", "required": true}
  ]
}
```

**Types**: `collector`, `analyzer`, `reporter`, `connector`, `ui`

**Permissions**: `data.read`, `tenant.read`, `graph.read`, `report.write`, `agent.context.read`

### Protocol

The plugin reads one JSON line from stdin:

```json
{
  "protocol_version": 1,
  "run_id": "...",
  "module_id": "my-plugin",
  "input": {"target": "10.10.10.1"},
  "host_context": { ... }
}
```

And writes one JSON line to stdout:

```json
{
  "protocol_version": 1,
  "run_id": "...",
  "module_id": "my-plugin",
  "ok": true,
  "result": {
    "schema_version": 1,
    "module_id": "my-plugin",
    "summary": "...",
    "findings": [...],
    "entities": [...],
    "metadata": {}
  }
}
```

## Contributing

1. Fork this repo
2. Create your plugin directory with `plugin.json` + entrypoint
3. Add an entry to `registry.json`
4. Open a PR

Plugin entrypoints can be written in any language — the C2 spawns them as child processes.
