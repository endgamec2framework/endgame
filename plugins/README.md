# ENDGAME module SDK

ENDGAME modules are external processes installed under the server's
`data/plugins/<module-id>/` directory. A module directory must contain a
`plugin.json` manifest and its executable entrypoint.

The host starts the entrypoint with:

```text
<entrypoint> --endgame-plugin-stdio
```

It sends exactly one JSON request on stdin and expects exactly one JSON
response on stdout. Logs belong on stderr. When a permission is declared, the
host may include a bounded `host_context` object in the request:

- `data.read`: sanitized agent inventory (never AES keys, credentials, or raw results)
- `agent.context.read`: the sanitized agent selected by `input.agent_id`
- `graph.read`: the BloodHound nodes and edges currently stored by the host
- `tenant.read`: the local-scope marker
- `report.write`: normalized output is accepted and recorded in run history

The host context is a snapshot for one run; modules do not get a live API or a
database handle.

Example manifest:

```json
{
  "id": "example-analyzer",
  "name": "Example analyzer",
  "version": "0.1.0",
  "api_version": 1,
  "type": "analyzer",
  "license": "MIT",
  "entrypoint": "example-analyzer",
  "permissions": ["data.read", "report.write"]
}
```

The first host API only allows read-oriented permissions. Modules cannot
access the SQLite database, agent keys, transport sockets, inherited C2
environment variables, or arbitrary agent tasking. The host enforces runtime,
input, host-context, and output limits. Modules are still native processes, so
only install reviewed modules under the server account; OS sandboxing and
signature verification remain future work.

The request's `host_context` is omitted when no declared permission needs host
data. The response must be a `plugins.RunResponse` with the matching `run_id`,
`module_id`, and `protocol_version`. Its `result` must use
`schema_version: 1` and the common schema for findings, entities,
relationships, and artifacts. This gives the UI and future graph, report, and
AI integrations one stable interchange format; module output is recorded in
the plugin-run history and is not silently merged into core C2 data.

Community modules should be installed manually and pinned to a reviewed
version. Installation, signature verification, a marketplace, and agent
capability modules are intentionally deferred until the host API is stable.
