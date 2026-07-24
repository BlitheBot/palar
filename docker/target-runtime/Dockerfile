# Runtime image for `mcpguard live` stdio targets. Deliberately minimal: it
# provides only a Node.js interpreter. Every target-specific dependency
# (the MCP SDK, zod, tsx, whatever the target itself needs) comes from the
# target directory's own node_modules, bind-mounted read-only at /target by
# src/live/sandbox.ts — nothing target-specific is baked into this image.
#
# Node-only for now: this matches every target mcpguard currently exercises
# (the vuln-server fixture and, generally, MCP servers declared with a
# "node"/"npx" command). A target declaring a non-Node command will fail
# inside this image — that's a named limitation, not a silent one.
FROM node:20-slim
