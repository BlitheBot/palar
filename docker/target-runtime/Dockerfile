# Runtime image for `palar live` stdio targets. Deliberately minimal: it
# provides only a Node.js interpreter. Every target-specific dependency
# (the MCP SDK, zod, tsx, whatever the target itself needs) comes from the
# target directory's own node_modules, bind-mounted read-only at /target by
# src/live/sandbox.ts — nothing target-specific is baked into this image.
#
# Node-only for now: this matches every target palar currently exercises
# (the vuln-server fixture and, generally, MCP servers declared with a
# "node"/"npx" command). A target declaring a non-Node command will fail
# inside this image — that's a named limitation, not a silent one.
FROM node:20-slim

# The command-injection oracle's callback probe shells out to `curl` from
# inside this container to reach the scan's oracle listener. node:20-slim
# ships neither curl nor wget, so without this the injection succeeds but the
# callback binary is missing (curl exits 127) and the probe reports
# UNCONFIRMED. Keep the layer minimal and clean the apt lists in the same
# layer so nothing is cached into the image.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*
