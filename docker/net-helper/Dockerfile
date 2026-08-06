# Short-lived privileged helper used only to install/remove the per-scan
# MCPG-<id> chain and its two jump rules (DOCKER-USER for forwarded
# traffic, INPUT for host-destined traffic), and to sweep up ones orphaned
# by a run that never reached teardown (see src/live/sandbox.ts).
# Run with --network host so its iptables calls land in the same netfilter
# state as the Docker daemon's own DOCKER-USER chain — on native Linux
# Engine that's the host's netns directly; on Docker Desktop it's the
# Desktop VM's netns, which --network host inside a container also reaches.
# Packaged as an image (rather than shelling out to a host-installed
# `iptables`) so palar only ever needs to assume Docker is installed,
# not any particular host package.
FROM alpine:3.20
RUN apk add --no-cache iptables
