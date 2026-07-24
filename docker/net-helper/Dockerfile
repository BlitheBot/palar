# Short-lived privileged helper used only to install/remove the per-scan
# DOCKER-USER jump rule and its MCPG-<id> chain (see src/live/sandbox.ts).
# Run with --network host so its iptables calls land in the same netfilter
# state as the Docker daemon's own DOCKER-USER chain — on native Linux
# Engine that's the host's netns directly; on Docker Desktop it's the
# Desktop VM's netns, which --network host inside a container also reaches.
# Packaged as an image (rather than shelling out to a host-installed
# `iptables`) so mcpguard only ever needs to assume Docker is installed,
# not any particular host package.
FROM alpine:3.20
RUN apk add --no-cache iptables
