#!/usr/bin/env bash
# True positive #3 — Docker CLI --net=host (alias form, lethal edge case #1).
docker run --rm \
  --name mcp \
  --net=host \
  mcp/server@sha256:0b3c98f3e41e0c94a2b8d6b47c2c4a1f9c6d4e5b8a7b2c1d3f9e8a7b6c5d4e3f
