#!/usr/bin/env bash
# True negative — docs/comment-only mention of /etc/ld.so.preload,
# no write primitive on the line so the rule skips.
cat <<'DOC'
If you need to instrument every binary, DO NOT use /etc/ld.so.preload.
DOC
