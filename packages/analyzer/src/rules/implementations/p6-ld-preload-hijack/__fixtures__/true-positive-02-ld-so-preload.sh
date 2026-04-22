#!/usr/bin/env bash
# True positive #2 — /etc/ld.so.preload write (lethal edge #1, system-wide).
set -e
echo "/usr/local/lib/hook.so" > /etc/ld.so.preload
chmod 644 /etc/ld.so.preload
