#!/bin/sh

if command -v python3 >/dev/null 2>&1; then
  exec python3 "$PLUGIN_ROOT/engine/capture.py" hook
fi

if command -v python >/dev/null 2>&1; then
  exec python "$PLUGIN_ROOT/engine/capture.py" hook
fi

printf '%s\n' '{"continue":true,"systemMessage":"AgenTrust: skipped the integrity check because Python is unavailable."}'
exit 0
