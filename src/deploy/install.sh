#!/bin/sh
# Retired entry point: never create accounts, tokens, certificates or firewall rules.
printf '%s\n' 'LEGACY_INSTALLER_RETIRED: automatic legacy deployment is disabled.' 'Use deploy/render.py and the gated deployment procedure; nothing was installed.' >&2
exit 2
