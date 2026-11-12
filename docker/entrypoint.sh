#!/bin/sh
# Container entrypoint: initialize a fresh volume, then run GoMTA.
set -eu
umask 027

GOMTA_HOME="${GOMTA_HOME:-/var/lib/gomta}"
CONFIG="${GOMTA_CONFIG:-$GOMTA_HOME/gomta.yaml}"

# set_config replaces a top-level key in the generated YAML file.
set_config() {
	key="$1"
	value="$2"
	[ -n "$value" ] || return 0
	if grep -q "^${key}:" "$CONFIG"; then
		sed -i "s|^${key}:.*|${key}: ${value}|" "$CONFIG"
	else
		printf '\n%s: %s\n' "$key" "$value" >>"$CONFIG"
	fi
}

init_config() {
	if [ -f "$CONFIG" ]; then
		return 0
	fi
	if [ -z "${GOMTA_DOMAINS:-}" ]; then
		echo "gomta: GOMTA_DOMAINS is required on first start (for example: example.com,example.org)" >&2
		exit 1
	fi

	set -- init -dir "$GOMTA_HOME" -domain "$GOMTA_DOMAINS"
	if [ -n "${GOMTA_HOSTNAME:-}" ]; then
		set -- "$@" -hostname "$GOMTA_HOSTNAME"
	fi
	if [ -n "${GOMTA_ADMIN_USER:-}" ]; then
		set -- "$@" -admin-user "$GOMTA_ADMIN_USER"
	fi
	if [ -n "${GOMTA_ADMIN_PASSWORD:-}" ]; then
		set -- "$@" -admin-password "$GOMTA_ADMIN_PASSWORD"
	fi
	if [ -n "${GOMTA_DKIM_SELECTOR:-}" ]; then
		set -- "$@" -selector "$GOMTA_DKIM_SELECTOR"
	fi
	if [ -n "${GOMTA_DKIM_BITS:-}" ]; then
		set -- "$@" -bits "$GOMTA_DKIM_BITS"
	fi

	gomta "$@"
}

# Allow `docker run ... gomta check` and other commands without starting the
# server. The default command is `serve`.
if [ "$#" -gt 0 ] && [ "$1" != "serve" ]; then
	exec gomta "$@"
fi
if [ "$#" -gt 0 ]; then
	shift
fi

init_config

# Optional overrides for container deployments. Edit the YAML for anything more
# involved (listeners, routing, TLS, queue).
set_config "plugins_file" "${GOMTA_PLUGINS_FILE:-}"
set_config "domains_file" "${GOMTA_DOMAINS_FILE:-}"
set_config "users_file" "${GOMTA_USERS_FILE:-}"
set_config "status_addr" "${GOMTA_STATUS_ADDR:-}"

exec gomta serve -config "$CONFIG" "$@"
