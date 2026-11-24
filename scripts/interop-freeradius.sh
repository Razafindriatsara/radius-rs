#!/usr/bin/env bash
# Interoperabilitätstest: radius-rs gegen radclient aus FreeRADIUS.
#
# Startet einen Server mit Testkonfiguration auf freien Ports, schickt
# Requests mit radclient und prüft die Antworten. Benötigt: cargo, radclient
# (Debian/Ubuntu: sudo apt install freeradius-utils).
#
# Aufruf:  ./scripts/interop-freeradius.sh            (baut und startet den Server selbst)
#          SERVER=127.0.0.1 AUTH_PORT=1812 ACCT_PORT=1813 SKIP_START=1 ./scripts/interop-freeradius.sh
#                                                       (prüft einen schon laufenden Server, z.B. im Docker-Container)
set -euo pipefail

SERVER="${SERVER:-127.0.0.1}"
AUTH_PORT="${AUTH_PORT:-18120}"
ACCT_PORT="${ACCT_PORT:-18130}"
SECRET="${SECRET:-testing123}"

command -v radclient >/dev/null || { echo "radclient fehlt: sudo apt install freeradius-utils" >&2; exit 2; }

WORK="$(mktemp -d)"
SERVER_PID=""
cleanup() {
    if [[ -n "$SERVER_PID" ]]; then kill "$SERVER_PID" 2>/dev/null || true; fi
    rm -rf "$WORK"
}
trap cleanup EXIT

PASS=0
FAIL=0
ok()   { echo "  ✔ $1"; PASS=$((PASS + 1)); }
indent() { while IFS= read -r line; do echo "      $line"; done; }
fail() { echo "  ✘ $1"; FAIL=$((FAIL + 1)); }

# Schickt Attribute an radclient und prüft, ob die Antwort das Muster enthält.
#   expect <Beschreibung> <Befehl: auth|acct|status> <Port> <Muster> <Attribute...>
expect() {
    local desc="$1" cmd="$2" port="$3" pattern="$4"; shift 4
    local out
    out="$(printf '%s\n' "$@" | radclient -x -r 1 -t 2 "$SERVER:$port" "$cmd" "$SECRET" 2>&1 || true)"
    if grep -q -- "$pattern" <<<"$out"; then ok "$desc"; else fail "$desc"; indent <<<"$out"; fi
}

# Erwartet KEINE Antwort (Server muss das Paket verwerfen).
expect_drop() {
    local desc="$1" cmd="$2" port="$3" secret="$4"; shift 4
    local out
    out="$(printf '%s\n' "$@" | radclient -x -r 1 -t 2 "$SERVER:$port" "$cmd" "$secret" 2>&1 || true)"
    if grep -q "^Received" <<<"$out"; then fail "$desc"; indent <<<"$out"; else ok "$desc"; fi
}

if [[ -z "${SKIP_START:-}" ]]; then
    echo "▶ Baue radius-rs ..."
    cargo build --quiet --bin radius-rs
    BIN="$(cargo metadata --format-version 1 --no-deps | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')/debug/radius-rs"

    HASH="$("$BIN" hash-password geheim123)"
    LONG_PW="ein-sehr-langes-passwort-ueber-mehrere-md5-bloecke-1234"
    HASH_LONG="$("$BIN" hash-password "$LONG_PW")"
    cat >"$WORK/config.toml" <<EOF
[server]
auth_listen = "$SERVER:$AUTH_PORT"
acct_listen = "$SERVER:$ACCT_PORT"
require_message_authenticator = true

[[clients]]
name = "interop"
address = "127.0.0.0/8"
secret = "$SECRET"

[[users]]
name = "martin"
password_hash = "$HASH"
session_timeout = 3600
reply_message = "Willkommen bei radius-rs"

[[users]]
name = "langpw"
password_hash = "$HASH_LONG"

[accounting]
database = "$WORK/accounting.db"
EOF

    echo "▶ Starte Server auf $SERVER:$AUTH_PORT / $ACCT_PORT ..."
    RUST_LOG=warn "$BIN" "$WORK/config.toml" >"$WORK/server.log" 2>&1 &
    SERVER_PID=$!
    for _ in $(seq 1 50); do
        grep -q "lausche.*$ACCT_PORT" "$WORK/server.log" 2>/dev/null && break
        sleep 0.1
    done
fi

echo "▶ Access-Request (PAP)"
expect "richtiges Passwort → Access-Accept" auth "$AUTH_PORT" "Received Access-Accept" \
    'User-Name = "martin"' 'User-Password = "geheim123"' 'Message-Authenticator = 0x00'
expect "Antwort enthält Session-Timeout" auth "$AUTH_PORT" "Session-Timeout = 3600" \
    'User-Name = "martin"' 'User-Password = "geheim123"' 'Message-Authenticator = 0x00'
expect "Antwort enthält Reply-Message" auth "$AUTH_PORT" 'Reply-Message = "Willkommen bei radius-rs"' \
    'User-Name = "martin"' 'User-Password = "geheim123"' 'Message-Authenticator = 0x00'
expect "falsches Passwort → Access-Reject" auth "$AUTH_PORT" "Received Access-Reject" \
    'User-Name = "martin"' 'User-Password = "falsch"' 'Message-Authenticator = 0x00'
expect "unbekannter Benutzer → Access-Reject" auth "$AUTH_PORT" "Received Access-Reject" \
    'User-Name = "niemand"' 'User-Password = "egal"' 'Message-Authenticator = 0x00'
if [[ -z "${SKIP_START:-}" ]]; then
    expect "Passwort über 4 MD5-Blöcke (54 Byte) korrekt entschlüsselt" auth "$AUTH_PORT" "Received Access-Accept" \
        'User-Name = "langpw"' "User-Password = \"$LONG_PW\"" 'Message-Authenticator = 0x00'
fi

echo "▶ Sicherheit"
# radclient ab 3.2.5 hängt den Message-Authenticator immer selbst an (BlastRADIUS-Fix),
# Requests OHNE ihn lassen sich damit nicht erzeugen. Diesen Fall prüft tests/end_to_end.rs.
expect "Antwort trägt Message-Authenticator (von radclient geprüft)" auth "$AUTH_PORT" "Message-Authenticator = 0x" \
    'User-Name = "martin"' 'User-Password = "geheim123"' 'Message-Authenticator = 0x00'
expect_drop "falsches Shared Secret → verworfen" auth "$AUTH_PORT" "falsches-secret" \
    'User-Name = "martin"' 'User-Password = "geheim123"' 'Message-Authenticator = 0x00'

echo "▶ Status-Server (RFC 5997)"
expect "Status-Server → Antwort" status "$AUTH_PORT" "Received Access-Accept" \
    'Message-Authenticator = 0x00'

echo "▶ Accounting (RFC 2866)"
expect "Start → Accounting-Response" acct "$ACCT_PORT" "Received Accounting-Response" \
    'User-Name = "martin"' 'Acct-Status-Type = Start' 'Acct-Session-Id = "interop-1"' 'NAS-Identifier = "ci"'
expect "Interim-Update → Accounting-Response" acct "$ACCT_PORT" "Received Accounting-Response" \
    'User-Name = "martin"' 'Acct-Status-Type = Interim-Update' 'Acct-Session-Id = "interop-1"' 'NAS-Identifier = "ci"' \
    'Acct-Session-Time = 60' 'Acct-Input-Octets = 1000' 'Acct-Output-Octets = 2000'
expect "Stop → Accounting-Response" acct "$ACCT_PORT" "Received Accounting-Response" \
    'User-Name = "martin"' 'Acct-Status-Type = Stop' 'Acct-Session-Id = "interop-1"' 'NAS-Identifier = "ci"' \
    'Acct-Session-Time = 754' 'Acct-Input-Octets = 1048576' 'Acct-Output-Octets = 52428800' 'Acct-Terminate-Cause = User-Request'
expect_drop "Accounting mit falschem Secret → verworfen" acct "$ACCT_PORT" "falsches-secret" \
    'User-Name = "martin"' 'Acct-Status-Type = Start' 'Acct-Session-Id = "boese"'

if [[ -z "${SKIP_START:-}" ]]; then
    echo "▶ Gespeicherte Session"
    cat >"$WORK/sessions.toml" <<EOF
[server]
[accounting]
database = "$WORK/accounting.db"
EOF
    SESSIONS="$("$BIN" sessions "$WORK/sessions.toml" 2>/dev/null)"
    if grep -qE "interop-1 +martin +ci +beendet +0:12:34 +50\.0 MB +1\.0 MB +User-Request" <<<"$SESSIONS"; then
        ok "Session korrekt gespeichert (Dauer, Download/Upload, Grund)"
    else
        fail "Session korrekt gespeichert"; indent <<<"$SESSIONS"
    fi
    if grep -q "boese" <<<"$SESSIONS"; then fail "verworfener Request wurde trotzdem gespeichert"; else ok "verworfener Request nicht gespeichert"; fi
fi

echo
echo "Ergebnis: $PASS bestanden, $FAIL fehlgeschlagen"
[[ $FAIL -eq 0 ]]
