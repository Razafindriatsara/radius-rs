#!/usr/bin/env bash
# Rauchtest der Admin-Oberfläche gegen die Compose-Umgebung:
# Portal-Anmeldung → Admin-Anmeldung → Trennen per Disconnect-Request (RFC 5176).
set -euo pipefail
ADMIN=${ADMIN:-http://127.0.0.1:8090}
PORTAL=${PORTAL:-http://127.0.0.1:8080}
PW=${ADMIN_PASSWORD:-admin-demo}
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

for _ in $(seq 1 20); do curl -fsS -o /dev/null "$ADMIN/login" && break; sleep 1; done

echo "== Falsches Admin-Passwort"
code=$(curl -s -o /dev/null -w '%{http_code}' -d 'password=falsch' "$ADMIN/login")
test "$code" = "401"

echo "== Admin anmelden"
code=$(curl -s -o /dev/null -w '%{http_code}' -c "$tmp/admin" --data-urlencode "password=$PW" "$ADMIN/login")
test "$code" = "303"
csrf=$(curl -fsS -b "$tmp/admin" "$ADMIN/" | grep -o 'name="csrf" value="[0-9a-f]\{32\}"' | head -1 | grep -o '[0-9a-f]\{32\}')
test -n "$csrf"

echo "== Benutzer anlegen"
user="smoke-$RANDOM"
loc=$(curl -s -o /dev/null -w '%{redirect_url}' -b "$tmp/admin" \
  --data-urlencode "csrf=$csrf" --data-urlencode "name=$user" --data-urlencode "password=smoke-geheim" \
  "$ADMIN/users")
case "$loc" in *m=created) ;; *) echo "Anlegen fehlgeschlagen: $loc"; exit 1 ;; esac

echo "== $user meldet sich am Portal an"
code=$(curl -s -o /dev/null -w '%{http_code}' -c "$tmp/guest" -d "username=$user&password=smoke-geheim" "$PORTAL/login")
test "$code" = "303"
code=$(curl -s -o /dev/null -w '%{http_code}' -b "$tmp/guest" "$PORTAL/status")
test "$code" = "200"

# Zeile dieses Benutzers in der Übersicht suchen
curl -fsS -b "$tmp/admin" "$ADMIN/" > "$tmp/dash.html"
row=$(tr -d "\n" < "$tmp/dash.html" | grep -o "<tr><td><strong>$user</strong>.*")
form=${row#*action=\"/sessions/disconnect\"}
sid=${form#*session_id\" value=\"}; sid=${sid%%\"*}
nas=${form#*name=\"nas\" value=\"}; nas=${nas%%\"*}
test -n "$sid" && test -n "$nas"
echo "   Sitzung $sid an $nas"

echo "== Trennen per Disconnect-Request"
loc=$(curl -s -o /dev/null -w '%{redirect_url}' -b "$tmp/admin" \
  --data-urlencode "csrf=$csrf" --data-urlencode "session_id=$sid" --data-urlencode "nas=$nas" \
  "$ADMIN/sessions/disconnect")
echo "   $loc"
case "$loc" in *m=disconnected) ;; *) echo "Trennen fehlgeschlagen"; exit 1 ;; esac

echo "== Portal zeigt die Sitzung nicht mehr an"
code=$(curl -s -o /dev/null -w '%{http_code}' -b "$tmp/guest" "$PORTAL/status")
test "$code" = "303"

echo "== CSV-Export"
curl -fsS -b "$tmp/admin" "$ADMIN/sessions.csv" | grep -q 'Admin-Reset'
echo "Admin-Rauchtest bestanden"
