# radius-rs

[![CI](https://github.com/Razafindriatsara/radius-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/Razafindriatsara/radius-rs/actions/workflows/ci.yml)
![Rust](https://img.shields.io/badge/rust-2024-orange)
![License: MIT](https://img.shields.io/badge/license-MIT-blue)

Ein schlanker, sicherheitsorientierter RADIUS-Server in Rust.
Er implementiert Authentifizierung (RFC 2865), Accounting (RFC 2866), Message-Authenticator (RFC 3579), Status-Server (RFC 5997) und die Erkennung doppelter Requests (RFC 5080).

> Portfolioprojekt: Netzwerkprotokoll nach RFC, binäres Paketformat, Protokoll-Kryptografie, Async-Rust, SQLite.
> Getestet unter Linux, Windows und macOS.

## Was ist RADIUS?

RADIUS ist das Protokoll, mit dem Access Points, Switches und VPN-Gateways (der *NAS*) einen zentralen Server fragen: „Darf sich dieser Benutzer anmelden?“ Danach melden sie, wie lange die Sitzung lief und wie viele Daten übertragen wurden. Es steckt hinter WPA2-Enterprise im Firmen-WLAN, hinter vielen VPN-Zugängen und hinter Internetanschlüssen von Providern.

## Features

- [x] Paket-Codec für Header und Attribute (TLV), robust gegen fehlerhafte Eingaben
- [x] PAP-Authentifizierung mit Argon2-gehashten Passwörtern
- [x] Response Authenticator und Message-Authenticator (HMAC-MD5)
- [x] **BlastRADIUS-Schutz** (CVE-2024-3596): Message-Authenticator wird verlangt und in jeder Antwort als erstes Attribut gesendet
- [x] **Accounting in SQLite**: Start, Interim-Update, Stop, Accounting-On/Off, 64-Bit-Zähler über Gigawords
- [x] **Erkennung doppelter Requests**: Wiederholungen bekommen die gespeicherte Antwort, ohne erneute Prüfung
- [x] Status-Server für Health Checks
- [x] Pro-Client Shared Secrets, unbekannte Clients werden verworfen
- [x] Argon2 und SQLite laufen im Blocking-Threadpool und bremsen den Async-Server nicht aus
- [x] Eigener Testclient `radius-client`, der Antworten kryptografisch prüft
- [x] 22 automatische Tests, darunter Testvektoren aus RFC 2865 und Property-Tests
- [x] CI auf GitHub Actions: Tests auf drei Betriebssystemen, `rustfmt`, `clippy -D warnings`

### Mögliche Erweiterungen

- [ ] RadSec (RADIUS über TLS, RFC 6614) mit `rustls`
- [ ] EAP (PEAP/EAP-TLS) für WPA2-Enterprise
- [ ] CoA/Disconnect (RFC 5176), um aktive Sessions zu trennen
- [ ] Prometheus-Metriken
- [ ] Fuzzing mit `cargo-fuzz`

## Architektur

```
               UDP 1812 (Auth) / 1813 (Accounting)
NAS ─────────────────────────────────────────────► server.rs
                                                   │  Client-Whitelist
                                                   │  dedup.rs: Duplikat? → gespeicherte Antwort
                                                   ▼
                                             handler.rs   (Protokoll-Logik, ohne Netzwerk testbar)
                              ┌──────────────┬────┴─────────┬──────────────┐
                          packet.rs      crypto.rs        auth.rs      accounting.rs
                          (Codec)        (MD5/HMAC)       (Argon2)     (SQLite)
```

`handler.rs` arbeitet nur mit Bytes rein und Bytes raus. Dadurch lässt sich die gesamte Protokoll-Logik ohne Sockets testen. Das Benutzer-Backend steckt hinter dem Trait `Authenticator` und lässt sich gegen SQL oder LDAP austauschen.

## Schnellstart

```bash
cp config.example.toml config.toml     # PowerShell: Copy-Item config.example.toml config.toml
cargo run -- config.toml
```

Neuen Benutzer anlegen: Hash erzeugen und in `config.toml` eintragen.

```bash
cargo run -- hash-password MeinPasswort
```

### Testclient

Im Projekt ist ein eigener Client enthalten. Er prüft auch Response Authenticator und Message-Authenticator der Antwort. Exit-Code 0 bedeutet Erfolg, 1 Ablehnung oder keine Antwort.

```bash
# Anmeldung
cargo run --bin radius-client -- martin geheim123          # Access-Accept
cargo run --bin radius-client -- martin falsch             # Access-Reject
cargo run --bin radius-client -- status                    # Health Check

# Accounting
cargo run --bin radius-client -- acct start   martin sess-001
cargo run --bin radius-client -- acct interim martin sess-001
cargo run --bin radius-client -- acct stop    martin sess-001

# Gespeicherte Sessions anzeigen
cargo run -- sessions
```

Beispielausgabe von `sessions`:

```
Session        Benutzer     NAS            Status       Dauer     Download       Upload  Ende
sess-001       martin       radius-client  beendet    0:11:41      66.0 MB       8.3 MB  User-Request
sess-002       martin       radius-client  aktiv      0:00:00          0 B          0 B
```

### Mit FreeRADIUS-Werkzeugen

```bash
echo -e 'User-Name=martin\nUser-Password=geheim123\nMessage-Authenticator=0x00' \
  | radclient -x 127.0.0.1:1812 auth testing123
```

Für das ältere `radtest` (ohne Message-Authenticator) in der Konfiguration `require_message_authenticator = false` setzen. Mit Wireshark (Filter `radius`) lassen sich die Pakete dekodiert ansehen.

## Tests

```bash
cargo test
```

| Bereich | Was geprüft wird |
|---|---|
| `packet` | Roundtrip, ungültige Längen, Property-Tests: der Parser panickt bei keiner Eingabe |
| `crypto` | Testvektoren aus RFC 2865 Abschnitt 7.1, lange Passwörter, Message-Authenticator |
| `auth` | Argon2: richtiges und falsches Passwort, unbekannter Benutzer |
| `accounting` | Lebenszyklus einer Session, Stop ohne Start, Accounting-Off, Zähler über 4 GiB |
| `dedup` | Neu, in Bearbeitung, gespeichert, Ablauf, Speichergrenze |
| End-to-End | Echtes UDP: Accept, Reject, Verwerfen, Duplikat (Passwort wird nur einmal geprüft), Accounting landet in der DB |

## Design-Entscheidungen

- **Warum MD5?** Das schreibt das RADIUS-Protokoll vor. Echter Transportschutz kommt mit RadSec (TLS).
- **Warum nur PAP und nicht CHAP?** CHAP braucht das Klartext-Passwort auf dem Server. PAP erlaubt Argon2-Hashes. Für ein sicheres Backend ist PAP über einen geschützten Kanal die bessere Wahl.
- **Warum werden ungültige Pakete still verworfen?** RFC 2865 schreibt das vor. Eine Fehlermeldung würde Angreifern Informationen liefern.
- **Warum ein Duplikat-Cache?** Geht eine Antwort verloren, wiederholt der NAS den Request. Ohne Cache würde Accounting doppelt gezählt und Argon2 unnötig CPU verbrauchen. Schlüssel ist (IP, Port, Identifier, Request Authenticator), wie RFC 5080 empfiehlt. Der Cache ist in der Größe begrenzt, damit eine Flut von Requests keinen Speicher frisst.
- **Warum keine Antwort, wenn die Datenbank ausfällt?** RFC 2866: Der Server bestätigt Accounting erst, wenn es gespeichert ist. Ohne Antwort wiederholt der NAS den Request später, und nichts geht verloren.
- **Warum `spawn_blocking`?** Argon2 ist absichtlich rechenintensiv, SQLite blockiert. Beides würde sonst die Async-Worker von tokio anhalten.
- **Konstanter Zeitvergleich** bei Authenticators, damit Timing nichts verrät.

## Referenzen

- RFC 2865: RADIUS
- RFC 2866: RADIUS Accounting
- RFC 3579: RADIUS Support for EAP (Message-Authenticator)
- RFC 5080: Common RADIUS Implementation Issues (Duplikaterkennung)
- RFC 5997: Status-Server
- RFC 6614: RADIUS over TLS (RadSec)
- CVE-2024-3596: BlastRADIUS

## Lizenz

MIT, siehe [LICENSE](LICENSE).
