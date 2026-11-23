# radius-rs

Ein schlanker, sicherheitsorientierter RADIUS-Server in Rust.
Implementiert Authentifizierung (RFC 2865), Accounting (RFC 2866), Message-Authenticator (RFC 3579) und Status-Server (RFC 5997).

> Portfolioprojekt: Netzwerkprotokoll nach RFC, binäres Paketformat, Protokoll-Kryptografie, Async-Rust.

## Features

- [x] Paket-Codec für Header und Attribute (TLV), robust gegen fehlerhafte Eingaben
- [x] PAP-Authentifizierung mit Argon2-gehashten Passwörtern
- [x] Response Authenticator und Message-Authenticator (HMAC-MD5)
- [x] **BlastRADIUS-Schutz:** Message-Authenticator wird verlangt und in jeder Antwort als erstes Attribut gesendet
- [x] Status-Server für Health Checks
- [x] Accounting-Requests (Start/Stop/Interim) prüfen und beantworten
- [x] Pro-Client Shared Secrets, unbekannte Clients werden verworfen
- [x] Property-Tests: der Parser panickt bei keiner Eingabe
- [ ] Accounting-Sessions in SQLite speichern
- [ ] Duplikaterkennung (Identifier-Cache) und Rate Limiting
- [ ] Fuzzing mit `cargo-fuzz`
- [ ] Prometheus-Metriken
- [ ] RadSec (RADIUS über TLS, RFC 6614) mit `rustls`
- [ ] CoA/Disconnect (RFC 5176)
- [ ] EAP (PEAP/EAP-TLS) für WPA2-Enterprise

## Architektur

```
            UDP 1812/1813
NAS ──────────────────────► server.rs   (tokio, Client-Whitelist)
                                │
                                ▼
                           handler.rs   (Protokoll-Logik, ohne Netzwerk testbar)
                           │        │
                  packet.rs          crypto.rs        auth.rs
                  (Codec)            (MD5/HMAC)       (Trait Authenticator, Argon2)
```

`handler.rs` arbeitet nur mit Bytes rein und Bytes raus. Dadurch lässt sich die gesamte Protokoll-Logik ohne Sockets testen, und das Backend (`Authenticator`-Trait) ist austauschbar, zum Beispiel gegen SQL oder LDAP.

## Schnellstart

```bash
cp config.example.toml config.toml
cargo run --release -- config.toml
```

Test mit FreeRADIUS-Werkzeugen (`sudo apt install freeradius-utils`):

```bash
# radclient mit Message-Authenticator (empfohlen)
echo -e 'User-Name=martin\nUser-Password=geheim123\nMessage-Authenticator=0x00' \
  | radclient -x 127.0.0.1:1812 auth testing123

# Status-Server
echo 'Message-Authenticator=0x00' | radclient -x 127.0.0.1:1812 status testing123
```

Für das ältere `radtest` (ohne Message-Authenticator) in der Konfiguration `require_message_authenticator = false` setzen.

Mit Wireshark (Filter `radius`) lassen sich die Pakete dekodiert ansehen.

## Tests

```bash
cargo test
```

- Testvektoren aus **RFC 2865 Abschnitt 7.1** (PAP-Entschlüsselung und Response Authenticator)
- Property-Tests für den Parser (`proptest`)
- End-to-End-Test über echtes UDP: Accept, Reject, Verwerfen ohne Message-Authenticator, Robustheit gegen Müll

## Design-Entscheidungen

- **Warum MD5?** Das schreibt das RADIUS-Protokoll vor. Echter Transportschutz kommt mit RadSec (TLS).
- **Warum nur PAP und nicht CHAP?** CHAP braucht das Klartext-Passwort auf dem Server. PAP erlaubt Argon2-Hashes. Für ein sicheres Backend ist PAP über einen geschützten Kanal die bessere Wahl.
- **Warum werden ungültige Pakete still verworfen?** RFC 2865 schreibt das vor. Eine Fehlermeldung würde Angreifern Informationen liefern.
- **Konstanter Zeitvergleich** bei Authenticators, damit Timing nichts verrät.

## Referenzen

- RFC 2865: RADIUS
- RFC 2866: RADIUS Accounting
- RFC 3579: RADIUS Support for EAP (Message-Authenticator)
- RFC 5997: Status-Server
- RFC 6614: RADIUS over TLS (RadSec)
- CVE-2024-3596: BlastRADIUS

## Lizenz

MIT
