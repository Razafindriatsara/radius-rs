# Changelog

Alle nennenswerten Änderungen an diesem Projekt. Format nach [Keep a Changelog](https://keepachangelog.com/de/1.1.0/), Versionierung nach [Semantic Versioning](https://semver.org/lang/de/).

## [Unreleased]

### Neu
- Eingangsportal `radius-portal` (Captive Portal) mit App-Oberfläche für Smartphones: Anmeldung, Statusseite mit Countdown bis zum Session-Timeout, Abmeldung, Dunkelmodus, installierbar als Web-App
- Accounting Start/Stop aus dem Portal, automatisches Sitzungsende bei Session-Timeout
- Sperre nach wiederholten Fehlversuchen pro IP, Content-Security-Policy, sichere Sitzungs-Cookies
- Asynchroner RADIUS-Client als Bibliotheksmodul `client`
- Portal im Docker-Image und in `docker-compose.yml`, in den Release-Paketen und in der CI

## [0.1.0] – 2026-11-24

Erste veröffentlichte Version.

### Protokoll
- RADIUS-Authentifizierung nach RFC 2865 mit PAP, Passwörter als Argon2-Hashes
- Response Authenticator und Message-Authenticator (HMAC-MD5, RFC 3579)
- Schutz gegen BlastRADIUS (CVE-2024-3596): Message-Authenticator wird verlangt und in jeder Antwort als erstes Attribut gesendet
- Status-Server für Health Checks (RFC 5997)
- Accounting nach RFC 2866 (Start, Interim-Update, Stop, Accounting-On/Off) mit Speicherung in SQLite und 64-Bit-Zählern über Gigawords
- Erkennung doppelter Requests nach RFC 5080

### Betrieb
- NAS-Clients als einzelne IP oder Netz (CIDR, IPv4/IPv6)
- `radius-rs sessions` zeigt gespeicherte Accounting-Sessions als Tabelle
- `radius-rs hash-password` erzeugt Argon2-Hashes für die Konfiguration
- Testclient `radius-client` für Anmeldung, Status und Accounting, prüft Antworten kryptografisch
- Docker-Image für linux/amd64 und linux/arm64, läuft ohne Root, mit Compose-Demo

### Qualität
- 28 automatische Tests, darunter Testvektoren aus RFC 2865 und Property-Tests
- 15 Interoperabilitätstests gegen `radclient` von FreeRADIUS
- CI auf Linux, Windows und macOS

[0.1.0]: https://github.com/Razafindriatsara/radius-rs/releases/tag/v0.1.0
