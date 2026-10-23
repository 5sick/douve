# Changelog

## v0.3.1

Security update — upgrade recommended for every install (the entry serves HTTP/2 to the internet).

- Agents are built with Go 1.26.10, fixing Go standard library vulnerabilities reachable from
  Douve code: HTTP/2 server memory exhaustion and crash, HTTP/1 connection desynchronization,
  MIME header memory limit bypass, and others (GO-2026-6603, 6605, 6607, 6608, 6610, 6611, 6612,
  6613, 6617, 6809).
- Threat model: a compromised Hub can expose, through the agent tunnel, ports that listen only on
  127.0.0.1 of a managed server.

## v0.3.0

Upgrading from v0.2.0: replace `douve-hub` and restart (take a `douve-hub backup` first); the
database migrates by itself (schema v14 → v20) and agents update themselves. Existing services stay
public exactly as before; the internal path is off until you turn it on.

**Trust: the Hub is no longer all-powerful**
- Signed releases: `SHA256SUMS` is signed with the release key, and agents only replace themselves
  with a signed, not-older release — a compromised Hub can't push its own agent binary.
- Opening a terminal requires a passkey signature for *that server, that account, now*. The agent
  verifies it against its own terminal trust list; changes to the list need an admin passkey
  signature (approve on the Servers page). `douve-agent terminal-trust show|reset`.
- Roles: admin / operator (granted servers only) / app (granted apps only). Every API is checked on
  the Hub, unlisted APIs are admin-only, and the entry asks the Hub per app.
- Audit log hash chain with daily verification (`douve-hub audit-verify`) and signed export to a
  webhook.
- Fuzzing for the WebAuthn/CBOR/JWT/config parsers (Hub: libFuzzer + ASan/UBSan) and agent parsers
  (Go); fixes for what it found, including a pre-auth Hub crash on malformed JSON.
- `SECURITY.md` now has a threat model: what each kind of attacker can and can't do.

**Two paths per app: internal and public**
- Each service can be internal (only from your registered devices), public (the entry's domain), or
  both. Internal-only services don't exist on the public entry.
- Internal path = WireGuard run by the entry agent itself (userspace WireGuard + netstack; no kernel
  interface, forwarding or firewall changes). Add a phone or PC on the Account page (QR or config
  file). While connected, apps open at their usual address with no sign-in page, by that person's
  permissions. Needs one UDP port (default 51821).

**Servers**
- Security checklist (Security page): SSH password and root login, `Match` blocks re-enabling
  passwords, automatic security updates, time sync, pending reboot, internet-facing ports. "Fix" is
  signed with a passkey and verified by the agent like the terminal; SSH changes are checked with
  `sshd -t`/`sshd -T` and rolled back on failure.
- File upload/download from the terminal page (100 MB), as the terminal account, each transfer
  signed; uploads are moved into place only if size and SHA-256 match what was signed.
- Connection check (server page): public IP, NAT type (STUN), CGNAT / double router, which path
  Douve uses (entry / direct / tunnel), and a test from another server whether 22/80/443 are
  reachable from outside. Hourly, with alerts when SSH becomes reachable or the entry stops
  answering on 443.

**Smaller**
- `douve-hub service-add --redirect` for old addresses after a move.
- Failing systemd units started by a timer (e.g. `dnf-makecache`) alert only after 2 hours.
- Phones: the Account page is in the bottom menu.
- SELinux servers: commands run outside the agent sandbox use socket pairs instead of pipes
  (`systemd-run --pipe` with pipes is refused).
