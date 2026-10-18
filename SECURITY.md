# Security

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub: **Security → Report a vulnerability** on
this repository. Don't open a public issue. You'll get an answer within a week; fixes for confirmed
issues ship as a new release with a note in the release text.

Only the latest release is supported.

## What Douve is — and what that means for trust

Douve is a *front door*: it decides who can reach your apps and it can open a root-capable shell on
every server it manages. Plan your trust accordingly.

- **The Hub is the crown jewel.** Whoever controls the Hub can push routes to every server, sees
  the traffic it relays and can serve a malicious web UI. Two things are deliberately out of its
  reach: agent updates must carry the release signature, and a terminal only opens when a person's
  passkey signed that exact request — the server checks the signature itself (see *Threat model*).
  Treat the Hub server like a password manager.
- **Roles limit what a signed-in person can do, not what an administrator can do.** There are
  three roles: *admin* (everything), *operator* (only the servers granted to them: view, terminal,
  and services that point at that server's own ports) and *app* (only the granted apps, through the
  edge). Checks run on the Hub for every API call — paths not explicitly listed are admin-only — and
  the edge asks the Hub per app (`/auth/verify?service=<id>`). An operator can still do anything a
  root shell on their servers allows, so grant the terminal like you would grant SSH.
- **No external audit yet.** WebAuthn verification, CBOR/COSE parsing and the session layer are
  implemented in this repository (C++), with unit tests and end-to-end tests using a real
  browser's virtual authenticator, and are fuzzed (libFuzzer with ASan/UBSan on the Hub, Go native
  fuzzing on the Agent; see `scripts/fuzz.sh`), but they have not been audited by a third party.

## Design

**Sign-in**
- No passwords anywhere. Passkeys (WebAuthn: ES256, RS256, EdDSA) are the main method; Google
  sign-in is optional and limited to an allow-list.
- The first admin is created with a one-time invitation link printed on the server; the token is
  in the URL fragment so it never reaches server logs or `Referer` headers.
- Login endpoints are rate-limited per IP.

**Sessions**
- Server-side sessions. The database stores only the SHA-256 of the session token.
- Cookie: `HttpOnly; Secure; SameSite=Lax`. Idle timeout 30 days, absolute 90 days.
  Logging in again in the same browser replaces that browser's previous session.
- Sensitive actions require a recent passkey check: 5 minutes for settings, services, invitations
  and recovery codes. Opening a terminal needs a passkey signature for that terminal, every time
  (see *Web terminal*).
- State-changing requests must come from the Hub's own origin (CSRF). Pages use a strict
  Content-Security-Policy (`script-src 'self'`, no inline scripts).

**Recovery codes**
- 10 one-time codes (≈ 59 bits each), stored as hashes, rate-limited like logins. Using one sends
  an alert and is written to the audit log. A recovery session is treated as freshly verified for a
  few minutes so you can register a new passkey.

**The entry (edge) and forward auth**
- The entry agent terminates TLS (Let's Encrypt via ACME) and checks every request to a protected
  app against the Hub. Before forwarding, it strips the `douve_session` cookie and any client-sent
  `X-Douve-User` / `Tailscale-*` headers, then sets `X-Douve-User` itself.
- **Fail closed:** if the Hub can't be reached, protected apps are blocked; apps you marked
  public keep working from the entry's saved routing table.
- HSTS is set on HTTPS responses.

**Internal path (device WireGuard)**
- Services can be *internal* (only from registered devices), *public* (the entry's domain), or
  both. Internal-only services are not in the entry's public routing table, so the public entry
  answers 404 for them.
- Each phone or PC is a WireGuard peer of the entry server. The Hub generates the device key pair,
  shows the configuration (QR or file) once and stores only the public key. The entry agent runs
  WireGuard (wireguard-go) and its TCP/IP stack (gVisor netstack) in-process: no kernel interface,
  no IP forwarding, no firewall changes. A device reaches only the entry's internal address
  (10.201.0.1): DNS (internal service names answer with that address, everything else is forwarded
  to the server's resolver), HTTP→HTTPS, and HTTPS with the entry's certificates. It does not get
  network access to the servers.
- The device address is the identity: WireGuard only accepts packets from the address assigned to
  that device's key. The entry maps it to the Douve user and checks that user's permission for the
  service, then forwards with `X-Douve-User` — no sign-in page. Deleting a device or changing a
  person's role takes effect on the entry immediately. The entry keeps working from its saved
  routing table while the Hub is down.
- Needs one UDP port open to the entry (default 51821). Without a valid device key WireGuard sends
  no response at all.

**Agents**
- Each agent has an Ed25519 identity created at join time; joining uses a one-time token valid for
  15 minutes. Agents keep one outbound WebSocket to the Hub — no inbound ports on servers.
- The agent tunnel (for servers without a direct path) is authenticated with the same key, and the
  entry only forwards to upstreams on the Hub-provided allow-list for that server.
- **Agents don't trust the Hub for updates.** The Hub hands out new agent binaries, but an agent
  only replaces itself when the release checksum list (`SHA256SUMS`) carries a valid signature from
  the official release key built into the agent — or from a key you added to
  `/etc/douve-agent/trusted-keys` for your own builds — when the signed version matches the offered
  one and is not older than the running agent, and when the downloaded file matches the signed
  checksum. A compromised Hub can't push unsigned code or roll agents back to an old release.
- `douve-agent expose` (publishing from a server) is limited to that server's own ports and names
  under the base domain, can be turned off, and is alerted and audited.

**Web terminal**
- Opens a shell as an existing sudo-capable user on the server (via `systemd-run`, also under
  SELinux). Screen output is recorded (20 MB cap per session); recordings can be deleted in the UI.
- **The server checks the passkey itself.** Every time a terminal is opened, the browser signs
  `douve-terminal-open:v1 · server id · account · time · one-time value` with the user's passkey
  (a WebAuthn assertion whose challenge is the SHA-256 of that statement). The Hub verifies it and
  passes it on; the agent verifies it again against its own **terminal trust list** — origin,
  rpId hash, user verification flag, signature, that the key may open terminals on *this* server,
  the time (±2 minutes) and that the one-time value was not used before — and only then starts
  the shell. A signature for one server or account doesn't open another.
- **Files** (upload/download from the terminal page, up to 100 MB) use the same protection: each
  transfer is signed as `file-put:<account>:<size>:<sha256>:<path>` or `file-get:<account>:<path>`
  and verified by the agent. Files are read and written as that account (`systemd-run --uid`), so
  the kernel enforces its permissions; uploads land in a temporary file and are moved into place
  only if size and SHA-256 match what was signed. Every transfer is in the audit log.
- **The trust list** (passkeys of admins, and of operators with the servers granted to them) lives
  in the agent's state directory (`/var/lib/douve-agent/terminal-trust.json`), where the Hub can't
  write. An agent accepts the list as-is only the first time (at join, or after upgrading to this
  version) and while it contains no admin passkey yet. After that, a new version is accepted only
  with a signature from an admin passkey already on the list, and versions only go up. New passkeys,
  removed passkeys and role changes therefore wait until an admin approves them with a passkey
  (Servers page). `douve-agent terminal-trust show` prints the list; `terminal-trust reset` (root,
  on the server) clears it so the next list from the Hub is accepted as on first install. If the
  file can't be read, the agent refuses terminals instead of starting over.

**Security checklist**
- Each agent checks its server when it connects and every 6 hours: SSH password and root login
  (`sshd -T`, the effective values), `Match` blocks that re-enable passwords, automatic security
  updates (unattended-upgrades / dnf-automatic), time sync, pending reboot, and ports listening on
  internet-facing addresses.
- "Fix" changes the server as root, so it is protected like the terminal: the person signs
  `douve-server-action:v1 · server id · fix:<item> · time · one-time value` with a passkey, the Hub
  verifies it, and the agent verifies it again against its terminal trust list before doing
  anything. A signature for another item or server, or a terminal signature, is rejected. SSH fixes
  go into `/etc/ssh/sshd_config.d/00-douve.conf`, are checked with `sshd -t` and against `sshd -T`,
  and are rolled back if either fails.

**Connection check**
- Each agent asks two public STUN servers what address it is seen from (public IP, NAT, symmetric
  NAT) and its router (UPnP/NAT-PMP) for its outside address (CGNAT, double NAT). Another connected
  server with a different public address then tries TCP 22/80/443 on that address — so "reachable"
  means reachable from outside. Agents only probe public IPv4 addresses and only those three ports,
  so a compromised Hub can't use them to scan private networks. Alerts: SSH (22) open to the
  internet, the entry not reachable on 443 twice in a row.

**Security monitoring**
- SSH logins and failures, `sudo`/`su` by non-admin accounts, account changes, changes to
  `passwd`, `shadow`, `sudoers`, `sshd_config`, `authorized_keys`, cron and systemd units, and
  newly opened public ports. Actions performed in the Douve terminal are attributed to the Douve user
  and not alerted.

**Tailscale mode**
- The Hub trusts `Tailscale-User-Login` only on connections from `127.0.0.1`/`::1` (i.e. from
  `tailscale serve` on the same machine) and only for allowed accounts.

**Audit log**
- Sign-ins, re-authentication, settings and channel changes, invites, terminal sessions (screen
  recordings) and publishing from a node are recorded.
- Records form a hash chain: each row stores `SHA-256("douve-audit-v1" + length-prefixed previous
  hash, id, time, user, event, IP, detail)`, starting from 32 zero bytes. Changing a record, or
  deleting one in the middle, breaks the chain at that row. `douve-hub audit-verify` recomputes it;
  the Hub also checks once a day and alerts if it breaks.
- The chain alone cannot show that the *last* records were deleted, or that someone with write
  access rewrote the whole chain. For that, send the log elsewhere: a webhook channel with
  "also send the audit log" receives signed batches (`{"type":"audit","prev_hash":…,"records":[…]}`,
  `X-Douve-Signature`) in order, from the first record, and can verify the chain itself.

**Data at rest**
- One SQLite database. It contains agent public keys, hashed session tokens, alert credentials
  (Telegram bot token, Google client secret) and the audit log. Backups (`douve-hub backup` and the
  daily automatic backups) contain the same data and are written with mode 600 — store copies
  safely.

## Threat model

What each kind of attacker can and can't do, assuming the rest of the system works as designed.

| Attacker | Can | Can't |
|---|---|---|
| Anyone on the internet | Reach the entry on 80/443, public apps, the sign-in page (rate-limited) | Sign in without an allowed account's passkey or Google login; reach protected apps; reach agents (no inbound ports) |
| Stolen session cookie | Until the session is revoked or expires: see what that person's role can see; within 5 minutes of the person's last passkey check also change settings and services | Open a terminal (needs a fresh passkey signature the server verifies); pass a new passkey check |
| Operator / app user | Their granted servers and apps; an operator has root on their servers through the terminal | Other servers, settings, users; publish other servers' or the Hub's ports |
| **Root on the Hub server** (or write access to its database) | Change routes and expose or redirect apps; act as any user towards apps behind the entry's login check; read alert credentials, the Google client secret and recordings; see terminal sessions it relays **and inject keystrokes into a session a user opened**; serve a modified web UI, so the next passkey touch of a signed-in admin may sign something else than shown (one touch = one signed statement); rewrite the audit log (detected only by the copy sent to a webhook) | Open a terminal without a person touching their passkey for it; add its own key to the servers' trust lists without an admin's passkey signature; install unsigned agent code or roll agents back |
| Stolen or lost device (phone/PC with its WireGuard config) | Open the internal services that person may open, until the device is deleted in Douve | Reach the servers' network; anything beyond that person's permissions |
| Root on one managed server | Everything on that server; send false metrics and security events for it; if it is the entry: see the plain traffic of every app and the session cookies passing through it | Open terminals on other servers (signatures are bound to a server id); impersonate other servers to the Hub |
| A copy of a backup | Read everything in the database: alert credentials, the Google client secret, agent *public* keys, session token hashes | Sign in or act as an agent (no private keys or plain session tokens inside) |

Known limits:
- The web UI is served by the Hub. A compromised Hub can therefore show one thing and ask the
  passkey to sign another; the protection above means it needs a person to touch their passkey,
  and each touch yields one statement bound to one server. A client that doesn't load code from the
  Hub (such as a future `douve ssh`) closes this gap.
- Terminal traffic is not end-to-end encrypted between browser and server; the Hub relays it.
- The first trust list an agent accepts is trust-on-first-use, like joining itself.
- Internal service names get public certificates, so they appear in Certificate Transparency logs
  (the names, not the content).
- Passkey verification (WebAuthn, CBOR/COSE) is our own code: tested and fuzzed, not audited.

## Verifying releases

Releases are signed with [minisign](https://jedisct1.github.io/minisign/) (Ed25519). Release key:

```
RWSAXEv+Y7MKiWfICcWzr0WkYGW6Tt92A6+Zxc5hPK1WlzaRvSgAb1ec
```

```sh
minisign -Vm SHA256SUMS -P RWSAXEv+Y7MKiWfICcWzr0WkYGW6Tt92A6+Zxc5hPK1WlzaRvSgAb1ec
sha256sum -c --ignore-missing SHA256SUMS
```

The installer (`douve-agent install`) does both checks itself. Building your own releases: create a
key with `douve-sign keygen`, sign `SHA256SUMS` with `douve-sign sign`, and install with
`--trusted-key your.pub` (the key is also stored in `/etc/douve-agent/trusted-keys` so updates work).

## Recommendations

- Keep one way into your servers that doesn't depend on Douve (cloud serial console, or SSH over a
  private network) before closing port 22. See [docs/recovery.md](docs/recovery.md).
- Register passkeys on two devices and keep your recovery codes off the server.
- Publish apps as *public* only when they have their own login or are meant to be public.
- Keep the Hub updated.
