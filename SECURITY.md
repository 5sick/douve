# Security

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub: **Security → Report a vulnerability** on
this repository. Don't open a public issue. You'll get an answer within a week; fixes for confirmed
issues ship as a new release with a note in the release text.

Only the latest release is supported.

## What Douve is — and what that means for trust

Douve is a *front door*: it decides who can reach your apps and it can open a root-capable shell on
every server it manages. Plan your trust accordingly.

- **The Hub is the crown jewel.** Whoever controls the Hub (or a signed-in session with a fresh
  passkey check) can open terminals on, push routes to, and update the agents of every server.
  Treat the Hub server like a password manager.
- **Every user is a full administrator.** There are no roles yet. Only invite people you would
  give root to.
- **No external audit yet.** WebAuthn verification, CBOR/COSE parsing and the session layer are
  implemented in this repository (C++), with unit tests and end-to-end tests using a real
  browser's virtual authenticator, but they have not been fuzzed or audited.

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
  and recovery codes; **60 seconds** for opening a terminal.
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

**Agents**
- Each agent has an Ed25519 identity created at join time; joining uses a one-time token valid for
  15 minutes. Agents keep one outbound WebSocket to the Hub — no inbound ports on servers.
- The agent tunnel (for servers without a direct path) is authenticated with the same key, and the
  entry only forwards to upstreams on the Hub-provided allow-list for that server.
- Agents update themselves from the Hub and verify the SHA-256 the Hub publishes before replacing
  the binary — so agents trust the Hub (see above).
- `douve-agent expose` (publishing from a server) is limited to that server's own ports and names
  under the base domain, can be turned off, and is alerted and audited.

**Web terminal**
- Opens a shell as an existing sudo-capable user on the server (via `systemd-run`, also under
  SELinux). Screen output is recorded (20 MB cap per session); recordings can be deleted in the UI.

**Security monitoring**
- SSH logins and failures, `sudo`/`su` by non-admin accounts, account changes, changes to
  `passwd`, `shadow`, `sudoers`, `sshd_config`, `authorized_keys`, cron and systemd units, and
  newly opened public ports. Actions performed in the Douve terminal are attributed to the Douve user
  and not alerted.

**Tailscale mode**
- The Hub trusts `Tailscale-User-Login` only on connections from `127.0.0.1`/`::1` (i.e. from
  `tailscale serve` on the same machine) and only for allowed accounts.

**Data at rest**
- One SQLite database. It contains agent public keys, hashed session tokens, alert credentials
  (Telegram bot token, Google client secret) and the audit log. Backups (`douve-hub backup` and the
  daily automatic backups) contain the same data and are written with mode 600 — store copies
  safely.

## Recommendations

- Keep one way into your servers that doesn't depend on Douve (cloud serial console, or SSH over a
  private network) before closing port 22. See [docs/recovery.md](docs/recovery.md).
- Register passkeys on two devices and keep your recovery codes off the server.
- Publish apps as *public* only when they have their own login or are meant to be public.
- Keep the Hub updated.
