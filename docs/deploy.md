# Manual install, upgrades and configuration

Most people should use the installer from the [README](../README.md#install). This page is for
manual installs, upgrades and the config file.

## Manual install (Hub)

```sh
# binaries from a release (or build them: make hub-static agent)
sudo install -m 755 douve-hub-linux-$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/') /usr/local/bin/douve-hub
sudo douve-hub init --public-url https://douve.example.com --email you@example.com
sudo douve-hub install-service
sudo systemctl daemon-reload && sudo systemctl enable --now douve-hub
sudo douve-hub invite --email you@example.com          # open the link, create your passkey
sudo douve-hub recovery-codes --email you@example.com  # keep these off the server
```

Put the agent binaries (`douve-agent-linux-amd64`, `douve-agent-linux-arm64`, `SHA256SUMS`,
`VERSION`) in `/usr/local/share/douve/agent/` so that **Servers → Add server** can hand them to new
servers. `deploy/install-hub.sh <douve-hub binary> [init options]` does all of the above from a
source checkout.

The Hub listens on `127.0.0.1:8700` by default. Make one server the entry (Servers → Make entry)
so its agent serves the Hub and your apps on 80/443, or put your own reverse proxy in front.

## Internal path (device WireGuard)

Settings → Internal path: turn it on and open the UDP port (default 51821) to the entry server in
your cloud firewall. Then each person adds devices on the Account page (QR for the WireGuard app,
or a config file). Mark services *internal*, *public* or both in the service dialog. Changing the
port or the address devices connect to means registering devices again.

## Upgrades

- **Hub:** replace `/usr/local/bin/douve-hub` and restart (`deploy/install-hub.sh` keeps the
  existing config). Database migrations run automatically; take a `douve-hub backup` first.
- **Agents:** update themselves when the Hub has a newer agent in
  `/usr/local/share/douve/agent/`.

## `/etc/douve/hub.json`

Created by `douve-hub init`; mode 600. The service reads it through systemd credentials.

| Key | Meaning |
|---|---|
| `public_url` | Address users open (`https://douve.example.com`). Used for origin checks and links. |
| `cookie_domain` | Domain the sign-in cookie covers (default: parent of `public_url`). Apps must be under it. |
| `rp_id`, `rp_name` | WebAuthn relying party (default: `cookie_domain`, "Douve"). Changing `rp_id` invalidates passkeys. |
| `allowed_emails` | Accounts allowed to sign in (people you invite are added in the database). |
| `listen_address`, `listen_port` | Where the Hub listens (default `127.0.0.1:8700`). |
| `trusted_proxies` | Proxies whose `X-Forwarded-For` is trusted (default loopback). |
| `internal_url` | Address agents use to reach the Hub, if different from `public_url`. |
| `tunnel_url` | Address agents use for the entry tunnel, if the default doesn't fit. |
| `tailscale_auth` | `true` in Tailscale-only mode: trust `tailscale serve` identity headers from loopback. |
| `language` | Default alert language, `ko` or `en` (Settings → Alert language overrides it). |
| `privacy_contact` | Contact shown on the `/privacy` page (e.g. an email). Empty hides it. |
| `google.client_id`, `google.client_secret` | Optional Google sign-in (also settable in the web UI). |
| `telegram.bot_token`, `telegram.chat_id` | Telegram alerts (also settable in the web UI). |
| `database_path` | SQLite file (default `/var/lib/douve/hub.db`). |
| `session_idle_days`, `session_max_days` | Session lifetime (default 30 / 90). |
| `metrics_retention_days` | How long minute metrics are kept. |

## Using Douve login with your own nginx

If you keep nginx in front of some apps, protect them with Douve via `auth_request`. See
[`deploy/nginx/protect-snippet.conf`](../deploy/nginx/protect-snippet.conf): include it in a
`server` block, point `proxy_pass` of `/_douve_auth` at the Hub's `/auth/verify`, and add the Hub's
address to `trusted_proxies` if nginx runs on another machine. A `200` from `/auth/verify` means
signed in (the user is in the `X-Douve-User` response header); `401` means redirect to
`https://douve.example.com/login?rd=<original URL>`.
