# Emergency exit — getting back in when something breaks

Once Douve lets you close SSH (port 22), the most important question is "how do I get in if Douve
breaks?". Do these three things right after installing:

1. **Keep your recovery codes** — the 10 codes printed at the end of the install (or Account →
   Recovery codes → Generate new). Store them off the server: a password manager or paper.
2. **Register two or more passkeys** on different devices, e.g. your phone and laptop
   (Account → Add passkey).
3. **Copy backups off the server.** The Hub writes `/var/lib/douve/backups/auto-YYYYMMDD.db` every
   day and keeps 7. In case you lose the whole server, now and then copy a `sudo douve-hub backup`
   file somewhere else. Backups contain secrets (agent keys, sessions, alert tokens) — keep them
   safe.

And **know one way into your servers that doesn't go through Douve**: your cloud provider's serial
console (OCI "Console connection", AWS "EC2 Serial Console", Hetzner "Console", …) or SSH over a
private network such as WireGuard or Tailscale. Only close public port 22 when you have one.

## By situation

### I lost my passkey device (the Hub is fine)
Sign-in page → **"Lost your passkey? Sign in with a recovery code"** → enter one code.
For a few minutes after that you count as freshly verified, so you can **Add passkey** right away.
Delete the lost device's passkey on the Account page and generate new codes if few are left.
Signing in with a recovery code sends an alert — if it wasn't you, generate new codes immediately
and log out other devices.

### I have no recovery codes either (but I can get a shell on the Hub server)
```sh
sudo douve-hub invite --email me@example.com          # link to register a new passkey (24 h)
sudo douve-hub recovery-codes --email me@example.com  # new recovery codes (old ones stop working)
```
Get the shell through your cloud console or private-network SSH. The Douve web terminal of other
servers needs a working Hub.

### The Hub doesn't respond
- Apps you published as public keep working: the entry serves them from its last routing table,
  even after the entry restarts.
- Apps that require a Douve login are blocked on purpose and show "Can't reach the sign-in server".
- On the Hub server: `systemctl status douve-hub`, `journalctl -u douve-hub -n 100`,
  `systemctl restart douve-hub`.
- If the database is damaged, roll back to an automatic backup (see "Restore").

### I lost the whole Hub server
Install the Douve binaries on a new server (steps 1–2 of the installer, or download only `douve-hub`
from the release), then:
```sh
sudo douve-hub install-service
sudo douve-hub restore douve-backup-....db     # restores the config (hub.json) and the database
sudo systemctl daemon-reload && sudo systemctl enable --now douve-hub
```
Point DNS (or the Tailscale name) at the new server; the agents on your other servers reconnect to
the same address by themselves (their keys are in the restored database, so no re-joining). If the
new server is also the entry, use Douve → Servers → Make entry (edge).

### Restore
```sh
sudo systemctl stop douve-hub
sudo douve-hub restore /var/lib/douve/backups/auto-20261006.db   # current DB and config kept as *.before-restore-<time>
sudo systemctl start douve-hub
```
Use `--keep-config` to roll back only the database.

### The entry (edge) server died
Make another server with a public IP the entry (Douve → Servers → Make entry (edge)) and point DNS
at it. The new entry gets certificates automatically.
