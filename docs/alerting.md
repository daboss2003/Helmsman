# Alerts

Helmsman can tell you when something needs your attention — an app going down, a server running hot, a certificate failing to renew — and it can even tell you when **Helmsman itself** goes dark. Alerting is **off until you turn it on**, and adds nothing to a running system until you do.

See also: [Scaling & self-healing](./scaling-and-self-healing.md) · [Backups & recovery](./backup-and-recovery.md)

---

## Turning it on

Enable alerting in `config.yaml` and **restart** Helmsman:

```yaml
alerting:
  enabled: true
  quiet_start_hour: 22      # optional: hold non-critical alerts overnight
  quiet_end_hour: 7
  dead_mans_url: "https://hc-ping.com/your-uuid"   # heartbeat target (see below)
```

```bash
sudo systemctl restart helmsman
```

> **Restart, not reload.** The alerting engine starts at boot, so `systemctl reload` won't turn it on — you must `systemctl restart helmsman`. (See [editing the config file](./installation.md#editing-the-config-file-reload-vs-restart).)

Everything else is managed in the dashboard — no files or config to hand-edit. The **Alerts** page shows open alerts and links to two dedicated screens: **Channels** (where alerts go) and **Rules** (what to watch for). Each has an **Add** button that opens a form. Alerting is **not** part of any app's `helmsman.yaml`: channels and rules are platform-level and live in the dashboard, and channel credentials (SMTP passwords, webhook secrets, bot tokens) are stored **encrypted at rest** — they are never rendered back into a form or written to a file. Open problems also appear on the **Incidents** screen.

## What it watches

- **Your servers** — CPU, memory, disk, and load.
- **Your apps** — containers going down, becoming unhealthy, or restart-looping; a dependency an app reports as down.
- **The platform** — crashed or out-of-memory containers, a failing certificate, a full disk, low memory headroom.

## How it decides what to send

Some apps already alert on their own. Helmsman is smart about this:

- **App alerts defer to apps that cover themselves.** If an app already pages you about its own health, Helmsman won't double-page. The one exception is a **down safety net**: if an app actually goes *down* or unreachable, Helmsman always alerts — so "the app went dark" never results in silence.
- **Platform alerts always fire.** Crashes, out-of-memory kills, certificate or edge failures, a full disk — these are never deferred, because a crash-looping app can't be trusted to report its own death.

You set this up as **rules** on the **Rules** page (Alerts → Rules): pick what to watch (e.g. host CPU, container down, restart storm), an optional scope (all apps, or one app), a threshold, how long it must hold before alerting, the severity, and which channel to send to (a dropdown of your channels, or all enabled).

## How an alert reaches you

Add one or more **channels** on the **Channels** page (Alerts → Channels). An alert goes to each one:

| Channel | What you provide |
|---|---|
| **Email** | Your SMTP server details. Sent over TLS; messages link back to the dashboard. |
| **Webhook** | A URL. The request is signed so your receiver can verify it's really from Helmsman. |
| **Slack** | An incoming webhook URL. |
| **Discord** | An incoming webhook URL. |
| **Telegram** | A bot token and chat id. |
| **ntfy** | A server URL, a topic, and (optionally) a token for a protected topic/server. |

The **Add a channel** form shows **only the fields for the kind you pick** — choose ntfy and you'll see just the ntfy fields, choose SMTP and you'll see just the mail fields. After adding a channel, use **Send test** to confirm it works.

### Push to your phone with ntfy

[ntfy](https://ntfy.sh) is the easiest way to get alerts as phone push notifications. To set it up:

1. On the **Channels** page (Alerts → Channels) → **Add a channel**, pick **ntfy** and fill in:
   - **Server URL** — `https://ntfy.sh` (the free public service) or your own ntfy server.
   - **Topic** — any name, e.g. `helmsman-alerts-7x2k9`. On public ntfy.sh a topic is *unauthenticated*, so **use a long, random name** (anyone who knows it can read it).
   - **Token** — leave blank for public ntfy.sh; fill it only if your topic/server requires auth.
2. Install the **ntfy app** (iOS/Android) and **subscribe to the same topic** (on a self-hosted server, subscribe to the full URL, e.g. `https://ntfy.example.com/<topic>`).
3. Back in Helmsman, click **Send test** — you should get a push within a second or two.
4. Add a **rule** (below) so real conditions actually fire to it.

If you'd rather not rely on public ntfy.sh, you can self-host ntfy (a single small binary) and point the channel at it — see [the ntfy docs](https://docs.ntfy.sh/install/).

### Let Helmsman host ntfy for you

If you don't want to use public ntfy.sh **or** run ntfy yourself, pick **ntfy (Helmsman-hosted)** when adding a channel. Helmsman runs its own private ntfy for you:

- You give it a **hostname** (a DNS name pointed at this server, e.g. `ntfy.example.com`) and a **topic**.
- Helmsman starts a locked-down ntfy container, **exposes it through the managed edge with automatic HTTPS**, and generates two tokens: a **write** token it publishes with (kept server-side) and a **read-only** token for you.
- The Channels page then shows your **subscribe URL + read-only token**. In the ntfy app, add that server, set the token, and subscribe to the topic. The read-only token can only **receive** alerts — never publish — so it's safe on your phone. iOS gets instant push via ntfy.sh's free relay (which only ever sees an opaque topic hash, never your messages).

Requirements: the **managed edge must be enabled** (Helmsman needs it to expose ntfy over HTTPS) and the hostname's **DNS must point at this server** (so the edge can get a certificate). The ntfy server is **only run once you configure this channel** — deleting the channel stops and removes it.

Alerts are **deduplicated** — one problem is one page, not a flood — and they respect your **quiet hours**: non-critical alerts are held overnight, while critical ones always come through. Helmsman paces its own sending so a slow mail server or bot can never turn it into a spam-cannon.

## Knowing Helmsman itself is alive (the dead-man's switch)

A dashboard that's down can't alert you that it's down. So Helmsman sends a periodic heartbeat to an outside URL you choose (`dead_mans_url` — for example a free check at [healthchecks.io](https://healthchecks.io)). As long as Helmsman is healthy, the pings keep arriving. If Helmsman — or the whole server — dies, the pings stop and that outside service pages you. Set it once and you're covered even for a total-host failure.

## Acking and silencing

On the **Alerts** page you can see every open alert and:

- **Acknowledge** it — you've seen it; stop re-paging.
- **Silence** it for a while — useful during planned maintenance.

An alert **auto-resolves** on its own once the underlying problem clears.
