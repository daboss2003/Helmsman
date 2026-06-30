# Running many apps on one server

A per-app definition describes one app. When you run several apps on a server, a few things belong to the **server**, not to any single app — shared alert channels, server-wide defaults, and the order apps should come up in. That's what the host file is for.

See also: [The `mooring.yaml` file](./definition-file.md) · [Installation](./installation.md)

---

## The host file

The host file (`kind: Host`) is an optional, server-level definition where you set:

- **Shared defaults** — values that apply to every app unless the app overrides them (for example, common labels or sensible resource defaults).
- **Which apps live on this server**, and the **order to deploy them** — so a database comes up before the app that depends on it.

Like the per-app file, the host file is the source of truth: you keep it in version control, and the dashboard reads it (it shows the deployed server settings, and is read-only for them).

## Where settings live (and what the dashboard can change)

Mooring keeps settings in three layers, by how sensitive they are:

1. **The root of trust** — your master key, the dashboard login, the IP allowlist, and the network address. These live in `config.yaml` and are set **over SSH at install**. The dashboard can **never** change them; they're set over SSH at install only.
2. **Server settings** — the host-wide defaults and coordination above.
3. **App settings** — everything about an individual app: its image, env, secrets, routes, scaling, and so on.

Layers 2 and 3 are defined in their definition files (the host file and each app's `mooring.yaml`); the dashboard reflects them read-only, except the operational things it deliberately owns — secret values, lifecycle actions, and the auto-scaling policy. Layer 1 stays SSH-only on purpose. Settings combine in order — a built-in default, then a server default, then the app's own value — with the most specific winning, and the same safety checks apply no matter which layer a value came from.

## Acknowledging changes

If a setting that *broadens* what an app can do changes (say, opening a new route or raising a limit), Mooring surfaces it for you to acknowledge rather than applying it silently — so an unexpected change in a file you committed can't quietly take effect.
