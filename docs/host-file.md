# Running many apps on one server

A per-app definition describes one app. When you run several apps on a server, a few things belong to the **server**, not to any single app — shared alert channels, server-wide defaults, and the order apps should come up in. That's what the host file is for.

See also: [The `helmsman.yaml` file](./definition-file.md) · [Installation](./installation.md)

---

## The host file

The host file (`kind: Host`) is an optional, server-level definition where you set:

- **Shared defaults** — values that apply to every app unless the app overrides them (for example, common labels or sensible resource defaults).
- **Which apps live on this server**, and the **order to deploy them** — so a database comes up before the app that depends on it.

Like the per-app file, the dashboard keeps this in sync; you can also keep it in version control and let the dashboard manage it.

## Where settings live (and what the dashboard can change)

Helmsman keeps settings in three layers, by how sensitive they are:

1. **The root of trust** — your master key, the dashboard login, the IP allowlist, and the network address. These live in `config.yaml` and are set **over SSH at install**. The dashboard can **never** change them — so even a fully compromised dashboard can't widen who's allowed in or read your key.
2. **Server settings** — the host-wide defaults and coordination above.
3. **App settings** — everything about an individual app: its image, env, secrets, routes, scaling, and so on.

You manage layers 2 and 3 in the dashboard (or in their definition files). Layer 1 stays SSH-only on purpose. Settings combine in order — a built-in default, then a server default, then the app's own value — with the most specific winning, and the same safety checks apply no matter which layer a value came from.

## Acknowledging changes

If a setting that *broadens* what an app can do changes (say, opening a new route or raising a limit), Helmsman surfaces it for you to acknowledge rather than applying it silently — so an unexpected change in a file you committed can't quietly take effect.
