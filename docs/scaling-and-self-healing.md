# Scaling & self-healing

Two optional automations keep your apps responsive and running. Both are **off until you turn them on**. If acting would risk your server, they hold back and alert you instead.

See also: [Alerts](./alerting.md) · [Incidents](./first-steps.md)

---

## Auto-scaling

Auto-scaling adjusts how many copies (**replicas**) of a service run, based on load — more under pressure, fewer when idle. You enable it **per service** on the app's page.

**Only stateless services qualify.** A service must be **stateless and edge-fronted** — no fixed host port, no read-write data volume — because running several copies of something stateful (like a database) would corrupt its data. You confirm this when enabling it, and Helmsman re-checks each cycle: if a service gains a writable volume or starts looking stateful, it's scaled back down and left alone.

**Edge-fronted means HTTP *or* L4.** Normally "edge-fronted" is an HTTP service behind an `edge.route`. A **non-HTTP** stream service (DNS, MQTT) can also scale if you front it with an [`edge.l4_route`](./definition-file.md#specedgel4_routes-tcpudp-load-balancing): the L4 load balancer owns the public port and the replicas stay internal, so it no longer "publishes a fixed host port." This needs **nginx installed on the host** and `edge.l4_enabled` (it's opt-in and not bundled — see the definition-file reference). Without it, such services run as a single instance.

**It only adds capacity when there's room.** Before starting another replica, Helmsman checks there's provably enough memory and CPU, keeping headroom for itself and the edge. On a server that's near its limit it **collapses to a single replica** and won't scale up. It moves **one step at a time** with separate scale-up and scale-down thresholds (and a hold window), so it doesn't flap up and down.

**You're alerted if it can't scale up.** If it declines to scale because the server is constrained, it can alert you — that's your cue the box needs more resources.

You configure min/max replicas, per-replica memory and CPU, and the up/down thresholds on the app's **Auto-scaling** panel.

> Never enable this for a database, message broker, or anything that owns data — those are meant to run as a single instance.

## Self-healing

The self-healing supervisor watches your services and **recovers ones that crash or get stuck** — restarting a failed container, and escalating if a restart isn't enough. It only ever *reduces* pressure or holds steady; it never adds load.

When it **can't** recover a service after trying, it stops retrying (to avoid a crash-loop hammering the box), **flags the service on the Incidents screen**, and alerts you. That's the "self-healing gave up" state — you investigate, fix the underlying problem, and click **clear & retry** to let Helmsman try again.

**Planned downtime:** if you're taking a service down on purpose, mark it as expected-down for a window so the supervisor doesn't fight you trying to bring it back.

Self-healing is conservative for the same reason auto-scaling is: a recovery action that needs to recreate a container runs only when there's room, so healing one app can't knock over the server.
