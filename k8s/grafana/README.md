# Grafana dashboard

`linnix-noisy-neighbor.json` charts the per-pod stall attribution cognitod
exports. Import it through **Dashboards → New → Import → Upload JSON file**.

The datasource is a template variable rather than a hardcoded UID, so the
dashboard works against whichever Prometheus you pick at import time.

## What each panel answers

| Panel | Question |
| --- | --- |
| Most stalled pods | Who is losing time to CPU pressure? |
| Top offenders | Who is causing other pods to wait? |
| Stall attribution over time | How is blame moving between pairs? |
| Blame series dropped | Is any attribution missing from this view? |
| Nodes reporting attribution | Are all nodes actually instrumented? |
| Pairs under blame | Is contention spreading or concentrating? |

The victim metric is in microseconds and the offender metric is in seconds —
they come from different sources, so the panels carry different units on
purpose. Don't sum across the two.

## If the panels are empty

1. **Is the endpoint on?** `kubectl exec` into an agent pod and
   `curl localhost:3000/metrics/prometheus`. A 404 means `[outputs] prometheus`
   is not set — check the ConfigMap.
2. **Is Prometheus scraping it?** The DaemonSet carries `prometheus.io/scrape`
   annotations, which the standard `kubernetes-pods` job honours. Prometheus
   Operator ignores annotations; add a `PodMonitor` selecting `app: linnix` on
   port 3000, path `/metrics/prometheus`.
3. **Are the probes attached?** `curl localhost:3000/readyz`. Attribution is
   kernel-derived, so a node running userspace-only reports nothing to blame.
4. **Has anything stalled yet?** The offender metric only appears once a pod
   sustains pressure for `sustained_pressure_seconds`. On an idle cluster both
   attribution panels are legitimately empty.
