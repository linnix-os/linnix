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

## If you set an API token

`api.auth_token` protects every route, `/metrics/prometheus` included, and the
scrape annotations carry no credential — so an authenticated deployment returns
401 to the annotation-based job and the dashboard stays empty. Point Prometheus
at the same token instead of relying on annotations:

```yaml
# prometheus.yml — replaces the annotation-driven job for Linnix
- job_name: linnix
  kubernetes_sd_configs:
    - role: pod
  authorization:
    type: Bearer
    credentials_file: /etc/prometheus/secrets/linnix-token/token
  # The metric's own victim_* labels never collide with the target labels
  # Prometheus attaches, so honor_labels is not needed.
  relabel_configs:
    - source_labels: [__meta_kubernetes_pod_label_app]
      action: keep
      regex: linnix
    - source_labels: [__meta_kubernetes_pod_ip]
      target_label: __address__
      replacement: $1:3000
    - target_label: __metrics_path__
      replacement: /metrics/prometheus
    - source_labels: [__meta_kubernetes_pod_node_name]
      target_label: kube_node
```

With Prometheus Operator, the same thing as a `PodMonitor`:

```yaml
apiVersion: monitoring.coreos.com/v1
kind: PodMonitor
metadata:
  name: linnix
spec:
  selector:
    matchLabels:
      app: linnix
  podMetricsEndpoints:
    - port: api
      path: /metrics/prometheus
      authorization:
        credentials:
          name: linnix-api-token
          key: token
```

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
