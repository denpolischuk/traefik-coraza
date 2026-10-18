---
title: 'Coraza Web Application Firewall (native research build)'
description: 'Native Coraza WAF middleware available in this research fork of Traefik Proxy'
---

!!! warning "Research build"

    This page documents a **research-only** native Coraza integration added to this
    Traefik Proxy tree. It is not part of upstream Traefik Proxy and is not
    supported by Traefik Labs.

The native middleware uses [Coraza](https://coraza.io/) and the
[OWASP Core Rule Set](https://coreruleset.org/) directly. It does not require a
Traefik Hub license, an API key, or a WASM plugin download.

It is configured through the existing `plugin` middleware section so that
configurations written for Traefik Hub can be reused:

```yaml
http:
  middlewares:
    waf:
      plugin:
        coraza:
          directives:
            - SecRuleEngine On
            - SecRule REQUEST_URI "@streq /admin" "id:101,phase:1,t:lowercase,log,deny,status:403"
```

The middleware is compiled into the Traefik binary. The `plugin.coraza` key is
used for compatibility; no plugin is downloaded or interpreted at runtime.

## Configuration options

| Field | Description | Default | Required |
|:--|:--|:--|:--|
| `directives` | List of Coraza/ModSecurity directives to load. | | Yes |
| `crsEnabled` | Mount the embedded OWASP CRS filesystem, allowing `@owasp_crs/*` and `@coraza.conf-recommended` includes. It does not load rules by itself. | `false` | No |

At least one directive is required. `SecRuleEngine On` is required to enforce
rules; without it, Coraza defaults may leave the engine in detection-only mode.

## Metrics

When Traefik metrics are enabled, the native WAF exports the following metrics
through the configured metrics backend (Prometheus, OpenTelemetry, Datadog,
InfluxDB, or StatsD):

| Metric | Type | Labels | Description |
|:--|:--|:--|:--|
| `traefik_waf_requests_total` | Counter | `middleware`, `outcome` | Requests processed by the WAF. `outcome` is `allowed`, `detected` (rules matched without an interruption), `blocked`, or `redirected`. |
| `traefik_waf_interruptions_total` | Counter | `middleware`, `action`, `severity` | Disruptive WAF actions and the severity of the triggering rule. |
| `traefik_waf_request_duration_seconds` | Histogram | `middleware`, `outcome` | Time spent in the WAF for a request, including request and response inspection. |
| `traefik_waf_rule_matches_total` | Counter | `middleware`, `severity` | Rule matches, including non-disruptive matches in detection-only mode. |

Backend-specific naming may differ. For example, Datadog and StatsD use names
such as `waf.request.total`, `waf.interruptions.total`,
`waf.request.duration`, and `waf.rule.matches.total`.

!!! note

    WAF metrics intentionally omit `rule_id`, phase, and status labels to keep
    cardinality bounded. Rule IDs are user-defined and can grow without bound as
    rules and middleware instances are added. For per-rule detail, including the
    rule ID, phase, matched data, and transaction ID, use Coraza audit logs
    (`SecAuditLog`, `SecAuditLogParts`, and `SecAuditLogFormat`) or access logs
    instead of metrics.

## OWASP Core Rule Set

Set `crsEnabled: true` to make the embedded CRS files available, then include
the rule files you want:

```yaml
http:
  middlewares:
    waf-crs:
      plugin:
        coraza:
          crsEnabled: true
          directives:
            - Include @coraza.conf-recommended
            - Include @crs-setup.conf.example
            - Include @owasp_crs/*.conf
            - SecRuleEngine On
            - SecAction "id:900110,phase:1,pass,t:none,nolog,setvar:tx.inbound_anomaly_score_threshold=5,setvar:tx.outbound_anomaly_score_threshold=4"
```

`crsEnabled` mounts the ruleset filesystem only. The `Include` directives select
which files are loaded, matching the behavior of the commercial native
integration.

!!! note

    `@crs-setup.conf.example` already defines `SecDefaultAction` for the CRS
    phases. Adding another `SecDefaultAction` for the same phase causes Coraza
    to reject the configuration. Override individual actions instead, or adapt
    a local copy of the CRS setup file.

## Operational notes

- **Detection-only by default:** `@coraza.conf-recommended` sets
  `SecRuleEngine DetectionOnly`. Add `SecRuleEngine On` after the includes to
  block requests.
- **Writable temporary directory:** Coraza buffers request/response bodies and
  may spill them to temporary files. Ensure the configured `SecTmpDir` and
  `SecDataDir` (default `/tmp`) are writable. This is the same requirement as
  Traefik Hub.
- **Response inspection:** Set `SecResponseBodyAccess On` and
  `SecResponseBodyMimeType` to inspect response bodies. Response inspection
  buffers the response before it is sent downstream.
- **Audit logs:** Configure `SecAuditLog` to a writable path. Audit log
  initialization happens when the WAF is compiled.
- **Rule compilation cache:** Compiled WAFs are cached by configuration hash and
  shared by middleware instances. Unused WAFs are removed after a short delay.

## Minimal blocking example

```yaml
http:
  routers:
    app:
      rule: PathPrefix(`/`)
      entryPoints:
        - web
      service: app
      middlewares:
        - waf

  middlewares:
    waf:
      plugin:
        coraza:
          directives:
            - SecRuleEngine On
            - SecRequestBodyAccess On
            - SecRule ARGS "@detectSQLi" "id:102,phase:2,block,msg:'SQL Injection Attack Detected',logdata:'Matched Data: %{MATCHED_VAR} found within %{MATCHED_VAR_NAME}'"

  services:
    app:
      loadBalancer:
        servers:
          - url: http://127.0.0.1:8080
```
