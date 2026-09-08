# MISP Connector for Technitium DNS Server

A plugin that pulls malicious domain indicators from a MISP instance and enforces blocking in [Technitium DNS Server](https://github.com/TechnitiumSoftware/DnsServer).

It maintains an in-memory blocklist for fast lookups, keeps a disk-backed cache for faster startup, and periodically refreshes indicators from the configured instance.

> NOTE: This app is not included in the main Technitium DNS Server repository as of [v15](https://github.com/TechnitiumSoftware/DnsServer/blob/master/CHANGELOG.md#version-150).

## What is MISP

[MISP](https://www.misp-project.org/) is a threat intelligence platform for sharing, storing, and correlating indicators of compromise and related threat intelligence. See the [project documentation](https://www.misp-project.org/documentation/) for details.

This plugin assumes that you already have a working MISP instance. Installing and configuring MISP itself is outside the scope of Technitium DNS Server.

See [this article](https://zaferbalkan.com/technitium-misp/) for a sample use case.

## Features

- Retrieves `domain` attributes marked `to_ids` from published MISP events through `/attributes/restSearch`.
- Reports the matched domain and MISP event ID by default.
- Can optionally include source organisation, threat level, event description, and event tags.
- Suppresses full event context for restricted TLP-marked events.
- Handles paginated fetches with retry for transient network failures.
- Matches both exact domains and parent domains without allocating new strings during lookup.
- Blocks matching DNS requests with `NXDOMAIN`, or returns a TXT blocking report when enabled.
- Optionally includes a short blocking report as Extended DNS Error metadata when the client query contains EDNS.
- Supports configurable refresh intervals, search age windows, blocking TTL, report context, and page size.

## MISP REST query

The connector uses the attribute-level MISP REST search endpoint:

```text
/attributes/restSearch
```

With the default `reportContext` setting, each request is conceptually:

```json
{
  "returnFormat": "json",
  "type": "domain",
  "to_ids": true,
  "deleted": false,
  "published": true,
  "last": "15d",
  "includeContext": false,
  "limit": 1000,
  "page": 1
}
```

The connector explicitly filters for published events. This is required for the JSON export because MISP does not implicitly apply the `published` filter to non-restrictive JSON `restSearch` responses.

The attribute's `event_id` is enough for the default event-ID report, so parent event objects are not requested or retained. When `reportContext` is set to `full`, `includeContext` is enabled so the connector can use parent-event information without a second MISP request.

The connector deliberately does not retain every field returned by MISP. The matched domain and MISP event ID remain available for deeper investigation while long-lived per-IOC metadata is kept small.

The original MISP feed name or feed URL is not resolved. MISP does not provide a universal feed identifier on every attribute, so feed provenance would require additional source-specific mapping.

## Configuration

Supply a JSON configuration like the following:

```json
{
	"enableBlocking": true,
	"mispServerUrl": "https://misp.example.com",
	"mispApiKey": "YourMispApiKeyHere",
	"disableTlsValidation": false,
	"updateInterval": "2h",
	"maxIocAge": "15d",
	"blockingAnswerTtl": 30,
	"allowTxtBlockingReport": true,
	"paginationLimit": 1000,
	"reportContext": "event-id",
	"addExtendedDnsError": true
}
```

* `enableBlocking` lets you disable enforcement without uninstalling the app.
* `mispServerUrl` is the base URL of the MISP instance. Path-prefixed deployments such as `https://example.com/misp/` are supported.
* `mispApiKey` is the API key used to query MISP.
* `disableTlsValidation` can be useful for test instances and homelabs, but it is not recommended in production.
* `updateInterval` controls how often the app refreshes indicators from MISP. Supported suffixes are `m`, `h`, and `d`.
* `maxIocAge` is passed to MISP as the `last` search parameter. In current MISP versions, `last` is an alias for the event publication timestamp filter; it does not filter the attribute's `last_seen` field directly. Supported suffixes are `m`, `h`, and `d`.
* `blockingAnswerTtl` sets the TTL, in seconds, for blocking TXT answers and SOA records. The allowed range is `30` to `86400`; the default is `30`.
* `allowTxtBlockingReport` returns a TXT blocking report for blocked TXT queries instead of `NXDOMAIN`.
* `paginationLimit` controls how many attributes are requested from MISP per page. The default is `1000` and the accepted range is `1` to `10000`. Smaller pages reduce transient memory use during refresh at the cost of more API requests.
* `reportContext` controls how much MISP information is exposed in blocking reports: `none` reports only the source and matched domain, `event-id` also reports the MISP event ID and is the default, and `full` opts in to additional event metadata.
* `addExtendedDnsError` adds a short blocking report to the EDNS payload when the query includes EDNS.

## Blocking responses

With the default `reportContext: "event-id"`, a report looks like:

```text
source=misp-connector;domain=evil.example;event=3812
```

With `reportContext: "full"`, an unrestricted event can additionally produce:

```text
source=misp-connector;domain=evil.example;event=3812;org=CIRCL;threat=high;info=Malicious infrastructure;tags=tlp:clear,confidence:90
```

Full event metadata is not emitted when the event has a TLP tag other than `TLP:CLEAR` or the legacy `TLP:WHITE`. This includes `TLP:GREEN`, `TLP:AMBER`, `TLP:AMBER+STRICT`, and `TLP:RED`.

Possible full-context fields are:

| Field | Meaning |
| --- | --- |
| `source` | Always `misp-connector`. |
| `domain` | The MISP domain attribute that matched the query or one of its parent domains. |
| `event` | MISP event ID. |
| `org` | Source organisation (`Event.Orgc.name`). |
| `threat` | MISP threat level. |
| `info` | Parent event description (`Event.info`). |
| `tags` | Event tags, bounded to keep the report small. |

Report values replace field delimiters and control characters before output. Text is truncated on UTF-8 character boundaries so multi-byte characters and surrogate pairs are not split.

For ordinary queries, the app returns `NXDOMAIN` with an SOA record in the authority section. If `allowTxtBlockingReport` is enabled and the blocked query type is `TXT`, it returns a report of at most 512 UTF-8 bytes as the TXT answer.

If `addExtendedDnsError` is enabled and the request contains EDNS, an independently bounded report of at most 128 UTF-8 bytes is added as an Extended DNS Error with the `Blocked` code. The shorter EDE form limits UDP response inflation; the TXT response is the appropriate place for longer diagnostics.

## Duplicate indicators

When the same domain appears in multiple MISP events, the connector chooses deterministically: a valid event ID is preferred over a missing ID, and otherwise the lowest event ID wins. This prevents report context from changing solely because MISP returned pages in a different order.

## Memory use and sizing

Technitium DNS Server can run on modest hardware, but this connector maintains its own MISP IOC lookup and therefore adds memory consumption. With the default `event-id` report mode, event objects are not requested or retained. `full` mode additionally stores bounded event context once per unique MISP event rather than duplicating it for every IOC.

Refreshes need additional headroom because the current snapshot stays active while a complete replacement is built. Peak memory can therefore include both IOC snapshots and one MISP REST response page. `paginationLimit` affects the response-page portion of that peak; a smaller value uses less transient memory but requires more API calls.

There is no fixed RAM requirement per IOC that applies to every deployment. Operators should monitor their actual workload and choose IOC scope, `maxIocAge`, `paginationLimit`, and report context according to the memory available to the DNS server and the security coverage they require. Balancing resource consumption against threat-intelligence coverage is the operator's responsibility.

## IOC cache

The cache is stored in the application folder as `misp_domain_cache.txt` and contains one domain per line. Only the blocking domains are persisted; MISP event context remains in memory.

After a restart, cached domains can block immediately, but event IDs and optional full context become available after the next successful MISP refresh. This keeps the cache simple and avoids duplicating threat-intelligence metadata on disk and in memory.

## Acknowledgement

Thanks to everyone who has been part of or contributed to the [MISP Project](https://www.misp-project.org/) for making it a useful resource.
