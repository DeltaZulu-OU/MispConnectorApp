# MISP Connector for Technitium DNS Server

A plugin that pulls malicious domain names from MISP feeds and enforces blocking in [Technitium DNS Server](https://github.com/TechnitiumSoftware/DnsServer).

It maintains an in-memory blocklist for fast lookups, keeps a disk-backed cache for faster startup, and periodically refreshes indicators from the configured MISP instance.

> NOTE: This app is not included in the main Technitium DNS Server repository as of [v15](https://github.com/TechnitiumSoftware/DnsServer/blob/master/CHANGELOG.md#version-150).

## What is MISP

[MISP](https://www.misp-project.org/) is a threat intelligence platform for sharing, storing, and correlating indicators of compromise, threat intelligence, financial fraud information, vulnerability information, and related data. See the [project documentation](https://www.misp-project.org/documentation/) for details.

This plugin assumes that you already have a working MISP instance. Installing and configuring MISP itself is outside the scope of Technitium DNS Server.

See [this article](https://zaferbalkan.com/technitium-misp/) for a sample use case.

## Features

- Retrieves domain-name indicators of compromise from a MISP server through its REST API.
- Handles paginated fetches with exponential backoff and retry for transient network failures.
- Maintains the current blocklist in memory for fast lookup and persists it to disk for faster startup.
- Matches both exact domains and parent domains without allocating new strings during lookup.
- Blocks matching DNS requests by returning `NXDOMAIN`, or, for TXT queries when enabled, a human-readable blocking report.
- Optionally includes the same blocking report as Extended DNS Error metadata when the client query contains EDNS.
- Lets you configure the TTL applied to blocking answers.
- Supports configurable refresh intervals and IOC age windows.
- Allows TLS certificate validation to be disabled for test environments, with an explicit warning in logs.

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
	"paginationLimit": 5000,
	"addExtendedDnsError": true
}
```

* `enableBlocking` lets you disable enforcement without uninstalling the app.
* `mispServerUrl` is the base URL of the MISP instance.
* `mispApiKey` is the API key used to query MISP.
* `disableTlsValidation` can be useful for test instances and homelabs, but it is not recommended in production.
* `updateInterval` controls how often the app refreshes indicators from MISP. Supported suffixes are `m`, `h`, and `d`.
* `maxIocAge` filters indicators by their MISP `last_seen` value, which lets you limit the blocklist to more recent campaigns. Supported suffixes are `m`, `h`, and `d`.
* `blockingAnswerTtl` sets the TTL, in seconds, for both blocking TXT answers and blocking SOA records. The allowed range is `30` to `86400`; the default is `30`.
* `allowTxtBlockingReport` returns a TXT blocking report for blocked TXT queries instead of `NXDOMAIN`.
* `paginationLimit` controls how many attributes are requested from MISP per page.
* `addExtendedDnsError` adds the blocking report to the EDNS payload when the query includes EDNS, which is useful when DNS telemetry is exported to a SIEM.

## Blocking responses

For a blocked domain, the app generates a report in the following form:

```text
source=misp-connector;domain=example.org
```

For ordinary queries, the app returns `NXDOMAIN` with an SOA record in the authority section. If `allowTxtBlockingReport` is enabled and the blocked query type is `TXT`, it returns the blocking report as the TXT answer instead.

If `addExtendedDnsError` is enabled and the request contains EDNS, the same report is also added as an Extended DNS Error with the `Blocked` code.

## Acknowledgement

Thanks to everyone who has been part of or contributed to the [MISP Project](https://www.misp-project.org/) for making it an useful resource.