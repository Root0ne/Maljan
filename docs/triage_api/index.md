# Triage Cloud API - Home

Source: https://tria.ge/docs/
Mirrored: 2026-05-23

---

# Recorded Future: Sandbox

Welcome to the Recorded Future: Sandbox API documentation.

The v0 API endpoints in the cloud version of Recorded Future: Sandbox are considered stable. Minor changes will be made in a backwards compatible manner where possible and will be described in the changelog below.

For researchers and customers, we provide an API to automate sample analysis. The API is REST-like and includes event-driven actions.

The public cloud API:

`https://tria.ge/api/v0/`

The private cloud API:

`https://private.tria.ge/api/v0/`

The RecordedFuture sandbox API:

`https://sandbox.recordedfuture.com/api/v0/`

The RecordedFuture US sandbox API:

`https://us-sandbox.recordedfuture.com/api/v0`

The RecordedFuture APJ sandbox API:

`https://apj-sandbox.recordedfuture.com/api/v0`

The endpoints described in the API documentation use this base URL as prefix.

One might also be interested in our [official API client](https://github.com/hatching/triage) implemented in **Go** and **Python**.

Our [FAQ](faq) might have the answer you are looking for.

In case you have any questions or suggestions regarding the API, please reach out to us on [[email protected]](/cdn-cgi/l/email-protection#2e5d5b5e5e415c5a6e464f5a4d46474049004741).

## Changelog

-
2022-09-09: The `first_name` and `last_name` fields in the User object have been deprecated in favor of the `name` field. Please see the [User Management](cloud-api/users) page for more information.

-
2024-04-01: NDJSON site and spec are deprecated. All its usages have been changed to [JSONL](https://jsonlines.org/). This spec is fully compatible with Sandbox's current usage of NDJSON. Affects: `/api/v0/samples/events` and `/api/v0/samples/<sampleID>/events`
