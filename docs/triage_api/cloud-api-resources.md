# Triage Cloud API - Resources

Source: https://tria.ge/docs/cloud-api/resources/
Mirrored: 2026-05-23

---

It is possible to query the available resources in the Triage™ environment. A resource is an analysis environment for a specific OS, language and other specifics.

# GET /resources

List all resources available.

## Example

```shell
curl -H 'Authorization: Bearer <YOUR_ACCESS_KEY>' \
    https://tria.ge/api/v0/resources
```

```shell
curl -H 'Authorization: Bearer <YOUR_ACCESS_KEY>' \
    https://tria.ge/api/v0/resources | jq '.data[].resources[].tags'
```
