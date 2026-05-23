# Triage Cloud API - Geolocations

Source: https://tria.ge/docs/cloud-api/geolocations/
Mirrored: 2026-05-23

---

The Triage™ API offers an endpoint to query all available geographic locations for network routing during behavioral analysis.

# GET /geolocations

List all geolocations available.

## Example

```shell
curl -H 'Authorization: Bearer <YOUR_ACCESS_KEY>' \
    https://tria.ge/api/v0/geolocations
```

```shell
curl -H 'Authorization: Bearer <YOUR_ACCESS_KEY>' \
    https://tria.ge/api/v0/geolocations | jq '.data[].geolocations[].tags'
```

For a quick overview of all available geolocation tags:

```shell
curl -H 'Authorization: Bearer <YOUR_ACCESS_KEY>' \
    https://tria.ge/api/v0/geolocations | jq '[.data[].geolocations[].tags] | unique'
```

# Usage

For information about using geolocation settings when submitting samples for analysis, please refer to the [sample submission documentation](../submit/#submitting-using-a-different-geolocation). For configuring geolocation settings in profiles, see the [profile documentation](../profiles/#geolocations).
