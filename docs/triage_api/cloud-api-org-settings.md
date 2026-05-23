# Triage Cloud API - Organization Settings

Source: https://tria.ge/docs/cloud-api/org-settings/
Mirrored: 2026-05-23

---

This page describes the available organization settings that can be retrieved and changed. All operations on this page require the `manage_company` permission.

# The settings object

```json
{
  // Is magic link creation enabled or not.
  "magic_link": {
    "enabled": false
  }
}
```

# GET /org/settings

Returns the available organization settings.

# PUT /org/settings/magic

Enable or disable the creation of magic links.

The following object describes the parameters supported by this endpoint.

```json
{
    // Set to true to enable and false to disable the feature.
    "enabled": false
}
```

## Example

```
$ curl -H 'Authorization: Bearer <YOUR_ACCESS_KEY>' \
    -X PUT
    --data-raw '{"enabled": true}' \
    'https://tria.ge/api/v0/org/settings/magic'
```

```
// Response:
{}
```
