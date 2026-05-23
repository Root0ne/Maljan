# Triage Cloud API - Profiles

Source: https://tria.ge/docs/cloud-api/profiles/
Mirrored: 2026-05-23

---

Profiles allow analysis tasks to be tailored to the samples that are submitted.

Profiles are available only to users that are managed by a company.

# The Profile Object

```json
{
  // The unique ID of this profile.
  "id": "237d939c-2f66-4021-af7c-62a70e796f24",
  // A human readable name. The name should be unique.
  "name": "myprofile",
  // The set of tags that is used to match this profile to samples.
  // A locale tag must always be accompanied by at least one os tag.
  "tags": [
    "os:windows10-2004-x64",
    "locale:en-us"
  ],

  // Below are the options that are used in sample submissions.

  // The type of networking that should be used when running the sample.
  // Currently supported values are:
  // * "": The system default
  // * "drop": Disable networking.
  // * "internet": Allow connections to the internet.
  // * "tor": Route internet through the Tor network.
  // * "sim200": InetSim-like functionality with HTTP 200 responses.
  // * "sim404": InetSim-like functionality with HTTP 404 responses.
  // * "simnx": InetSim-like functionality with DNS NXDOMAIN responses.
  // * "vpn": Route connections through a specified VPN.
  "network": "internet",

  // Geographic location for VPN network routing. Requires `network: "vpn"` setting.
  "geolocation": "us",
  // The duraton of the analysis in seconds.
  "timeout": 120
}
```

# GET /profiles

List all profiles that your company has.

## Example

```
curl -H 'Authorization: Bearer <YOUR_ACCESS_KEY>' \
    https://tria.ge/api/v0/profiles/<PROFILE_ID>
```

# POST /profiles

Create a new profile.

The request body should be a profile object with ID omitted.

Query the [resources API](../resources/) to see the available resources to include in a profile.

## Example

```
curl -H 'Authorization: Bearer <YOUR_ACCESS_KEY>' \
    -X POST \
    -d '{"name":"foo","tags":["os:windows10-2004-x64","locale:en-us"],"timeout":120,"network":"internet"}' \
    https://tria.ge/api/v0/profiles
```

## Geolocations

Profiles can be created with a specified geolocation. For a complete list of available geographic locations, refer to [the geolocations documentation](../geolocations/).

```shell
curl -H 'Authorization: Bearer <YOUR_ACCESS_KEY>' \
  -X POST \
  -d '{"name":"foo", "tags":["os:windows10-2004-x64","locale:en-us"], "timeout":120, "geolocation": "us","network":"vpn"}' \
  https://tria.ge/api/v0/profiles
```

## Errors

- `409, "PROFILE_ALREADY_EXISTS"`, if there already is a profile with the specified name.

# GET /profiles/{profileID}

Retrieves a single profile by its ID or name.

## Errors

- `404, "NOT_FOUND"`, if no profile with the specified ID or name exists.

# PUT /profiles/{profileID}

Update the profile with the specified ID or name. The stored profile is overwritten, so it is important that the submitted profile has all fields, with the exception of the ID.

It is allowed to change the name of a profile as long as no other profile bears the new name. This will also invalidate future requests for profiles using the old name. To prevent breaking such requests, use the ID instead.

## Example

```
curl -H 'Authorization: Bearer <YOUR_ACCESS_KEY>' \
    -X PUT \
    -d '{"name":"foo","tags":["os:windows10-2004-x64"],"timeout":120}' \
    https://tria.ge/api/v0/profiles/<PROFILE_ID>
```

## Errors

- `404, "NOT_FOUND"`, if no profile with the specified ID or name exists.
- `409, "PROFILE_ALREADY_EXISTS"`, if an attempt was made to update the name that is already taken.

# DELETE /profiles/{profileID}

Delete a profile by its ID or name.

## Example

```
curl -H 'Authorization: Bearer <YOUR_ACCESS_KEY>' \
    -X DELETE https://tria.ge/api/v0/profiles/<PROFILE_ID>
```

## Errors

- `404, "NOT_FOUND"`, if no profile with the specified ID or name exists.
