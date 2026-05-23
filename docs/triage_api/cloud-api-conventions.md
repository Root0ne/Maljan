# Triage Cloud API - Conventions

Source: https://tria.ge/docs/cloud-api/conventions/
Mirrored: 2026-05-23

---

# Stability

The current API is considered stable. We will not make any backwards incompatible changes. We will, however, work on a v1 API layer that may include new features and concepts not available today.

Object keys are considered case-sensitive.

Adding new a new field to an object is considered a non-breaking change.

# Responses

## Success Responses

When a request has completed successfully, the HTTP status code is set to `200 OK` unless stated otherwise. For all responses that return a single object, the object is returned as the root element. Responses that return arrays of objects return the array in a `data` field.

Example:

```json
{
  "id": "137262b4-7982-4013-a40d-74cca237fe3f",
  // other fields
}
```

For endpoints that never return data, an empty object is returned.

## Error Responses

For both client and server errors, a single object is returned:

- `error`, a specific error code indicating the kind of failure. This field is always present.
- `message`, a human readable string with additional information about the cause of the error. This field is not intended to be used by machines, but is provided to make debugging client applications easier. Not guaranteed to be present.

Example:

```json
// 404
{
  "error": "NOT_FOUND",
  "message": "No sample with ID `00000000-0000-0000-0000-000000000000`"
}
```

### Client Errors

For all errors caused by a client error, the HTTP status code is set to a value in the range of `[400,499]`.

Generic client errors:

- `400, "BAD_REQUEST"`: An error occurred while decoding the request.
- `400, "INVALID"`: One or more required fields have a value that is not allowed.
- `401, "UNAUTHORIZED"`: Missing or invalid credentials.
- `404, "NOT_FOUND"`: Object not found or non-existing endpoint.
- `405, "METHOD_NOT_ALLOWED"`: Method not allowed for endpoint.

### Server Errors

In the event of an server by the server, the HTTP status code is set to `500 Internal Server Error`. The client may retry the request.

- `500, "INTERNAL"`: The request was valid, but the server could not process it.

# Authentication

All API requests should be authenticated using an API token. You can get a token on your [account](/account) page. This token should be set in the `Authorization` HTTP header. Example:

```
Authorization: Bearer <apikey>
```

# Pagination

Endpoints which return collections support a pagination scheme to iterate over the full collection using separate requests.

The pagination can be controlled using two query parameters:

- `limit`, the maximum number of items to return in in the response. The default is 50 and the maximum value allowed by the API is 200.
- `offset`, the offset at which to start returning objects as returned by previous pages. If omitted, the first page is returned. This value should be treated as an opaque string to remain compatible with future changes to the API.

The response is a regular response object containing a `data` field, an array with the objects in the returned page, and a `next` field which is the `offset` of the next page. It is omitted if there the next page would contain 0 elements.

Setting the `offset` to an out-of-range or querying an empty collection, will always return a page with `data` being an empty array.

# Time

All timestamps are returned as UTC in RFC3339 formatted strings. Example: `2019-04-05T14:28:15Z`
