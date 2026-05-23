# Triage Cloud API - User Management

Source: https://tria.ge/docs/cloud-api/users/
Mirrored: 2026-05-23

---

All operations on this page require the `manage_company` permission and the user making the API call to be a member of a company.

# Role matrix

| Permission | Read Only org_readonly | Submit org_submit | Read Own Samples Only org_read_own_samples | Manage own samples org_manage_own_samples | Basic org_basic | Advanced org_advanced | Admin org_admin |
| --- | --- | --- | --- | --- | --- | --- | --- |
| view_samples:owned | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ |
| view_samples | ✔ | ✔ |  |  | ✔ | ✔ | ✔ |
| submit_samples |  | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ |
| delete_samples:owned |  |  |  | ✔ |  |  | ✔ |
| delete_samples |  |  |  |  |  |  | ✔ |
| access_api |  |  | ✔ | ✔ | ✔ | ✔ | ✔ |
| edit_profiles |  |  |  |  |  | ✔ | ✔ |
| manage_company |  |  |  |  |  |  | ✔ |

# The User Object

```json
{
  // The unique ID of the user.
  "id": "8bbf3c1b-8d5a-4c75-996c-f3daa12c1b91",

  "company_id": "6f0fba3f-65dc-4d17-8a5d-98f9441ff150",

  // The email address of the user. Case sensitive.
  "email": "[[email protected]](/cdn-cgi/l/email-protection)",

  "email_confirmed_at": "2019-07-11T13:42:00Z", // timestamp string

  "name": "John Doe",
  "first_name": "John", // Deprecated! will be removed soon
  "last_name": "Doe", // Deprecated! will be removed soon

  // The creation or registration time of the user.
  "created_at": "2019-07-11T13:42:00Z", // timestamp string

  "role": "org_basic"
}
```

*Note:* the `first_name` and `last_name` fields of the user object have been deprecated on September 9th, 2022 and will be removed in API version 1. Please use the `name` field instead.

# GET /users

Return all users within the company as a paginated list.

# POST /users

Creates a new user and returns it. The user will become a member of the company the requesting user is a member of.

## Example request:

```json5
{
    // The email address that the user should use to log in.
    "email": "[[email protected]](/cdn-cgi/l/email-protection)",

    // If set to true, the user's email address is automatically confirmed.
    // Otherwise, the user should confirm their email address before being able
    // to sign in.
    "email_confirmed": true

    // If set, create the user with a user name instead of an email address. It
    // is not allowed to use an '@' character in user names.
    //
    // It is not allowed to set an email address if this option is used.
    //
    // Internally, the username is translated to a case sensitive email address
    // with the '@triage.local` suffix. This suffix should therefore be added
    // when logging in.
    "username": "foo",

    "password": "correcthorsebatterystaple",

    // The user's real name used for display purposes
    "name": "Foo Bar",

    // The set of premissions that the user should have. See the user object
    // documentation for which values are accepted here.
    "role": "org_basic"
}
```

## Examples:

Create a user with a username which is allowed to submit samples via the API:

```
$ curl -H 'Authorization: Bearer <YOUR_ACCESS_KEY>' \
    -X POST
    --data-raw '{"username":"foo","name":"Foo Bar",\
      "password":"min8chars","role":"org_basic"}'\
    'https://tria.ge/api/v0/users'
```

```json
// Response:
{
  "id": "16410a3e-fc32-44ee-820f-06ca5c99ef03",
  "company_id": "7dd3c863-622b-4a67-a2f8-9a87ddeea5bb",
  "email": "[[email protected]](/cdn-cgi/l/email-protection)",
  "email_confirmed_at": "2019-07-24T15:06:39.753258246+02:00",
  "name": "Foo Bar",
  "created_at": "2019-07-24T13:06:39.753257501Z",
  "role": "org_basic"
}
```

## Errors

- `409, "USER_ALREADY_REGISTERED"`, if there already is a user with the specified email address registered.

# GET /users/{userID}

Queries a single user by its ID, username or email address.

# DELETE /users/{userID}

Delete a user and all associated data, invalidating any sessions and removing their API keys. Any samples submitted by this user are kept.

The user making the request is not allowed to delete themselves.

## Errors

- `404, "NOT_FOUND"`, if the user does not exist.
- `409, "DELETE_SELF"`, if the user attempted to delete themselves.

# POST /users/{userID}/apikeys

Creates a new key can be used to make API calls on behalf of the specified user. The user should have been granted the `access_api` permission beforehand.

This call is idempotent, meaning that if an API key with a conflicting name is already present, it is returned instead.

## Examples

```
curl -H 'Authorization: Bearer <YOUR_ACCESS_KEY>' \
    -X POST
    --data-raw '{"name":"myclient"}'
    'https://tria.ge/api/v0/users/foo/apikeys'
```

```json
// Response:
{
  "name": "foo",
  "key": "cfde93eeab451dc73fb43986f525ccd9fe197a1c"
}
```

## Errors

- `404, "NOT_FOUND"`, if the user does not exist.
- `409, "MISSING_PERMISSION"`, if the user does not have the `access_api` permission.

# GET /users/{userID}/apikeys

Lists all API keys that the user has.

## Example response

```json
{
  "data": [
    {
      "name": "foo",
      "key": "cfde93eeab451dc73fb43986f525ccd9fe197a1c"
    }
  ]
}
```

# DELETE /users/{userID}/apikeys/{apikeyName}

Delete the user's API key with the specified name.

## Errors

- `404, "NOT_FOUND"`, if the user does not exist or if the API key does not exist.
