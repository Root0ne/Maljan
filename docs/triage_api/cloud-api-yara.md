# Triage Cloud API - Yara

Source: https://tria.ge/docs/cloud-api/yara/
Mirrored: 2026-05-23

---

The Yara API endpoint allows yara rules to be uploaded, manipulated and deleted. Keep in mind that the rules are still compiled to check compatibility. For more information about compatibility please refer to the documentation: [triage yara documentation](https://tria.ge/docs/yara/)

# GET /yara

Returns a listing of yara rules that are accessible by the user.

- `name` specify the current rule name in the query `/v0/yara/bazar.yara` to retrieve a detailed listing of a rule.

### Retrieve all yara rules

```shell
curl --request GET \
  --url https://tria.ge/api/v0/yara \
  --header 'Authorization: Bearer <YOUR_ACCESS_KEY>'
```

Result:

```json
{
  "rules": [
    {
      "name": "msrule.yara"
    },
    {
      "name": "bzrule.yara"
    }
  ]
}
```

### Retrieve specific yara rule

```shell
curl --request GET \
  --url https://tria.ge/api/v0/yara/arkei.yara \
  --header 'Authorization: Bearer <YOUR_ACCESS_KEY>'
```

Result:

```json
{
  "warnings": [
    "info: rule family_arkei: has no triage_score metadata",
    "info: rule family_arkei: has no triage_description metadata"
  ],
  "rule": "rule family_arkei {\n    meta:\n        author = \"Nikos 'n0t' Totosis\"\n        description = \"Arkei Stealer Payload\"\n        triage_family = \"arkei\"\n        triage_tags = \"stealer\"\n\n    strings:\n        $c1 = \"/c timeout /t 5 & del /f /q \\\"%s\\\" & exit\" ascii\n        $c2 = \"BCDEFGHIJKLMNOPQRSTUVWXYZ1234567890\" ascii\n\n        $s1 = \"%dx%d\" ascii\n        $s2 = \"%d/%d/%d %d:%d:%d\" ascii\n        $s3 = \"%s / %s\" ascii\n        $s4 = \"%d MB\" ascii\n        $s5 = \"UTC%d\" ascii\n        $s6 = \"JohnDoe\" ascii\n        $s7 = \"HAL9TH\" ascii\n\n    condition:\n        1 of ($c*) and 4 of ($s*)\n}\n",
  "name": "arkei.yara"
}
```

Non existing rule:

```json
{
  "error": "NOT_FOUND",
  "message": "could not get yara rule: file not found"
}
```

# POST /yara

### Create a new yara rule

```shell
curl --request POST \
  --url https://tria.ge/api/v0/yara \
  --header 'Authorization: Bearer <YOUR_ACCESS_KEY>' \
  --header 'Content-Type: application/json' \
  --data '{
    "name": "arkei.yara",
    "rule": "rule family_arkei {\n    meta:\n        author = \"Nikos '\''n0t'\'' Totosis\"\n        description = \"Arkei Stealer Payload\"\n        triage_family = \"arkei\"\n        triage_tags = \"stealer\"\n\n    strings:\n        $c1 = \"/c timeout /t 5 & del /f /q \\\"%s\\\" & exit\" ascii\n        $c2 = \"BCDEFGHIJKLMNOPQRSTUVWXYZ1234567890\" ascii\n\n        $s1 = \"%dx%d\" ascii\n        $s2 = \"%d/%d/%d %d:%d:%d\" ascii\n        $s3 = \"%s / %s\" ascii\n        $s4 = \"%d MB\" ascii\n        $s5 = \"UTC%d\" ascii\n        $s6 = \"JohnDoe\" ascii\n        $s7 = \"HAL9TH\" ascii\n\n    condition:\n        1 of ($c*) and 4 of ($s*)\n}"
  }'
```

Result

success:

```json
{}
```

Existing rule with that name:

```json
{
  "error": "ERRONEOUS_FILENAME",
  "message": "filename is invalid"
}
```

Compilation error:

```json
{
  "error": "COMPILE_ERROR",
  "message": "Compile Source failed to compile: duplicated identifier \"family_arkei\""
}
```

# PUT /yara

### Update an existing yara rule

Notes:

- When updating a yara rule the compilation can fail. If that is the case the rule name is updated, but the old rule content will remain.
- Both name and rule are always required to be filled, even when changing only one of the attributes.

## Query Parameters

- `name` specify the current rule name in the query `/v0/yara/bazar.yara` Update name and file content:

```shell
curl --request PUT \
  --url https://tria.ge/api/v0/yara/arkei.yara \
  --header 'Authorization: Bearer <YOUR_ACCESS_KEY>' \
  --header 'Content-Type: application/json' \
  --data '{
    "name": "arkei_new.yara"
    "rule": "rule family_arkei {\n    meta:\n        author = \"Nikos 'n0t' Totosis\"\n        description = \"Arkei Stealer Payload\"\n        triage_family = \"arkei\"\n        triage_tags = \"stealer\"\n\n    strings:\n        $c1 = \"/c timeout /t 5 & del /f /q \\\"%s\\\" & exit\" ascii\n        $c2 = \"BCDEFGHIJKLMNOPQRSTUVWXYZ1234567890\" ascii\n\n        $s1 = \"%dx%d\" ascii\n        $s2 = \"%d/%d/%d %d:%d:%d\" ascii\n        $s3 = \"%s / %s\" ascii\n        $s4 = \"%d MB\" ascii\n        $s5 = \"UTC%d\" ascii\n        $s6 = \"JohnDoe\" ascii\n        $s7 = \"HAL9TH\" ascii\n\n    condition:\n        1 of ($c*) and 4 of ($s*)\n}"
  }'
```

Result

success:

```json
{}
```

Existing rule with that name:

```json
{
  "error": "ERRONEOUS_FILENAME",
  "message": "filename is invalid"
}
```

Compilation error:

```json
{
  "error": "COMPILE_ERROR",
  "message": "Compile Source failed to compile: duplicated identifier \"family_arkei\""
}
```

Non existing rule:

```json
{
  "error": "NOT_FOUND",
  "message": "could not get yara rule: file not found"
}
```

# DELETE /yara

### Delete an exising yara rule

```shell
curl --request DELETE \
  --url https://tria.ge/api/v0/yara/arkei.yara \
  --header 'Authorization: Bearer <YOUR_ACCESS_KEY>'
```

success:

```json
{}
```

Non existing rule:

```json
{
  "error": "NOT_FOUND",
  "message": "could not get yara rule: file not found"
}
```
