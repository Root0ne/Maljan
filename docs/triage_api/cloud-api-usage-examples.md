# Triage Cloud API - Usage Examples

Source: https://tria.ge/docs/cloud-api/usage-examples/
Mirrored: 2026-05-23

---

# Usage Examples

## Interactive sample submission

Submitting a sample in interactive mode allows for the static report to be inspected before analysis starts and the environments to be tweaked.

Interactive submission consists of at least two steps: 1. Submitting a sample with `interactive: true`. This will pause the sample at the `static_analysis` status 2. Setting the profiles to continue with the actual sandbox analysis

Submit the file:

```
$ curl -H 'Authorization: Bearer <YOUR_ACCESS_KEY>' \
    -X POST \
    -F 'file=@<YOUR_SAMPLE_FILE_PATH>' \
    -F '_json={"kind":"file","interactive":true}' \
    'https://tria.ge/api/v0/samples'
```

```json
// Response:
{
  "id": "190724-hakvlwz8cx",
  "status": "pending",
  // ...
}
```

Optional, retrieve the static report to base profile decisions on. It may take some time for the report to become available, Triage™ will indicate this with the `REPORT_NOT_AVAILABLE` error code. If you encounter this, try again after a minute or so.

```
$ curl -H 'Authorization: Bearer <YOUR_ACCESS_KEY>'
    https://tria.ge/api/v0/samples/<SAMPLE_ID>/reports/static | jq
```

Now set one or more profiles to start. You should select a profile you created earlier with the profile API or web interface.

```
$ curl -H 'Authorization: Bearer <YOUR_ACCESS_KEY>' \
    -X POST \
    --data-raw '{"profiles":[{"profile":"<PROFILE_ID>"}]}' \
    'https://tria.ge/api/v0/samples/<SAMPLE_ID>/profile'
# {}
```

Alternatively, you can also just continue with profiles that Triage™ thinks are best by setting `auto: true`.

```
$ curl -H 'Authorization: Bearer <YOUR_ACCESS_KEY>' \
    -X POST \
    --data-raw '{"auto":true}' \
    'https://tria.ge/api/v0/samples/<SAMPLE_ID>/profile'
# {}
```

## Submitting an archive

It is possible to submit an archive and analyse individual files from this archive.

The files should be selected by using the `pick` options, available in both the submission and the profiles selection endpoint.

To select the files immediately when uploading the archive, populate the `profiles` field with the files that should be analysed prefixed with `unpack001/`:

```
$ curl -H 'Authorization: Bearer <YOUR_ACCESS_KEY>' \
    -X POST \
    -F 'file=@<YOUR_SAMPLE_FILE_PATH>' \
    -F '_json={"kind":"file","profiles":[{"pick":"unpack001/evil.bat","profile":"<PROFILE_ID>"}]}' \
    'https://tria.ge/api/v0/samples'
```

```json
// Response:
{
  "id": "190724-hakvlwz8cx",
  "status": "pending",
  // ...
}
```

It is also possible to select the files from the archive when submitting interactively. This also allows you to use the list of extracted files (`.files[].relpath`) from the static report if desired. There are two possibilities of selecting the files.

One is to set the `profiles` parameter just as you would when submitting:

```
$ curl -H 'Authorization: Bearer <YOUR_ACCESS_KEY>' \
    -X POST \
    --data-raw '{"profiles":[{"pick":"unpack001/evil.bat","profile":"<PROFILE_ID>"}]}' \
    'https://tria.ge/api/v0/samples/<SAMPLE_ID>/profile'
# {}
```

Or you can just select the files by setting them in the `pick` field.

```
$ curl -H 'Authorization: Bearer <YOUR_ACCESS_KEY>' \
    -X POST \
    --data-raw '{"pick":["unpack001/evil.bat"]}' \
    'https://tria.ge/api/v0/samples/<SAMPLE_ID>/profile'
# {}
```
