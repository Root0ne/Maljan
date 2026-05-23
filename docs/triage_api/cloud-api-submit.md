# Triage Cloud API - Sample submission

Source: https://tria.ge/docs/cloud-api/submit/
Mirrored: 2026-05-23

---

# Submitting samples

# POST /samples

This endpoint allows both files and URLs to be submitted. Samples can be submitted using automatic mode for high-volume analysis, as well as interactive mode. In interactive mode, you must manually choose how to analyze the sample after static analysis of the sample has completed.

## Required fields

| Key | Type | Description |
| --- | --- | --- |
| `kind` | String | One of: `file`, `url`, `fetch` or `import` |

## Optional fields

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `file` | File |  | The uploaded file. Requires `kind` to be set to `"file"` |
| `interactive` | Boolean | `false` | If set to true, the analysis profile must be chosen manually after static analysis has finished |
| `password` | String |  | A password that may be used to decrypt the provided file, usually an archive (zip/rar/etc) |
| `profiles` | Array |  | A mapping of one or more files to one or more (embedded) profiles |
| `url` | String |  | The URL to use as sample. Requires `kind` to be set to `"url"` or `"fetch"` |
| `defaults.timeout` | Int |  | The timeout in seconds for behavioral analysis (maximum 3600) |
| `defaults.network` | String | `internet` | Controls internet connectivity type for behavioral analysis |

If `interactive` is set to *true*, analysis pauses when the sample status reaches `static_analysis`. To continue, you must manually start the analysis.

## JSON example

The following object describes the parameters one could specify in their submission:

```json5
{
    // Optionally specify the kind of submission this is. If not defined, kind
    // is inferred from the other parameters. See below for examples of each
    // type of submission.
    "kind": "file" | "url" | "fetch" | "import",

    // Submit a URL to use as sample. If kind is "fetch", the URL is downloaded
    // as file instead of executed directly in a browser.
    "url": "http://example.com/malware.exe",

    // Optional: manually specify the filename of the sample. If not specified,
    // the filename of the attached file is used. Not applicable to "url"
    "target": "my-malware.exe",

    // Optional: defaults to false.  If set to true, the analysis profile must be
    // chosen manually after static analysis has finished.
    "interactive": false,

    // Optional: A password that may be used to decrypt the provided file,
    // usually an archive (zip/rar/etc).
    "password": "infected",

    // Optional: A mapping of one or more files to one or more (embedded) profiles.
    "profiles": [...],

    // Experimental: an optional array of user-defined strings that lets the
    // user mark a sample. The resulting tags will be embedded in the reports.
    // The total size cannot exceed 1kB and tags cannot be empty.
    "user_tags": ["id:123789", "source:smtp"],

    // The optional defaults object specifies base parameters to use for
    // automatic analysis.
    "defaults": {
        // Optional: Specify the timeout of the analysis (in seconds, maximum 3600).
        "timeout": 60,

        // Optional: defaults to "internet". Specify the type of network
        // routing to use in behavioral analysis.
        "network": "internet" | "drop" | "tor"
    }
}
```

# Submitting a file

File submissions are required to be performed using the `multipart/form-data` scheme. The field name of uploaded file should be `file` and the file should have a filename. Optionally override the filename with the `target` field.

Because submitting a JSON payload when submitting a multipart upload can be difficult, the submission parameters can be submitted in one of two ways:

- For simple submissions, encode the parameters as form values instead of JSON. Nested objects can be specified with a period (e.g. `defaults.network`). Array fields can be specified multiple times.
- Alternatively, the JSON parameter payload can be encoded as a form field with key `_json`. This is required when using nested fields such as `profiles`.

See below for examples.

## File submission examples

Submitting a file:

```
$ curl -H 'Authorization: Bearer <YOUR_ACCESS_KEY>' \
    -F 'file=@<YOUR_SAMPLE_FILE_PATH>' \
    https://tria.ge/api/v0/samples
```

```json
// Response:
{
  "id": "190724-hakvlwz8cx",
  "status": "running",
  "kind": "file",
  "filename": "evil.bat",
  "private": true,
  "submitted": "2019-07-24T13:32:07.253524Z"
}
```

Submitting a file with JSON parameters:

```
$ curl -H 'Authorization: Bearer <YOUR_ACCESS_KEY>' \
    -F '_json={"kind":"file","defaults":{"timeout": 60, "network":"drop"}}' \
    -F 'file=@<YOUR_SAMPLE_FILE_PATH>' \
    https://tria.ge/api/v0/samples
```

Submitting a password-protected .zip file:

```
$ curl -H 'Authorization: Bearer <YOUR_ACCESS_KEY>' \
    -F password=mysecret \
    -F 'file=@<YOUR_ZIP_FILE_PATH>' \
    https://tria.ge/api/v0/samples
```

Submitting a file with custom filename, user tags, and Tor network routing:

```
$ curl -H 'Authorization: Bearer <YOUR_ACCESS_KEY>' \
    -F target=custom-filename.bat \
    -F user_tags=4e2000db-6b18-4c25-9876-748aaa808a32 \
    -F user_tags=source:1234 \
    -F default.network=tor \
    -F 'file=@<YOUR_ZIP_FILE_PATH>' \
    https://tria.ge/api/v0/samples
```

# Submitting a URL

To submit a URL, you must do one of the following:

- Set the `"url"` parameter
- Specify `"kind"` to be `"url"` and `"target"` to be the URL

It's not possible to mix file upload and URL submissions.

# Submitting using a different Geolocation

To analyze a sample using a specific geographic location, you can use the VPN network option combined with the geolocation parameter. This allows you to simulate running a sample from different regions.

## Required settings

- Set `defaults.network` to `"vpn"`
- Specify the desired region in the `defaults.geolocation` parameter

To see which regions are available, visit [the geolocation documentation](../geolocations/)

```shell
$ curl -H 'Authorization: Bearer <YOUR_ACCESS_KEY>' \
-F '_json={"kind": "url","target": "https://example.org","defaults": {"timeout": 60, "network": "vpn", "geolocation": "north-america"}}' \
https://tria.ge/api/v0/samples
```

## Fetching a sample from a URL

In some use-cases it's desirable to submit a URL from which Triage™ will download the sample itself. E.g., the sample could be located in AWS S3, your own website, etc.

To have Triage™ fetch the sample from a URL, you must set `kind` to `"fetch"` and include the URL of the sample as `url` or `target`.

## Import a sample from public Triage™

The `import` kind imports the sample from https://tria.ge/ and submits it on environment you are on. This is currently only supported on the cloud environments and only for importing file analyses.

Set `kind` to `import` and `url` to the public Triage™ sample you want to import.

```shell
$ curl -H 'Authorization: Bearer <YOUR_ACCESS_KEY>' \
    -F kind=import \
    -F url="https://tria.ge/250303-rhl3gszvdw" \
    https://private.tria.ge/api/v0/samples
```

Note that you can also specify just the sample/analysis ID (in this case "220202-rs4ehsacen") instead of the full https://tria.ge/ URL.

## URL submission examples

Submitting a URL:

```
$ curl -H 'Authorization: Bearer <YOUR_ACCESS_KEY>' \
    -F url=http://example.org/ \
    https://tria.ge/api/v0/samples
```

Fetching a sample from a URL:

```shell
# As form:
$ curl -H 'Authorization: Bearer <YOUR_ACCESS_KEY>' \
    -F kind=fetch \
    -F url=https://hostname.tld/sample.exe \
    https://tria.ge/api/v0/samples

# As JSON:
$ curl -H 'Authorization: Bearer <YOUR_ACCESS_KEY>' \
    -H 'Content-Type: application/json' \
    -d '{"kind": "fetch", "url": "https://hostname.tld/sample.exe"}'
    https://tria.ge/api/v0/samples
```

# Choosing a profile

Selecting a profile allows more to control over the virtual environment that is used to run the sample. Selecting a profile requires `interactive` to be false.

Profiles can be selected by adding them to the `profiles` array as shown below:

```json5
{
  "profiles": [
    {
      // The ID or name of the profile to use.
      "profile": "myprofilename",
      // If an archive is submitted, specify the filename in the archive this
      // profile should be used for (as per this example). This field can be
      // omitted if a single file is submitted (alternatively "sample" also
      // selects the submitted file).
      "pick": "unpack001/something.exe"
    }
  ],
  // Other options
}
```

A file may be selected multiple times with different profiles so it will be executed in different environments.

Please refer to [the documentation](../samples/#post-samplessampleidprofile) for `POST /samples/{sampleID}/profile`.

## Using an embedded profile

[Profile contents](../profiles/#the-profile-object) can also be embedded in the `profile` key. This means the profile does not have to exist and you can directly specify the settings per picked file.

You can only use available resource tags. See the [resources API](../resources/) for querying available resources to include in a profile.

```json5
{
  "profiles": [
    {
      // The ID or name of the profile to use.
      "profile": {
        // Tags must be of existing resource tags, such as 'os'.
        "tags": ["os:windows10-2004-x64", "locale:en-us"],
      },
      // If an archive is submitted, specify the filename in the archive this
      // profile should be used for (as per this example). This field can be
      // omitted if a single file is submitted (alternatively "sample" also
      // selects the submitted file).
      "pick": "unpack001/something.exe"
    }
  ],
  // Other options
}
```

Please refer to [the profile documentation](../profiles/#post-profiles) to see the available fields and how to create profiles.
