# Triage Cloud API - Samples

Source: https://tria.ge/docs/cloud-api/samples/
Mirrored: 2026-05-23

---

# GET /samples

Queries the collection of samples submitted by requester.

## Query Parameters

- `subset` (default `owned`), if set to `owned`, all the samples that the requesting user is able to access are returned. If set to `public` all samples that can be viewed by any user returned (this feature is only available on the public cloud). If set to `org`, all organization samples are listed.

# POST /samples

Review the documentation on how to submit samples on the [sample submission](../submit/) page.

# GET /samples/{sampleID}

Queries the sample with the specified ID.

## Examples:

```
$ curl -H 'Authorization: Bearer <YOUR_ACCESS_KEY>' \
    'https://tria.ge/api/v0/samples/<SAMPLE_ID>'
```

```json
// Response:
{
  "id": "190724-hakvlwz8cx",
  "status": "reported",
  "kind": "file",
  "filename": "evil.bat",
  "private": true,
  "submitted": "2019-07-24T13:32:07.253524Z",
  "user_id": "59b43c0d-3bbe-495b-a80c-349a4c058426"
}
```

## Errors

- `404, "NOT_FOUND"`, if the sample does not exist.

# GET /search

The Search API endpoint supports all filters and queries which can be used through the web interface, and allow you to search available analyses for a range of IoCs or file characteristics.

The Search query should be placed in the `query` GET parameter.

For more information on the options available, check out the dedicated Search documentation [here](/docs/cloud-api/search/).

You can also find more information in [this blogpost](https://hatching.io/blog/tt-2020-10-23/) and on the [Search page in Triage™](/s/).

## Search examples

```
$ curl -H 'Authorization: Bearer <YOUR_ACCESS_KEY>' \
    'https://tria.ge/api/v0/search?query=family:emotet'
```

```json
{
  "data": [
    {
      "id": "201026-n8zz26cd4s",
      "status": "reported",
      "kind": "file",
      "filename": "888d012fd36d8fa86ab57e0d547eb429e68303fcdf76b08191942e9307a74f78",
      "private": false,
      "submitted": "2020-10-26T16:51:31Z",
      "completed": "2020-10-26T16:52:55Z",
      "user_id": "59b43c0d-3bbe-495b-a80c-349a4c058426"
    },
    ...
  ],
  "next": "2020-10-26T16:51:21.232458Z"
}
```

# GET /samples/{sampleID}/sample

Downloads the originally submitted sample for the chosen analysis ID.

**Note**: unlike the UI sample download, samples downloaded via the API are not additionally zipped/encrypted.

## Examples:

```
$ curl -H 'Authorization: Bearer <YOUR_ACCESS_KEY>' \
    'https://tria.ge/api/v0/samples/<SAMPLE_ID>/sample' \
    --output sample.bin
```

# GET /samples/{sampleID}/summary

Returns a short summary of the sample and its analysis tasks.

## Examples:

```
$ curl -H 'Authorization: Bearer <YOUR_ACCESS_KEY>' \
    'https://tria.ge/api/v0/samples/<SAMPLE_ID>/summary'
```

```json
// Response:
{
  "sample": "200606-l5dz9871we",
  "status": "reported",
  "custom": "frontend:7de1d1a3-f39b-4dd6-8a8d-b9d6bc0e7c81",
  "owner": "shark2.ams5.hatching.io",
  "target": "05af0cf40590aef24b28fa04c6b4998b7ab3b7f26e60c507adb84f3d837778f2",
  "created": "2020-06-06T00:03:27Z",
  "completed": "2020-06-06T00:06:10Z",
  "score": 10,
  "sha256": "05af0cf40590aef24b28fa04c6b4998b7ab3b7f26e60c507adb84f3d837778f2",
  "tasks": {
    "200606-l5dz9871we-behavioral1": {
      "kind": "behavioral",
      "status": "reported",
      "tags": [
        "evasion",
        "trojan",
        "persistence",
        "ransomware"
      ],
      "score": 10,
      "target": "05af0cf40590aef24b28fa04c6b4998b7ab3b7f26e60c507adb84f3d837778f2.exe",
      "backend": "horse2",
      "resource": "win7v200430",
      "platform": "windows7_x64",
      "queue_id": 1353974
    },
    "200606-l5dz9871we-behavioral2": {
      "kind": "behavioral",
      "status": "reported",
      "tags": [
        "evasion",
        "trojan",
        "ransomware",
        "persistence"
      ],
      "score": 10,
      "target": "05af0cf40590aef24b28fa04c6b4998b7ab3b7f26e60c507adb84f3d837778f2.exe",
      "backend": "horse2",
      "resource": "win10v200430",
      "platform": "windows10_x64",
      "queue_id": 1353975
    },
    "200606-l5dz9871we-static1": {
      "kind": "static",
      "status": "reported"
    }
  }
}
```

## Errors

- `404, "NOT_FOUND"`, if the sample does not exist.

# GET /samples/{sampleID}/overview.json

Returns the overview of the sample and its analysis tasks. The overview contains a one-pager with all the high-level information related to the sample including malware configuration, signatures, scoring, etc.

The exact definition of the Overview report, described in the Golang programming language, can be found at the [Overview Report](../overview-report) page.

## Examples:

```
$ curl -H 'Authorization: Bearer <YOUR_ACCESS_KEY>' \
    'https://tria.ge/api/v0/samples/<SAMPLE_ID>/overview.json'
```

```json
// Response:
{
  "version": "0.2.2",
  "sample": {
    "id": "200916-w52vg1yl1a",
    "target": "131.doc",
    "size": 547328,
    "md5": "3e241f5a1e7be77f25078560c8660351",
    "sha1": "ba25c371e75d1a52c1f41c163dc8840626423948",
    "sha256": "22d653dab4765e13c5fce0bf46a28a098d05582148fdf3101093f3687b42a5f1",
    "sha512": "4f031f6a3e44687ca65ceec847aacf3053feec0882bd5c07febef85ba1a7570ec1f4357446dfc84226448e1d8eb342066eeb3e6e7394d53caadd66223a2ff345"
  },
  "tasks": {
    "200916-w52vg1yl1a-behavioral1": {
      "kind": "behavioral",
      "status": "reported",
      "tags": [
        "spyware",
        "trojan",
        "banker",
        "family:trickbot"
      ],
      "score": 10,
      "target": "131.doc",
      "backend": "fu1m1",
      "resource": "win10v200722",
      "platform": "windows10_x64",
      "task_name": "300 seconds - Win. 10",
      "queue_id": 1911088
    },
    "200916-w52vg1yl1a-static1": {
      "kind": "static",
      "status": "reported"
    }
  },
  "analysis": {
    "score": 10
  },
  "targets": [
    {
      "tasks": [
        "behavioral1"
      ],
      "score": 10,
      "target": "131.doc",
      "size": 547328,
      "md5": "3e241f5a1e7be77f25078560c8660351",
      "sha1": "ba25c371e75d1a52c1f41c163dc8840626423948",
      "sha256": "22d653dab4765e13c5fce0bf46a28a098d05582148fdf3101093f3687b42a5f1",
      "sha512": "4f031f6a3e44687ca65ceec847aacf3053feec0882bd5c07febef85ba1a7570ec1f4357446dfc84226448e1d8eb342066eeb3e6e7394d53caadd66223a2ff345",
      "tags": [
        "spyware",
        "trojan",
        "banker",
        "family:trickbot"
      ],
      "family": [
        "trickbot"
      ],
      "signatures": [
        {
          "label": "trickbot",
          "name": "Trickbot",
          "score": 10,
          "tags": [
            "trojan",
            "banker",
            "family:trickbot"
          ],
          "desc": "Developed in 2016, TrickBot is one of the more recent banking Trojans."
        },
        ...
      ]
    }
  ],
  "extracted": [
      ...
    {
      "tasks": [
        "behavioral1"
      ],
      "dumped_file": "extracted/trickbot.payload-3",
      "resource": "behavioral1/memory/3212-19-0x0000000000A20000-0x0000000000A56000-memory.dmp",
      "config": {
        "family": "trickbot",
        "rule": "Trickbot2019",
        "c2": [
          "51.89.163.40:443",
          "89.223.126.186:443",
          "45.67.231.68:443",
          "148.251.185.165:443",
          "194.87.110.144:443",
          "213.32.84.27:443",
          "185.234.72.35:443",
          "45.89.125.148:443",
          "195.123.240.104:443",
          "185.99.2.243:443",
          "5.182.211.223:443",
          "195.123.240.113:443",
          "85.204.116.173:443",
          "5.152.210.188:443",
          "103.36.48.103:449",
          "36.94.33.102:449",
          "36.91.87.227:449",
          "177.190.69.162:449",
          "103.76.169.213:449",
          "179.97.246.23:449",
          "200.24.67.161:449",
          "181.143.186.42:449",
          "190.99.97.42:449",
          "179.127.88.41:449",
          "117.252.214.138:449",
          "117.222.63.145:449",
          "45.224.213.234:449",
          "45.237.241.97:449",
          "125.165.20.104:449"
        ],
        "version": "1000514",
        "botnet": "ono76",
        "keys": [
          {
            "kind": "ecc_pubkey.base64",
            "key": "ecc_pubkey",
            "value": "RUNTMzAAAADzIIbbIE3wcze1+xiwwK+Au/P78UrAO8YAHyPvHEwGVKOPphl8QVfrC7x/QaFYeXANw6E4HF7ietEp+7ZVQdWOx8c+HvO0Z2PTUPVbX9HAVrg4h9u1RNfhOHk+YysDLsg="
          }
        ],
        "attr": {
          "autorun": [
            {
              "name": "pwgrab",
              "control": ""
            }
          ]
        }
      }
    }
  ]
}
```

## Errors

- `404, "NOT_FOUND"`, if the sample does not exist.

# DELETE /samples/{sampleID}

Deletes the sample with the specified ID.

Note: on our [public cloud](https://tria.ge/) users and researchers are *NOT* able to delete samples on their own. Please contact support for doing so.

## Examples:

```
$ curl -H 'Authorization: Bearer <YOUR_ACCESS_KEY>' \
    -X DELETE \
    'https://tria.ge/api/v0/samples/<SAMPLE_ID>'
# {}
```

## Errors

- `404, "NOT_FOUND"`, if the sample does not exist.

# POST /samples/{sampleID}/profile

When a sample is in the `static_analysis` status, a profile should be selected in order to continue.

| Key | Type | Description |
| --- | --- | --- |
| `auto` | Boolean | Whether to have the system automatically select profiles. |
| `pick` | Array | If an archive was submitted, the set of files to run with automatic profiles. |
| `profiles` | Array | A mapping of one or more files to one or more profiles. |

Please refer to sample submission on how `profiles` should be specified.

The values in pick should be a subset of `.files[].relpath` from the static report.

## Examples:

Set a profile automatically:

```
$ curl -H 'Authorization: Bearer <YOUR_ACCESS_KEY>' \
    -X POST \
    --data-raw '{"auto":true}' \
    'https://tria.ge/api/v0/samples/<SAMPLE_ID>/profile'
# {}
```

Set a profile manually by specifying its ID or name:

```
$ curl -H 'Authorization: Bearer <YOUR_ACCESS_KEY>' \
    -X POST \
    --data-raw '{"profiles":[{"profile":"<PROFILE_ID>"}]}' \
    'https://tria.ge/api/v0/samples/<SAMPLE_ID>/profile'
# {}
```

If an archive was submitted and a custom selection of files should be made but have the system determine the profiles to use:

```
$ curl -H 'Authorization: Bearer <YOUR_ACCESS_KEY>' \
    -X POST \
    --data-raw '{"pick":["unpack001/file.exe"]}' \
    'https://tria.ge/api/v0/samples/<SAMPLE_ID>/profile'
# {}
```

## Errors

- `404, "NOT_FOUND"`, if the sample does not exist.
- `409, "PROFILE_NOT_SETTABLE"`, the profile could not be set due to the status of the sample not being `static_analysis` or the analysis not being interactive.

# GET /samples/{sampleID}/reports/static

Retrieves the generated [static report](../static-report).

## Examples

```
$ curl -H 'Authorization: Bearer <YOUR_ACCESS_KEY>'
    https://tria.ge/api/v0/samples/<SAMPLE_ID>/reports/static | jq
```

## Errors

- `404, "NOT_FOUND"`, if the sample does not exist.
- `404, "REPORT_NOT_AVAILABLE"`, if the status of the sample is before `"static_analysis"` or the status is `"failed"`.

# GET /samples/{sampleID}/{taskID}/report_triage.json

Retrieves the generated Triage™ Report for a single task.

## Examples

```
$ curl -H 'Authorization: Bearer <YOUR_ACCESS_KEY>' \
    https://tria.ge/api/v0/samples/<SAMPLE_ID>/behavioral1/report_triage.json | jq
```

## Errors

- `404, "NOT_FOUND"`, if the sample does not exist.
- `404, "REPORT_NOT_AVAILABLE"`, if the status of the task is not `"reported"`.

# GET /samples/{sampleID}/events

Opens an [JSONL](https://jsonlines.org/) stream to keep track of the progress of a sample in real time. The stream consists of a series of events labeled `sample` with a JSON encoded sample object as payload.

When the connection is opened, the current status of the sample is always sent.

After a sample with a terminal status (`"reported"`, `"failed"`) is sent, the connection is closed. The client should not attempt to reconnect since no further updates will be sent.

## Examples

```
$ curl -H 'Authorization: Bearer <YOUR_ACCESS_KEY>' \
    'https://tria.ge/api/v0/samples/<SAMPLE_ID>/events'
```

## Errors

- `404, "NOT_FOUND"`, if the sample does not exist.

# GET /samples/events

Opens an [JSONL](https://jsonlines.org/) event stream that will relay changes to the state of all samples the querying user is able to see. The format is the same as `/samples/{sampleID}/events` except that no initial state is sent.

## Examples

```
$ curl -H 'Authorization: Bearer <YOUR_ACCESS_KEY>' \
    'https://tria.ge/api/v0/samples/events'
```

# GET /samples/{sampleID}/{taskID}/logs/onemon.json

Retrieves the output of the kernel monitor in JSON format.

## Examples

```
$ curl -H 'Authorization: Bearer <YOUR_ACCESS_KEY>' \
    'https://tria.ge/api/v0/samples/{sampleID}/{taskID}/logs/onemon.json' \
    --output log.json
```

# GET /samples/{sampleID}/{taskID}/dump.pcap

Retrieves the PCAP of the analysis for further manual analysis.

## Examples

```
$ curl -H 'Authorization: Bearer <YOUR_ACCESS_KEY>' \
    'https://tria.ge/api/v0/samples/{sampleID}/{taskID}/dump.pcap' \
    --output dump.pcap
```

# GET /samples/{sampleID}/{taskID}/dump.pcapng

Retrieves PCAPNG for the analysis which contains all traffic, including decrypted HTTPS.

Note that this format requires Wireshark/TShark version 3 or above to open.

## Examples

```
$ curl -H 'Authorization: Bearer <YOUR_ACCESS_KEY>' \
    'https://tria.ge/api/v0/samples/{sampleID}/{taskID}/dump.pcapng' \
    --output dump.pcapng
```

# GET /samples/{sampleID}/{taskID}/files/{fileName}

Retrieves files dumped by the sample. The names can be found under the "dumped" section in the [report_triage.json](#get-samplessampleidtaskidreport_triagejson) file

## Examples

### Dropped file

```
$ curl -H 'Authorization: Bearer <YOUR_ACCESS_KEY>' \
    'https://tria.ge/api/v0/samples/{sampleID}/{taskID}/files/{fileName}' \
    --output file.exe
```

### Memory dump

```
$ curl -O -J -H 'Authorization: Bearer <YOUR_ACCESS_KEY>' \
    'https://tria.ge/api/v0/samples/{sampleID}/{taskID}/memory/{memoryDump}'
```

# GET /samples/{sampleID}/urlscan1/report_urlscan.json

CAUTION

The structure of the JSON returned by this API is managed externally. We do not have control over its contents. The actual format and data may vary.

Retrieves the UrlScan report in json format.

## Examples

```
$ curl -H 'Authorization: Bearer <YOUR_ACCESS_KEY>' \
    'https://tria.ge/api/v0/samples/{sampleID}/urlscan1/report_urlscan.json' \
    --output urlscan.json
```

# GET /samples/{sampleID}/urlscan1/screenshot.png

Retrieves a screenshot provided by UrlScan. This feature is only accessible if the target is a URL.

## Examples

```
$ curl -H 'Authorization: Bearer <YOUR_ACCESS_KEY>' \
    'https://tria.ge/api/v0/samples/{sampleID}/urlscan1/screenshot.png' \
    --output screenshot.png
```

# GET /samples/{sampleID}/magic

Retrieves the Magic Token associated with this sample. Can be used to craft the final URL.

## Examples

```
$ curl -H 'Authorization: Bearer <YOUR_ACCESS_KEY>' \
    'https://tria.ge/api/v0/samples/{sampleID}/magic'
"<magictoken>"

# Sample URL including Magic Token would then be:
# https://private.tria.ge/{sampleID}/magic/{magictoken}
```

# The Sample Object

```json5
{
  // The unique ID of this sample.
  "id": "190329-rerrjddcaj", // string

  // The current status of the analysis process. Can be any of the values
  // listed below:
  //
  // "pending"
  // A sample has been submitted and is queued for static analysis or the
  // static analysis is in progress.
  //
  // "static_analysis"
  // The static analysis report is ready. The sample will remain in this
  // status until a profile is selected.
  //
  // "scheduled"
  // All parameters for sandbox analysis have been selected. The sample is
  // scheduled for running on the sandbox.
  //
  // "running"
  // The sample is being run by the sandbox.
  //
  // "processing"
  // The sandbox has finished running the sample and the resulting metrics
  // are being processed into reports.
  //
  // "reported"
  // The sample has reports that can be retrieved. This status is terminal.
  //
  // "failed"
  // Analysis of the sample has failed. Any other status may transition into
  // this status. This status is terminal.
  "status": "reported", // string

  // The sample kind that was submitted. Either "file" or "url".
  "kind": "file", // string

  // If the sample kind is file, this is the name of the uploaded file.
  // Otherwise, this field is omitted.
  "filename": "evil.bat", // string

  // If the sample kind is url, this is the url that was submitted. Otherwise,
  // this field is omitted.
  "url": "http://example.com/evil.js", // string

  // If true, the sample can be viewed by only the requesting user or
  // organization the user belongs to. If false, the sample can be viewed by
  // anyone with a Recorded Future: Sandbox account.
  "private": false, // bool

  // The time this sample was submitted.
  "submitted": "2019-04-05T13:37:00Z", // timestamp string

  // The time the analysis has been completed and a behavioral report has been
  // generated. Only present if the status is equal to "reported".
  "completed": "2019-04-05T13:42:00Z", // timestamp string

  // The submitter's user ID. Will be omitted if the submitter's account no longer exists.
  "user_id": "59b43c0d-3bbe-495b-a80c-349a4c058426"

}
```
