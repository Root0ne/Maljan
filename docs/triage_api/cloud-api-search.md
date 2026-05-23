# Triage Cloud API - Search

Source: https://tria.ge/docs/cloud-api/search/
Mirrored: 2026-05-23

---

# Logic Operators

Most operators can be combined using basic logic operators to better filter/refine the results. Triage™ supports the following logic:

```
AND
OR
NOT
```

## Examples

```
family:emotet OR family:trickbot
family:smokeloader AND family:zloader
score: 10 AND NOT family
NOT family:emotet
```

# Search Operators

| Search By | Details | Examples |
| --- | --- | --- |
| File Hash | Search based on the hash of a file using one of the supported operators: md5 sha1 sha256 sha512 Note: in the web UI it is not necessary to define an operator for hash lookups. However it is recommended to define it manually in API requests. | md5:2dc87224ef9349f4b281f11fb43ed3f4 sha1:5ff465afaabcbf0150d1a3ab2c2e74f3a4426467 |
| Family | Search based on the family tag assigned by Triage™ after analysis | family:emotet NOT family:emotet family:gozi_ifsb |
| Tags | Search for analyses with a specific behaviour tag applied (see "Available Tags" below for more details) | tag:ransomware tag:miner |
| Botnet | Filter on the botnet tag | botnet:pub1 NOT botnet:pub1 |
| Platform/OS | Filter for Android or Linux analyses. Uses the tag operator like above. | tag:android tag:linux |
| Extracted C2 Data | Search for URLs/domains/IPs dumped by Triage™ configuration extractors. Multiple fields supported: url domain ip Note: defining the operator is not required by Triage™ but is recommended where possible when using the API to reduce chance of misidentification in an automated setup. | url:cloudinoren.club ip:212.186.191.177 domain:smtp.globaloffs-site.com |
| Cryptocurrency Wallets | Search based on cryptocurrency wallet addresses dumped by Triage™ configuration extractors (e.g. from ransomnotes) | wallet:398sW5eMDvyr93CJHKRD3eYE9vK5ELVrHP |
| Date and/or Time of Analysis | Filter analyses based on the time/date at which behavioural analysis was completed. Note that if a sample does not have any behavioural tasks - e.g. because it is an unsupported file type, or was only submitted to the static phase, then the task does not count as complete and will not be returned as part of these results. Operators: from to Dates and times are supported in the yyyy-mm-dd HH:MM:SS format. Operators can be used together to define periods of time. | from:2021-05-01T10:59:00 from:2021-05-01 to:2021-05-31 from:2021-05 to:2021-06-01T23:59:00 |

# Tags

## Available Tags

Below is a list of all the currently available **tags** used in Triage™ signatures. They can be used in search queries with the `tag:` selector.

```
adware
antivm
apt
backdoor
banker
bootkit
botnet
clipper
collection
crypter
discovery
downloader
dropper
evasion
exploit
exploiter
fakeav
ics
infostealer
keylogger
loader
maldoc
miner
overlay
persistence
ransomware
rat
rootkit
spam
spreader
spyware
stealer
trojan
wiper
worm
```

## Colours in search

TRIAGE

PUB1

SIGN1

SMOKELOADER

TROJAN

| Tag type | Tag colour | Example |
| --- | --- | --- |
| Brand | Turquoise |  |
| Botnet | Blue |  |
| Campaign | Purple |  |
| Family | Red |  |
| General | Grey |  |
