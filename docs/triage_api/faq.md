# Triage - FAQ

Source: https://tria.ge/docs/faq/
Mirrored: 2026-05-23

---

# Frequently asked questions

#### Can I delete a submission?

> This is our free, public Sandbox. All submissions are publicly visible and cannot be deleted.

We don't allow deletion to prevent people abusing the free Triage™ service.

Users of the [Recorded Future Enterprise Sandbox](https://sandbox.recordedfuture.com/) can delete submissions.

If you are a Recorded Future Sandbox customer and the delete option is not available to you, your user may lack the permissions to delete submissions. Please contact a sandbox administrator for your organisation to have a submission removed.

#### Do you offer private submissions?

All [Tria.ge](https://tria.ge) submissions are publicly visible, if you or your organisation are interested in private analyses please see the [Recorded Future Enterprise Sandbox](https://go.recordedfuture.com/enterprise-sandbox-contact-us) for more details.

Submissions to the Recorded Future Enterprise Sandbox are private by default and only accessible to authorised users in your organisation.

#### What is acceptable use of Triage™?

[Tria.ge](https://tria.ge) public sandbox is intended for the analysis of files and links suspected of containing malicious content.

The following activities are not permitted in the Tria.ge public sandbox:

-
circumventing content filtering

-
accessing adult content or video streaming services

-
playing videogames

-
cryptocurrency mining/hashing

-
copyright infringement

-
offensive hacking

Tria.ge users engaging in any of the above activities will be permanently banned from the platform.

#### What is the maximum runtime of a behavioral analysis?

**API submission**: 1 hour (3600 seconds)

**UI submission**: 15 minutes + *Extend analysis* button (1 minute increments, limited to 10 minutes total)

#### What is the maximum runtime of a behavioral analysis?

**API submission**: 1 hour (3600 seconds)

**UI submission**: 30 minutes + *Extend analysis* button (1 minute increments, limited to 10 minutes total)

#### Where can I find my API key/token?

The API key/token associated with your account can be found on the the Account page when you are logged on Triage™. On this page you will find an 'API access' section containing it.

See [this page](../cloud-api/conventions#authentication) for more information on how to use it.

#### Why is this dropped file not in the downloadable files section?

We try to make informed decisions on which files to expose in the report, mostly to avoid clutter. This unfortunately means some files slip through.

There is a feature that forces Triage™ to dump and expose a file. This can be achieved by manually deleting a file in Windows File Explorer.

See [this blog post](https://hatching.io/blog/dropped-files-ui/#dump-deleted-files) for more information.

Do not hesitate to tell us by using the feedback button if you think a file should have been dumped and exposed.

#### Supported browsers

Below is a list of browsers which are supported for use in the sandbox.

**Note**: Use of any browser not listed below may lead to undefined behaviour during analysis (e.g. incorrect scoring or missing results).

##### Windows

| Browser | Windows 7 | Windows 10 | Windows 11 |
| --- | --- | --- | --- |
| Internet Explorer | X | X |  |
| Google Chrome | X | X | X |
| Microsoft Edge |  | X | X |
| Mozilla Firefox | X | X | X |

##### Linux

Browsers are only available for Linux operating systems with a GUI (amd64)

- Mozilla Firefox

##### MacOS

- Google Chrome

##### Android

- Google Chrome

#### Where is the sample in behavioral analysis?

| OS | Environment variable | Absolute path |
| --- | --- | --- |
| Windows | `%TEMP%` (PowerShell: `$env:Temp`) | `C:\Users\Admin\AppData\Local\Temp` |
| macOS | `$HOME` | `/Users/run` |
| Linux |  | `/tmp/` |

#### What are the VM user passwords?

| OS | User | Password |
| --- | --- | --- |
| macOS | run | root |
| macOS | root | root |

This is subject to change. Other OSs might have changing usernames or passwords.

#### Which PCAP file contains decrypted requests from TLS MITM?

The PCAPNG contains all traffic, including decrypted HTTPS.

Note: that this format requires Wireshark/TShark version 3 or above to open.

#### I see an error when submitting a sample. What do I do?

First, check if you have a stable internet connection.

Some tools, networks and devices might block network traffic containing known malicious files. Try testing if the submission issues are caused by the sample by submitting a harmless file instead (like a small text file). If that works, you can, * Reach out to your device or network administrator to whitelist Sandbox. * Place the files you want to submit in an encrypted ZIP file with the password `infected` before uploading.

#### I have another (technical) question that is not in these docs.

For business inquiries, please contact us at [the web portal.](https://go.recordedfuture.com/enterprise-sandbox-contact-us)

For other questions, feel free to contact us as at [[email protected]](/cdn-cgi/l/email-protection#7605030606190402361e1702151e1f1811581f19). Or, click the feedback button on an analysis page if you have feedback about a specific analysis. This will tell us what analysis the feedback is about.
