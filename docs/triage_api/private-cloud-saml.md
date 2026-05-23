# Triage Private Cloud - SAML Setup

Source: https://tria.ge/docs/private-cloud/saml/
Mirrored: 2026-05-23

---

# SAML SSO Configuration

## Introduction

Triage™ Private Cloud supports SAML authentication to enable SSO for your organization. This document describes the steps required to enable SAML authentication.

Only *Service Provider (SP) initiated SSO* is supported. IdP initiated SSO will fail.

## 1. Request SAML SSO

Contact [[email protected]](/cdn-cgi/l/email-protection#a5d6d0d5d5cad7d1e5d7c0c6cad7c1c0c1c3d0d1d0d7c08bc6cac8) mentioning:

- Your Identity Provider (IdP) (e.g. `Okta`, `Azure`, `Google`)
- Which (if any) email domains you would like automatically redirected to your SSO ( like: `@recordedfuture.com`,`@hatching.io`)

Support will then provide you:

- Single Sign-on (ACS) URL `https://private.tria.ge/sso/<unique identifier>/saml/acs`
- Service Provider Entity ID URL `https://private.tria.ge/sso/<unique identifier>/saml/metadata`
- SSO start URL `https://private.tria.ge/login/saml/<unique identifier>`

These URLs are required to set up SAML in your Identity Provider (IdP).

## 2. Add Sandbox to your Identity Provider (IdP)

Configure SAML in your IdP with the provided **unique** `ACS` and `Entity ID` URLs. Configure the app registration to send the following attributes.

### Required attributes

| Attribute name | Description |
| --- | --- |
| email | User Email. Will also be used to link IdP account to pre-existing user in Sandbox. |
| If `nameid-format` is set to `emailAddress` in your IdP, Sandbox will use the nameID value as the user's email address. |  |
| We recommend providing the `email` attribute explicitly and setting NameIDPolicy `Format` to `persistent`. |  |

### Optional attributes

| Attribute name | Description |
| --- | --- |
| displayname | Name displayed in Sandbox |
| **or** |  |
| firstname | First name |
| lastname | Last name |
|  |  |
| sandbox_role | Role for user (like: `org_advanced`). See [role matrix](/docs/cloud-api/users/#role-matrix) for more info |

Triage™ supports SAML SSO through `Okta`, `Google` and `Azure`. Be sure to let us know if you require other identity providers.

**IdP** specific setup guides:

- [Okta](./okta)
- [Microsoft Azure](./azure)
- [Google](./google)

## 3. Share your SAML IdP Metadata file

Share your XML file with Support([[email protected]](/cdn-cgi/l/email-protection#98ebede8e8f7eaecd8eafdfbf7eafcfdfcfeedecedeafdb6fbf7f5)) via a file attachment or link. Support will send out a notification once SAML has been configured for testing. username+password logins will continue to work.

## 4. Test logging in through SSO

Support will provide you an *SSO start URL* (example: `https://private.tria.ge/login/saml/<unique identifier>`) which can be used to initiate SSO directly. Test signing in with a user by navigating to this URL.

Reach out to Support([[email protected]](/cdn-cgi/l/email-protection#2d5e585d5d425f596d5f484e425f4948494b5859585f48034e4240)) to let them know SAML is configured correctly.

## Finally

Support will disable username+password login. Existing users will be automatically redirected to SSO. New users signing in with provided email domains or users navigating to the *SSO start URL* will be redirected to SSO.
