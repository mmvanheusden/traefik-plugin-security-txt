# Security.txt Traefik plugin

**This repo is derived from: <https://github.com/solution-libre/traefik-plugin-robots-txt>**

<!-- markdownlint-disable-next-line MD001 -->

#### Table of Contents

1. [Description](#description)
2. [Setup](#setup)
3. [Usage](#usage)
4. [Fields](#fields)
5. [Development](#development)
6. [Contributors](#contributors)

## Description

Security.txt is a middleware plugin for [Traefik](https://traefik.io/) which easily adds a [`security.txt`](https://securitytxt.org/) to your site. It is fully RFC 9116 compliant.

## Setup

```yaml
# Static configuration

experimental:
  plugins:
    security-txt:
      moduleName: github.com/mmvanheusden/traefik-plugin-security-txt
      version: v0.1.0
```

## Usage

```yaml
# Dynamic configuration

http:
  routers:
    my-router:
      rule: host(`localhost`)
      service: service-foo
      entryPoints:
        - web
      middlewares:
        - my-security-txt

  services:
    service-foo:
      loadBalancer:
        servers:
          - url: http://127.0.0.1

  middlewares:
    my-security-txt:
      plugin:
        security-txt:
          expires: "2027-12-31T18:37:07Z" # Should be ISO 8601
          contact: ["mailto:security@example.com"]
          policy: "https://example.com/disclosure-policy.html"
          preferredLanguages: ["nl", "en"]
```

## Fields

**See: <https://www.rfc-editor.org/info/rfc9116/#name-field-definitions>**

| Name               | Description                                                                                                                                                                 | Notice                                                                                                   | Required | Example                                                |
| ------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------- | -------- | ------------------------------------------------------ |
| contact            | Indicates a method that researchers should use for reporting security vulnerabilities such as an email address, a phone number, and/or a web page with contact information. | Must be listed in order of preference. See <https://www.rfc-editor.org/info/rfc9116/#name-contact>       | YES      | `["mailto:security@example.com"]`                      |
| expires            | Indicates the date and time after which the data contained in the file is considered stale and should not be used.                                                          | Must be ISO 8601. See <https://www.rfc-editor.org/info/rfc9116/#name-expires>                            | YES      | `2027-12-31T18:37:07.000Z`                             |
| acknowledgments    | Indicates a link to a page where security researchers are recognized for their reports.                                                                                     | See <https://www.rfc-editor.org/info/rfc9116/#name-acknowledgments>                                      | NO       | `https://example.com/hall-of-fame`                     |
| canonical          | Indicates the canonical URIs where the "security.txt" file is located.                                                                                                      | See <https://www.rfc-editor.org/info/rfc9116/#name-canonical>                                            | NO       | `["https://www.example.com/.well-known/security.txt"]` |
| encryption         | Indicates an encryption key that security researchers should use for encrypted communication.                                                                               | Must be URIs. See <https://www.rfc-editor.org/info/rfc9116/#name-encryption>                             | NO       | `https://example.com/pgp-key.txt`                      |
| hiring             | Used for linking to the vendor's security-related job positions.                                                                                                            | See <https://www.rfc-editor.org/info/rfc9116/#name-hiring>                                               | NO       | `https://example.com/jobs`                             |
| policy             | Indicates a link to where the vulnerability disclosure policy is located.                                                                                                   | See <https://www.rfc-editor.org/info/rfc9116/#name-policy>                                               | NO       | `https://example.com/disclosure-policy`                |
| preferredLanguages | Used to indicate a set of natural languages that are preferred when submitting security reports.                                                                            | Languages tags must be RFC 5646. See <https://www.rfc-editor.org/info/rfc9116/#name-preferred-languages> | NO       | `["nl", "en"]`                                         |
| enableComment      | Prepend comment that identifies this plugin in Security.txt. **ENABLED BY DEFAULT**                                                                                         |                                                                                                          | NO       | `false`                                                |
| overwrite          | Remove the original Security.txt file content. **ENABLED BY DEFAULT**                                                                                                       |                                                                                                          | NO       | `true`                                                 |
| lastModified       | If `true`, doesn't leave out the `Last-Modified` header.                                                                                                                    |                                                                                                          | NO       | `true`                                                 |

## Development

**This repo was forked from: <https://github.com/solution-libre/traefik-plugin-robots-txt>**

[Fork this repo on GitHub](https://github.com/mmvanheusden/traefik-plugin-security-txt/fork)

## Contributors

The list of contributors can be found at: <https://github.com/mmvanheusden/traefik-plugin-security-txt/graphs/contributors>
