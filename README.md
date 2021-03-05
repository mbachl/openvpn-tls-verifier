# OpenVPN TLS Verifier

Allows certificate pinning of client certificates by verifying the certificate fingerprints against a file-based whitelist.

## System requirements
* The code is written for OpenBSD, but should compile on any other Unix-like OS with minor adaptations.
* syslog

## How to build
`gcc -o openvpn-tls-verifier openvpn-tls-verifier.c`

## How to use

### OpenVPN configuration

```
script-security 2
tls-verify "/.../openvpn-tls-verifier allowed-clients"
```

### Certificate pinning file
Create a text file named _allowed-clients_ (or any other filename configured in the _tls-verify_ line), containing the SHA256 fingerprints of the client-certificates following arbitrary descriptive text that is ignored by the verifier.

```
34:87:59:ab:51:ca:09:9b:f8:a6:df:c3:4d:1d:b3:ab:d0:0a:00:1b:71:b6:e2:13:bf:f4:42:ab:97:df:4d:c6 client-certificate-1
67:ab:34:a1:7a:98:f7:16:4d:1b:6c:cb:e6:b6:d0:ab:78:59:f8:0c:ba:a4:8f:fd:ac:db:f8:39:86:89:3c:78 client-certificate-2

```