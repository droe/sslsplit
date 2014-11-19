# SSLsplit - transparent and scalable SSL/TLS interception [![Build Status](https://travis-ci.org/droe/sslsplit.svg?branch=master)](https://travis-ci.org/droe/sslsplit)
Copyright (C) 2009-2014, [Daniel Roethlisberger](//daniel.roe.ch/).  
http://www.roe.ch/SSLsplit


## Overview

SSLsplit is a tool for man-in-the-middle attacks against SSL/TLS encrypted
network connections.  Connections are transparently intercepted through a
network address translation engine and redirected to SSLsplit.  SSLsplit
terminates SSL/TLS and initiates a new SSL/TLS connection to the original
destination address, while logging all data transmitted.  SSLsplit is intended
to be useful for network forensics and penetration testing.

SSLsplit supports plain TCP, plain SSL, HTTP and HTTPS connections over both
IPv4 and IPv6.  For SSL and HTTPS connections, SSLsplit generates and signs
forged X509v3 certificates on-the-fly, based on the original server certificate
subject DN and subjectAltName extension.  SSLsplit fully supports Server Name
Indication (SNI) and is able to work with RSA, DSA and ECDSA keys and DHE and
ECDHE cipher suites.  Depending on the version of OpenSSL, SSLsplit supports
SSL 3.0, TLS 1.0, TLS 1.1 and TLS 1.2, and optionally SSL 2.0 as well.
SSLsplit can also use existing certificates of which the private key is
available, instead of generating forged ones.  SSLsplit supports NULL-prefix CN
certificates and can deny OCSP requests in a generic way.  For HTTP and HTTPS
connections, SSLsplit removes response headers for HPKP in order to prevent
public key pinning, for HSTS to allow the user to accept untrusted
certificates, and Alternate Protocols to prevent switching to QUIC/SPDY.

See the manual page sslsplit(1) for details on using SSLsplit and setting up
the various NAT engines.


## Requirements

SSLsplit depends on the OpenSSL and libevent 2.x libraries.
The build depends on GNU make and a POSIX.2 environment in `PATH`.
The optional unit tests depend on the check library.

SSLsplit currently supports the following operating systems and NAT mechanisms:

-   FreeBSD: pf rdr and divert-to, ipfw fwd, ipfilter rdr
-   OpenBSD: pf rdr-to and divert-to
-   Linux: netfilter REDIRECT and TPROXY
-   Mac OS X: pf rdr and ipfw fwd


## Installation

    make
    make test       # optional unit tests
    make install    # optional install

Dependencies are autoconfigured using pkg-config.  If dependencies are not
picked up and fixing `PKG_CONFIG_PATH` does not help, you can specify their
respective locations manually by setting `OPENSSL_BASE`, `LIBEVENT_BASE` and/or
`CHECK_BASE` to the respective prefixes.

You can override the default install prefix (`/usr/local`) by setting `PREFIX`.
For more build options see `GNUmakefile`.


## Development

SSLsplit is being developed on Github.  For bug reports, please use the Github
issue tracker.  For patch submissions, please send me pull requests.

https://github.com/droe/sslsplit


## License

SSLsplit is provided under the simplified BSD license.
SSLsplit contains components licensed under the MIT and APSL licenses.
See the respective source file headers for details.


## Credits

SSLsplit was inspired by `mitm-ssl` by Claes M. Nyberg and `sslsniff` by Moxie
Marlinspike, but shares no source code with them.

SSLsplit includes `khash.h` by Attractive Chaos.


## Contributors

The following individuals have contributed to the SSLsplit codebase by
submitting patches or pull requests, in chronological order of first
contribution:

-   Daniel Roethlisberger (@droe), main author
-   Steve Wills (@swills)
-   Landon Fuller (@landonf)
-   Wayne Jensen (@wjjensen)

See NEWS.md and `git log` for details.


