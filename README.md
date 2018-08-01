# SSLsplit - transparent SSL/TLS interception [![Build Status](https://travis-ci.org/droe/sslsplit.svg?branch=master)](https://travis-ci.org/droe/sslsplit)
Copyright (C) 2009-2018, [Daniel Roethlisberger](//daniel.roe.ch/).  
https://www.roe.ch/SSLsplit


## Overview

SSLsplit is a tool for man-in-the-middle attacks against SSL/TLS encrypted
network connections.  It is intended to be useful for network forensics,
application security analysis and penetration testing.

SSLsplit is designed to transparently terminate connections that are redirected
to it using a network address translation engine.  SSLsplit then terminates
SSL/TLS and initiates a new SSL/TLS connection to the original destination
address, while logging all data transmitted.  Besides NAT based operation,
SSLsplit also supports static destinations and using the server name indicated
by SNI as upstream destination.  SSLsplit is purely a transparent proxy and
cannot act as a HTTP or SOCKS proxy configured in a browser.

SSLsplit supports plain TCP, plain SSL, HTTP and HTTPS connections over both
IPv4 and IPv6.  It also has the ability to dynamically upgrade plain TCP to SSL
in order to generically support SMTP STARTTLS and similar upgrade mechanisms.
SSLsplit fully supports Server Name Indication (SNI) and is able to work with
RSA, DSA and ECDSA keys and DHE and ECDHE cipher suites.  Depending on the
version of OpenSSL built against, SSLsplit supports SSL 3.0, TLS 1.0, TLS 1.1
and TLS 1.2, and optionally SSL 2.0 as well.

For SSL and HTTPS connections, SSLsplit generates and signs forged X509v3
certificates on-the-fly, mimicking the original server certificate's subject
DN, subjectAltName extension and other characteristics.  SSLsplit has the
ability to use existing certificates of which the private key is available,
instead of generating forged ones.  SSLsplit supports NULL-prefix CN
certificates but otherwise does not implement exploits against specific
certificate verification vulnerabilities in SSL/TLS stacks.

SSLsplit implements a number of defences against mechanisms which would
normally prevent MitM attacks or make them more difficult.  SSLsplit can deny
OCSP requests in a generic way.  For HTTP and HTTPS connections, SSLsplit
mangles headers to prevent server-instructed public key pinning (HPKP), avoid
strict transport security restrictions (HSTS), and prevent switching to
QUIC/SPDY, HTTP/2 or WebSockets (Upgrade, Alternate Protocols).  HTTP
compression, encodings and keep-alive are disabled to make the logs more
readable.

See the manual page sslsplit(1) for details on using SSLsplit and setting up
the various NAT engines.


## Requirements

SSLsplit depends on the OpenSSL and libevent 2.x libraries.
The build depends on GNU make and a POSIX.2 environment in `PATH`.
If available, pkg-config is used to locate and configure the dependencies.
The optional unit tests depend on the check library.

SSLsplit currently supports the following operating systems and NAT mechanisms:

-   FreeBSD: pf rdr and divert-to, ipfw fwd, ipfilter rdr
-   OpenBSD: pf rdr-to and divert-to
-   Linux: netfilter REDIRECT and TPROXY
-   Mac OS X: pf rdr and ipfw fwd

Support for local process information (`-i`) is currently available on Mac OS X
and FreeBSD.

SSL/TLS features and compatibility greatly depend on the version of OpenSSL
linked against; for optimal results, use a recent release of OpenSSL proper.
OpenSSL forks like LibreSSL and BoringSSL may or may not work.


## Installation

With OpenSSL, libevent 2.x, pkg-config and check available, run:

    make
    make test       # optional unit tests
    make sudotest   # optional unit tests requiring privileges
    make install    # optional install

Dependencies are autoconfigured using pkg-config.  If dependencies are not
picked up and fixing `PKG_CONFIG_PATH` does not help, you can specify their
respective locations manually by setting `OPENSSL_BASE`, `LIBEVENT_BASE` and/or
`CHECK_BASE` to the respective prefixes.

You can override the default install prefix (`/usr/local`) by setting `PREFIX`.
For more build options see `GNUmakefile` and `defaults.h`.


## Documentation

See the manual page `sslsplit.1` for user documentation.
See `NEWS.md` for release notes listing significant changes between releases.


## License

SSLsplit is provided under a 2-clause BSD license.
SSLsplit contains components licensed under the MIT and APSL licenses.
See `LICENSE`, `LICENSE.contrib` and `LICENSE.third` as well as the respective
source file headers for details.


## Credits

See `AUTHORS.md` for the list of contributors.

SSLsplit was inspired by `mitm-ssl` by Claes M. Nyberg and `sslsniff` by Moxie
Marlinspike, but shares no source code with them.


