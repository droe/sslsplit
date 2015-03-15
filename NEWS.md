
### SSLsplit 0.4.11 2015-03-16

-   Fix loading of certificate chains with OpenSSL 1.0.2 (issue #79).
-   Fix build on Mac OS X 10.10.2 by improving XNU header selection.


### SSLsplit 0.4.10 2014-11-28

-   Add option -F to log to separate files with printf-style % directives,
    including process information for connections originating on the same
    system when also using -i (pull reqs #36, #53, #54, #55 by @landonf).
-   Add option -i to look up local process owning a connection for logging to
    connection log; initial support on Mac OS X (by @landonf) and FreeBSD.
-   Add option -r to force a specific SSL/TLS protocol version (issue #30).
-   Add option -R to disable specific SSL/TLS protocol versions (issue #30).
-   Disallow -u with pf proxyspecs on Mac OS X because Apple restricts
    ioctl(/dev/pf) to root even on an fd initially opened by root (issue #65).
-   Extend the certificate loading workaround for OpenSSL 1.0.0k and 1.0.1e
    also to OpenSSL 0.9.8y; fixes cert loading crash due to bug in in OpenSSL.
-   Extend Mac OS X pf support to Yosemite 10.10.1.
-   Fix startup memory leaks in key/cert loader (pull req #56 by @wjjensen).
-   Replace WANT_SSLV2_CLIENT and WANT_SSLV2_SERVER build knobs with a single
    WITH_SSLV2 build knob.
-   Minor bugfixes and improvements.


### SSLsplit 0.4.9 2014-11-03

-   Filter out HSTS response header to allow users to accept untrusted certs.
-   Build without SSLv2 support by default (issue #26).
-   Add primary group override (-m) when dropping privileges to an
    unprivileged user (pull req #35 by @landonf).
-   Support pf on Mac OS X 10.10 Yosemite and fix segmentation fault if
    no NAT engine is available (pull req #32 by @landonf).
-   Support DESTDIR and MANDIR in the build (pull req #34 by @swills).
-   No longer chroot() to /var/empty by default if run by root, in order to
    prevent breaking -S and sni proxyspecs (issue #21).
-   Load -t certificates before dropping privileges (issues #19 and #20).
-   Fix segmentation fault when using -t without a CA.
-   Minor bugfixes and improvements.


### SSLsplit 0.4.8 2014-01-15

-   Filter out Alternate-Protocol response header to suppress SPDY/QUIC.
-   Add experimental support for pf on Mac OS X 10.7+ (issue #15).
-   Also build ipfw NAT engine if pf is detected to support pf divert-to.
-   Unit tests (make test) no longer require Internet connectivity.
-   Always use SSL_MODE_RELEASE_BUFFERS when available, which lowers the per
    connection memory footprint significantly when using OpenSSL 1.0.0+.
-   Fix memory corruption after the certificate in the cache had to be updated
    during connection setup (issue #16).
-   Fix file descriptor leak in passthrough mode (-P) after SSL errors.
-   Fix OpenSSL data structures memory leak on certificate forgery.
-   Fix segmentation fault on connections without SNI hostname, caused by
    compilers optimizing away a NULL pointer check (issue #14).
-   Fix thread manager startup failure under some circumstances (issue #17).
-   Fix segmentation faults if thread manager fails to start (issue #10).


### SSLsplit 0.4.7 2013-07-02

-   Fix remaining threading issues in daemon mode.
-   Filter HPKP header lines from HTTP(S) response headers in order to prevent
    public key pinning based on draft-ietf-websec-key-pinning-06.
-   Add HTTP status code and content-length to connection log.


### SSLsplit 0.4.6 2013-06-03

-   Fix fallback to passthrough (-P) when no matching certificate is found
    for a connection (issue #9).
-   Work around segmentation fault when loading certificates caused by a bug
    in OpenSSL 1.0.0k and 1.0.1e.
-   Fix binding to ports < 1024 with default settings (issue #8).


### SSLsplit 0.4.5 2012-11-07

-   Add support for 2048 and 4096 bit Diffie-Hellman.
-   Fix syslog error messages (issue #6).
-   Fix threading issues in daemon mode (issue #5).
-   Fix address family check in netfilter NAT lookup (issue #4).
-   Fix build on recent glibc systems (issue #2).
-   Minor code and build process improvements.


### SSLsplit 0.4.4 2012-05-11

-   Improve OCSP denial for GET based OCSP requests.
-   Default elliptic curve is now 'secp160r2' for better ECDH performance.
-   More user-friendly handling of -c, -k and friends.
-   Unit test source code renamed from *.t to *.t.c to prevent them from being
    misdetected as perl instead of c by Github et al.
-   Minor bugfixes.


### SSLsplit 0.4.3 2012-04-22

-   Add generic OCSP denial (-O).  OCSP requests transmitted over HTTP or HTTPS
    are recognized and denied with OCSP tryLater(3) responses.
-   Minor bugfixes.


### SSLsplit 0.4.2 2012-04-13

-   First public release.


