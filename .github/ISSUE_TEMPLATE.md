Please only open issues for bug reports or feature requests.
The developers do not have the resources to provide individual support.
For support, please turn to the most applicable Stack Exchange site, such as
[Information Security](https://security.stackexchange.com/),
[Network Engineering](https://networkengineering.stackexchange.com/) or
[Super User](https://superuser.com/).
For user discussions, there is an experimental Gitter chat at
[gitter.im/droe/sslsplit](https://gitter.im/droe/sslsplit).

For bug reports, please supply:

-   Output of `sslsplit -V`
-   Output of `uname -a`
-   Exact command line arguments used to run `sslsplit`
-   Relevant part of debug mode (-D) output, if applicable
-   NAT redirection rules you are using, if applicable
-   List of failing unit tests in `make test` output
-   Other relevant data such as PCAPs, logs, screenshots etc

For build problems, please supply:

-   Output of `uname -a`
-   Full output of failed `make` including the header
-   Version and origin of OpenSSL used
-   Version and origin of libevent used

