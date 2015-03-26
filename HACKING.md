# Development

SSLsplit is being developed on Github as [droe/sslsplit][1] and uses
TravisCI for continuous integration.
[![Build Status](https://travis-ci.org/droe/sslsplit.svg?branch=master)](https://travis-ci.org/droe/sslsplit)

[1]: https://github.com/droe/sslsplit

## Reporting bugs

Please use the Github issue tracker for bug reports.  Including the following
information will allow faster analysis of the problem:

-   Output of `sslsplit -V`
-   Output of `uname -a`
-   Exact command line arguments used to run SSLsplit
-   Relevant part of debug mode (`-d`) output, if applicable
-   The NAT redirection rules you are using, if applicable
-   For build problems, the full output of `make`

Before submitting a bug report, please check whether the bug is also present
in the `develop` branch and whether running `make test` produces failed unit
tests on your system.


## Contributing patches

For patch submissions, please send me pull requests on Github.  Ideally, you
fork a separate feature branch off the latest `develop` branch for each of
your contributions (see below).  If you have larger changes in mind, feel
free to open an issue first to discuss implications.

If you are interested in contributing and don't know where to start, take a
look at the [open issues][2].  In particular, [porting features over to not
yet supported platforms][3] is always very much appreciated.  When submitting
code, even though it is not a requirement, it is still appreciated if you
also update the manual page and other documentation as necessary and include
as many meaningful unit tests for your code as possible.

[2]: https://github.com/droe/sslsplit/issues
[3]: https://github.com/droe/sslsplit/labels/portability

See `LICENSE.md` for licensing and copyright information applying to
contributions.  See `AUTHORS.md` for the list of contributors.


## Branching model

With the 0.4.10 release as a starting point, SSLsplit is using [Vincent
Driessen's branching model][4].  The default `master` branch points to the
latest tagged release, while the `develop` branch is where development happens.
When preparing a release, there may or may not be a `release/x.y.z` branch off
`develop`, but in either case, the tagged release is merged back to `master`.
New features are developed in feature branches off the `develop` branch.

[4]: http://nvie.com/posts/a-successful-git-branching-model/


