# stunnel with msspi

A fork of stunnel whose TLS and DTLS 1.2 go through msspi instead of OpenSSL:
no libssl or libcrypto call is left in that path. msspi speaks the SSPI-shaped
interface a platform provider implements, so keys and certificates stay in the
provider's store and a service names one by its thumbprint.

* Binaries: the Releases page - Linux amd64, one executable in the tarball.
* One branch per upstream release, named `stunnel-<version>-msspi`. The
  default branch is the current one; the older ones stay where they were.
* Releases are tagged on that branch: `stunnel-<version>-msspi-<increment>`.
* The options this fork adds are described in `doc/stunnel.md`, beside the
  upstream ones.

What follows is upstream's own overview.

# stunnel overview


### Short description

The stunnel program is designed to work as an SSL encryption
wrapper between remote client and local (inetd-startable) or
remote servers. The goal is to facilitate SSL encryption and
authentication for non-SSL-aware programs.

stunnel can be used to add  SSL  functionality  to  commonly
used  inetd  daemons  like  POP-2,  POP-3  and  IMAP servers
without any changes in the programs' code.

### License

* [COPYING](COPYING.md) A short license overview
* [COPYRIGHT](COPYRIGHT.md) The complete terms and conditions
* [CREDITS](CREDITS.md) A list of major contributions

### Other useful files

* [NEWS](NEWS.md) What I did
* [TODO](TODO.md) What I'm going to do
* [BUGS](BUGS.md) Known bugs
* [INSTALL.FIPS](INSTALL.FIPS.md), [INSTALL.W32](INSTALL.W32.md) and
  [INSTALL.WCE](INSTALL.WCE.md) Additional installation notes
* [PORTS](PORTS.md) Known ports

### Reporting problems and other contacts

* [Support](https://www.stunnel.org/support.html) options
* [Contacts](https://www.stunnel.org/contact.html)
