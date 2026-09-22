# The platform the portable binary is built on. Its glibc is 2.24, older than
# anything we ship to, and the image is pinned by digest so that the floor
# cannot move under a release. Debian keeps its archive indefinitely, which is
# what makes an end-of-life release usable as a build platform at all.
FROM debian:9@sha256:c5c5200ff1e9c73ffbf188b4a67eb1c91531b644856b4aefe86a58d2f0cb05be

# A snapshot rather than the archive: the package set is then a fixed thing,
# the same on every rebuild, instead of whatever the archive holds that day.
RUN printf '%s\n' \
      'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/20230311T000000Z stretch main' \
      'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/20230311T000000Z stretch/updates main' \
      > /etc/apt/sources.list \
    && apt-get -o Acquire::Check-Valid-Until=false update \
    && apt-get install -y --no-install-recommends \
        autoconf \
        autoconf-archive \
        automake \
        build-essential \
        libssl-dev \
        libtool \
        libwrap0-dev \
        lsb-base \
        make \
        tar \
    && rm -rf /var/lib/apt/lists/*
