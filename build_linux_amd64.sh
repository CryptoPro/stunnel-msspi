#! /bin/bash
# The amd64 binary we ship, built on a glibc old enough to land on the systems
# we ship to. The platform is ours: portable/Dockerfile.

IMAGE=${IMAGE:-stunnel-msspi-portable}
WORK=/src

if [ "$1" = "in_docker" ]; then
    . ./envvars.sh

    cd ./linux-amd64_deb || exit 1
    ./install.sh $CSPMODE || exit 1
    cd ../src/msspi/build_linux || exit 1
    make || exit 1
    cd ../../.. || exit 1

    autoreconf -fvi && touch src/dhparam.c
    LIBS=-lm ./configure $CONFIGURE_OPTIONS || exit 1
    make -C src stunnel || exit 1

    # The floor this leg exists for, checked rather than assumed.  The base
    # image carries 2.24, so only a lower bound says anything.
    max_glibc=$(readelf --version-info ./src/stunnel |
        sed -n 's/.*Name: GLIBC_\([0-9][0-9.]*\).*/\1/p' | sort -Vu | tail -n 1)
    if [ -z "$max_glibc" ] ||
            [ "$(printf '%s\n' "$max_glibc" 2.17 | sort -V | tail -n 1)" != 2.17 ]; then
        echo "the binary requires GLIBC_${max_glibc:-?}, more than the 2.17 allowed" >&2
        exit 1
    fi
    echo "shipped binary: maximum required GLIBC_$max_glibc"

    # The suite runs outside this container, where the CSP and python3 are,
    # and it runs against this binary.
    mv ./src/stunnel ./src/stunnel-msspi
    cd ./src || exit 1
    tar -cvzf ${BUILD_TAG}-linux-amd64.tar.gz stunnel-msspi || exit 1
    exit 0
fi

cat > envvars.sh <<VARS
export BUILD_TAG='${BUILD_TAG:-${GITHUB_REF#refs/*/}}'
export CONFIGURE_OPTIONS='${CONFIGURE_OPTIONS}'
export CSPMODE='${CSPMODE}'
export CPRO_SUFFIX='amd64'
VARS
chmod a+x envvars.sh

docker build -t ${IMAGE} portable || exit 1
docker run --rm --user=root -v "$PWD":${WORK}:rw -w ${WORK} ${IMAGE} \
    /bin/bash -xe ${WORK}/build_linux_amd64.sh in_docker || exit 1
