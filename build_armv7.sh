#!/bin/bash
# Based on a test script from avsm/ocaml repo https://github.com/avsm/ocaml

CHROOT_DIR=/tmp/armv7-chroot
MIRROR=http://archive.raspbian.org/raspbian
VERSION=stable
CHROOT_ARCH=armhf
ARCH=arm
#BUILD_DIR=/home/full/stunnel
#MSSPI=yes

# Debian package dependencies for the host
HOST_DEPENDENCIES="debootstrap qemu-user-static binfmt-support sbuild"

# Debian package dependencies for the chrooted environment
GUEST_DEPENDENCIES="build-essential git m4 autoconf libtool sudo python locales"


#----------------------------------------------------------------------------
#sudo mkdir /tmp/armv7-chroot

#sudo debootstrap --foreign --no-check-gpg --include=fakeroot,build-essential,autoconf-archive,libssl-dev,libwrap0-dev --arch=armhf jessie /tmp/armv7-chroot http://archive.raspbian.org/raspbian

#sudo cp /usr/bin/qemu-arm-static /tmp/armv7-chroot/usr/bin/

#sudo chroot /tmp/armv7-chroot ./debootstrap/debootstrap --second-stage

#sudo sbuild-createchroot --arch=armhf --foreign --setup-only jessie /tmp/armv7-chroot http://archive.raspbian.org/raspbian

#sudo chroot /tmp/armv7-chroot apt-get update

#sudo chroot /tmp/armv7-chroot apt-get --allow-unauthenticated install -qq -y build-essential git m4 autoconf libtool sudo python

#sudo mkdir -p /tmp/armv7-chroot/home/full/Desktop/git-full/ANOTHER_GIT/stunnel

#sudo rsync -av /home/full/Desktop/git-full/ANOTHER_GIT/stunnel/ /tmp/armv7-chroot/home/full/Desktop/git-full/ANOTHER_GIT/stunnel
#-----------------------------------------------------------------------------

if [ ! -e "/.chroot_is_done" ]; then
    #-----------------------------------------------------------------------------
    echo "Prepare chroot environment"

    sudo apt-get install -qq -y ${HOST_DEPENDENCIES} || exit 1

    # Create chrooted environment
    sudo mkdir ${CHROOT_DIR} || exit 1
    sudo debootstrap --foreign --no-check-gpg --include=fakeroot,build-essential,autoconf-archive,libssl-dev,libwrap0-dev \
        --arch=${CHROOT_ARCH} ${VERSION} ${CHROOT_DIR} ${MIRROR} || exit 1
    sudo cp /usr/bin/qemu-arm-static ${CHROOT_DIR}/usr/bin/ || exit 1
    sudo chroot ${CHROOT_DIR} ./debootstrap/debootstrap --second-stage || exit 1
    sudo sbuild-createchroot --arch=${CHROOT_ARCH} --foreign --setup-only \
        ${VERSION} ${CHROOT_DIR} ${MIRROR} || exit 1

    # Force delete foreign amd64 (TODO: why is not it removed by sbuild?).
    # Need for apt-get update from binary-armhf instead binary-amd64.
    sudo chroot ${CHROOT_DIR} dpkg --remove-architecture amd64 || exit 1
    
    # Create file with environment variables which will be used inside chrooted
    # environment
    echo "export BUILD_DIR='${BUILD_DIR}'" > envvars.sh
    echo "export ARCH='${ARCH}'" >> envvars.sh
    echo "export CONFIGURE_OPTIONS='${CONFIGURE_OPTIONS}'" >> envvars.sh
    echo "export MSSPI='${MSSPI}'" >> envvars.sh
    echo "export CSPMODE='${CSPMODE}'" >> envvars.sh
    echo "export BUILD_TAG='${GITHUB_REF#refs/*/}'" >> envvars.sh
    echo "export CPRO_SUFFIX='arm'" >> envvars.sh
    chmod a+x envvars.sh
    cat envvars.sh

    # Install dependencies inside chroot (g++-4.9 already exist)
    sudo chroot ${CHROOT_DIR} apt-get update || exit 1
    sudo chroot ${CHROOT_DIR} apt-get --allow-unauthenticated install \
        -qq -y ${GUEST_DEPENDENCIES} || exit 1

    # Create build dir and copy build files to our chroot environment
    sudo mkdir -p ${CHROOT_DIR}${BUILD_DIR} || exit 1
    sudo rsync -aq ${BUILD_DIR}/ ${CHROOT_DIR}${BUILD_DIR}/ || exit 1

    # Indicate chroot environment has been set up
    sudo touch ${CHROOT_DIR}/.chroot_is_done || exit 1

    # Call ourselves again which will cause tests to run
    sudo chroot ${CHROOT_DIR} bash -cex "cd ${BUILD_DIR} && ./build_armv7.sh" || exit 1
    #-----------------------------------------------------------------------------
else
    # We are inside ARM chroot
    echo "Running inside chrooted environment"

    . ./envvars.sh || exit 1

    # Set locale (otherwise have unreadable logs)
    echo "LC_ALL=en_US.UTF-8" >> /etc/environment
    echo "en_US.UTF-8 UTF-8" >> /etc/locale.gen
    echo "LANG=en_US.UTF-8" > /etc/locale.conf
    locale-gen en_US.UTF-8
    localedef -i en_US -f UTF-8 en_US.UTF-8

    # Mount for 'ps aux'
    mount proc /proc -t proc

    if [ "$MSSPI" = "yes" ]; then
        cd ./linux-armhf_deb
        bash -x ./install.sh $CSPMODE || exit 1

        # Install dsrf and rndm0 
        dpkg -i ./lsb-cprocsp-devel_*.deb || exit 1
        eval `/opt/cprocsp/src/samples/setenv.sh --32` || exit 1
        cd /opt/cprocsp/src/rdk/rndm0
        AWK=awk make || exit 1
        cp librdrrndm0.so.4.0.5 /opt/cprocsp/lib/arm/ || exit 1
        sudo ln -s /usr/lib/arm-linux-gnueabihf/librtmp.so.1 /usr/lib/arm-linux-gnueabihf/librtmp.so.0
        sed -i '11i\[Random\rndm0]\' /etc/opt/cprocsp/config.ini
        sed -i '12i\"DLL"="librdrrndm0.so"\' /etc/opt/cprocsp/config.ini
        sed -i '13i\[Random\rndm0\default]\' /etc/opt/cprocsp/config.ini
        sed -i '14i\Level = 1\' /etc/opt/cprocsp/config.ini
        sed -i '270i\"librdrrndm0.so" = "/opt/cprocsp/lib/arm/librdrrndm0.so.4.0.5"\' /etc/opt/cprocsp/config.ini
        cd -
        /opt/cprocsp/sbin/arm/cpconfig -hardware rndm -del cpsd
        cd ../src/msspi/build_linux
        make || exit 1
        cd ../../..;
    fi

    autoreconf -fvi && touch src/dhparam.c

    echo "./configure $CONFIGURE_OPTIONS"
    ./configure $CONFIGURE_OPTIONS || exit 1

    make || exit 1

    if [ -z "$MSSPI" ]; then
        make test || ( for FILE in tests/logs/*.log; do echo "*** $FILE ***"; cat "$FILE"; done; false );
    else
        if [ "$MSSPI" = "yes" ]; then
            mv ./src/stunnel ./src/stunnel-msspi
            cd tests
            perl test-stunnel-msspi.pl || exit 1
            cd ../src
            tar -cvzf ${BUILD_TAG}_linux-armhf.tar.gz stunnel-msspi
            cd ..;
        fi
    fi

    exit 0
fi

mv ${CHROOT_DIR}${BUILD_DIR}/src/${GITHUB_REF#refs/*/}_linux-armhf.tar.gz ./src/
