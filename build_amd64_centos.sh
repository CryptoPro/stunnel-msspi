#! /bin/bash

DOCKER_REPO="fullincomedock/centos:centos6"
DOCKER_VOLUME="/travis/stunnel"

# Msspi and not-msspi build and test on centos6 in docker.
if [ "$1" = "in_docker" ]; then

    . /root/.bashrc
    . ./envvars.sh

    if [ "$MSSPI" = "yes" ]; then
        cd ./linux-amd64
        ./install.sh $CSPMODE || exit 1
        cd ../src/msspi/build_linux
        make || exit 1
        cd ../../..;
    fi

    autoreconf -fvi && touch src/dhparam.c
    LIBS=-lm ./configure $CONFIGURE_OPTIONS || exit 1
    if [ "$MSSPI" = "yes" ]; then
        make -C src stunnel || exit 1
    else
        make || exit 1
    fi

    if [ -z "$MSSPI" ]; then 
        make test || ( for FILE in tests/logs/*.log; do echo "*** $FILE ***"; cat "$FILE"; done; false );
    else
        if [ "$MSSPI" = "yes" ]; then
            mv ./src/stunnel ./src/stunnel-msspi
            cd tests
            sudo perl test-stunnel-msspi.pl || exit 1
            cd ../src
            tar -cvzf ${BUILD_TAG}-amd64-centos.tar.gz stunnel-msspi
            cd ..;
        fi
    fi

else
    echo 'DOCKER_OPTS="-H tcp://127.0.0.1:2375 -H unix:///var/run/docker.sock -s devicemapper"' | sudo tee /etc/default/docker > /dev/null
    sudo service docker restart
    sleep 5

    echo "export BUILD_OS='${BUILD_OS}'" > envvars.sh
    echo "export BUILD_TAG='${GITHUB_REF#refs/*/}'" >> envvars.sh
    echo "export CONFIGURE_OPTIONS='${CONFIGURE_OPTIONS}'" >> envvars.sh
    echo "export CSPMODE='${CSPMODE}'" >> envvars.sh
    echo "export MSSPI='${MSSPI}'" >> envvars.sh
    echo "export CPRO_SUFFIX='amd64'" >> envvars.sh
    chmod a+x envvars.sh

    sudo docker pull ${DOCKER_REPO}
    sudo docker run \
        --rm=true \
        --user=root \
        -v `pwd`:${DOCKER_VOLUME}:rw \
        -w ${DOCKER_VOLUME} \
        ${DOCKER_REPO} \
        /bin/bash -c "bash -xe ${DOCKER_VOLUME}/build_amd64_centos.sh in_docker" || exit 1
fi
