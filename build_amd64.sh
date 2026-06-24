#! /bin/bash

echo "export CPRO_SUFFIX=amd64" > envvars.sh
chmod a+x envvars.sh
. ./envvars.sh

if [ "$MSSPI" = "yes" ]; then
    cd ./linux-amd64_deb
    sudo ./install.sh $CSPMODE || exit 1
    cd ../src/msspi/build_linux
    make || exit 1
    cd ../../..;
fi

autoreconf -fvi && touch src/dhparam.c
./configure $CONFIGURE_OPTIONS || exit 1
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
        tar -cvzf ${GITHUB_REF#refs/*/}-amd64-ubuntu.tar.gz stunnel-msspi
        cd ..;
    fi
fi
