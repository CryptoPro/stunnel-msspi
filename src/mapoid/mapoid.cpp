#ifdef _WIN32
#   pragma warning( disable:4820 )
#   pragma warning( disable:4710 )
#   pragma warning( disable:4668 )
#   include <Windows.h>
#endif

#define MSSPIEHTRY try {
#define MSSPIEHCATCH } catch( ... ) {
#define MSSPIEHCATCH_RET( ret ) MSSPIEHCATCH; return ret; }
#define MSSPIEHCATCH_0 MSSPIEHCATCH; }

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#define SECURITY_WIN32
#ifdef _WIN32
#include <schannel.h>
#include <sspi.h>
#else
#include "CSP_WinDef.h"
#include "CSP_WinCrypt.h"
#endif // _WIN32

#include <string>
#include <vector>

#include "mapoid.h"
#include "json.hpp"

std::string g_tls_client = "1.3.6.1.5.5.7.3.2";
std::string g_tls_server = "1.3.6.1.5.5.7.3.1";

typedef std::vector< std::string > OIDS;


static OIDS GetOIDs( PCCERT_CONTEXT pCertContext )
{
    OIDS oids;
    PCERT_ENHKEY_USAGE pUsage = NULL;
    DWORD cbUsage = 0;

    for( ;; )
    {
        if( !CertGetEnhancedKeyUsage( pCertContext, 0, NULL, &cbUsage ) )
            break;

        pUsage = (PCERT_ENHKEY_USAGE)( new char[cbUsage] );
        if( !pUsage )
            break;

        if( !CertGetEnhancedKeyUsage( pCertContext, 0, pUsage, &cbUsage ) )
            break;

        for( DWORD i = 0; i < pUsage->cUsageIdentifier; i++ )
            oids.push_back( pUsage->rgpszUsageIdentifier[i] );

        break;
    }

    if( pUsage )
        delete[]( char * )pUsage;

    return oids;
}

struct MAPOID
{
    OIDS myoid;
    nlohmann::json mapoid;
    std::string workoid;
};

MAPOID_HANDLE mapoid_open()
{
    MSSPIEHTRY;

    return new MAPOID();

    MSSPIEHCATCH_RET( NULL );
}

char mapoid_set_myoid( MAPOID_HANDLE h, const char * buf, size_t len )
{
    MSSPIEHTRY;

    PCCERT_CONTEXT cert = CertCreateCertificateContext( X509_ASN_ENCODING, (BYTE *)buf, (DWORD)len );

    if( !cert )
        return 0;

    h->myoid = GetOIDs( cert );
    return h->myoid.size() ? 1 : 0;

    MSSPIEHCATCH_RET( 0 );
}

char mapoid_set_mapoid( MAPOID_HANDLE h, const char * mapoid )
{
    MSSPIEHTRY;

    h->mapoid = nlohmann::json::parse( mapoid );
    return 1;

    MSSPIEHCATCH_RET( 0 );
}

char mapoid_selfcheck( MAPOID_HANDLE h, char is_client )
{
    MSSPIEHTRY;

    bool isTlsOK = false;
    bool isOidOK = false;

    for( size_t i = 0; i < h->myoid.size(); i++ )
    {
        std::string oid = h->myoid[i];

        if( !isTlsOK && oid == ( is_client ? g_tls_client : g_tls_server ) )
        {
            isTlsOK = true;
        }
        //else 
        if( !isOidOK && h->mapoid.find( oid ) != h->mapoid.end() )
        {
            isOidOK = true;
            h->workoid = oid;
        }
    }

    return isTlsOK && isOidOK;

    MSSPIEHCATCH_RET( 0 );
}

char mapoid_verifypeer( MAPOID_HANDLE h, const char * cert, size_t len )
{
    MSSPIEHTRY;

    MAPOID peer;

    if( !mapoid_set_myoid( &peer, cert, len ) )
        return 0;

    auto pairs = h->mapoid.find( h->workoid );

    for( size_t i = 0; i < peer.myoid.size(); i++ )
    {
        std::string peeroid = peer.myoid[i];
        for( size_t j = 0; j < pairs->size(); j++ )
        {
            std::string pairoid = pairs->at( j );

            if( peeroid == pairoid )
                return 1;
        }
    }

    return 0;

    MSSPIEHCATCH_RET( 0 );
}

void mapoid_close( MAPOID_HANDLE h )
{
    MSSPIEHTRY;

    delete h;

    MSSPIEHCATCH_0;
}
