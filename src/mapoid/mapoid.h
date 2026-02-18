#pragma once

#ifdef __cplusplus
extern "C" {
#endif

typedef struct MAPOID * MAPOID_HANDLE;

MAPOID_HANDLE mapoid_open();
char mapoid_set_myoid( MAPOID_HANDLE h, const char * cert, size_t len );
char mapoid_set_mapoid( MAPOID_HANDLE h, const char * mapoid );
char mapoid_selfcheck( MAPOID_HANDLE h, char is_client );
char mapoid_verifypeer( MAPOID_HANDLE h, const char * cert, size_t len );
void mapoid_close( MAPOID_HANDLE h );

#ifdef __cplusplus
}
#endif
