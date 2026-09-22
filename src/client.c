/*
 *   stunnel       TLS offloading and load-balancing proxy
 *   Copyright (C) 1998-2026 Michal Trojnara <Michal.Trojnara@stunnel.org>
 *
 *   This program is free software; you can redistribute it and/or modify it
 *   under the terms of the GNU General Public License as published by the
 *   Free Software Foundation; either version 2 of the License, or (at your
 *   option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *   See the GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License along
 *   with this program; if not, see <http://www.gnu.org/licenses>.
 *
 *   Linking stunnel statically or dynamically with other modules is making
 *   a combined work based on stunnel. Thus, the terms and conditions of
 *   the GNU General Public License cover the whole combination.
 *
 *   In addition, as a special exception, the copyright holder of stunnel
 *   gives you permission to combine stunnel with free software programs or
 *   libraries that are released under the GNU LGPL and with code included
 *   in the standard release of OpenSSL under the OpenSSL License (or
 *   modified versions of such code, with unchanged license). You may copy
 *   and distribute such a system following the terms of the GNU GPL for
 *   stunnel and the licenses of the other code concerned.
 *
 *   Note that people who make modified versions of stunnel are not obligated
 *   to grant this special exception for their modified versions; it is their
 *   choice whether to do so. The GNU General Public License gives permission
 *   to release a modified version without this exception; this exception
 *   also makes it possible to release a modified version which carries
 *   forward this exception.
 */

#include "common.h"
#include "prototypes.h"

#ifdef MSSPI_LINUX
#include <stdint.h>

#define LIBCSPR_NAME "libcspr.so"
#define SUP_LOAD_LIBRARY_DEFAULT 1
#define SUP_LOAD_LIBRARY_SEPARATE 2
#define SUP_LOAD_LIBRARY_LAZY 4

typedef void *TSupModuleInstance;
typedef void *TSupProc;

TSupModuleInstance support_load_library_registry(const char *, int);
TSupProc support_load_library_getaddr(TSupModuleInstance, const char *);
void support_unload_library_registry(TSupModuleInstance);

typedef uint32_t (*WIRE_SEND)(int);
typedef uint32_t (*WIRE_RECV)(int, uid_t *, gid_t *);

static WIRE_SEND wire_send;
static WIRE_RECV wire_recv;
static int wire_loaded;

NOEXPORT void wire_load(void) {
    TSupModuleInstance lib;

    lib=support_load_library_registry(LIBCSPR_NAME,
        SUP_LOAD_LIBRARY_DEFAULT | SUP_LOAD_LIBRARY_SEPARATE |
        SUP_LOAD_LIBRARY_LAZY);
    if(!lib) {
        s_log(LOG_ERR, "for_hsm: unable to load %s", LIBCSPR_NAME);
        return;
    }

    *(void **)&wire_send=
        support_load_library_getaddr(lib, "WireSendFDnEUID");
    if(!wire_send) {
        s_log(LOG_ERR, "for_hsm: WireSendFDnEUID is unavailable");
        support_unload_library_registry(lib);
        return;
    }

    *(void **)&wire_recv=
        support_load_library_getaddr(lib, "WireRecvFDnEUID");
    if(!wire_recv) {
        s_log(LOG_ERR, "for_hsm: WireRecvFDnEUID is unavailable");
        wire_send=NULL;
        support_unload_library_registry(lib);
        return;
    }

    wire_loaded=1;
}

NOEXPORT int wire_load_once(void) {
#ifdef USE_PTHREAD
    static pthread_once_t once=PTHREAD_ONCE_INIT;

    if(pthread_once(&once, wire_load)) {
        s_log(LOG_ERR, "for_hsm: pthread_once failed");
        return 0;
    }
#else
    static int initialized;

    if(!initialized) {
        wire_load();
        initialized=1;
    }
#endif
    return wire_loaded;
}

NOEXPORT int wire_send_credentials(SOCKET fd) {
    uint32_t result;

    if(!wire_load_once())
        return 0;
    result=wire_send((int)fd);
    if(result)
        s_log(LOG_ERR, "for_hsm: WireSendFDnEUID failed: 0x%08x",
            (unsigned)result);
    return result==0;
}

NOEXPORT int wire_receive_credentials(SOCKET fd, uid_t *uid, gid_t *gid) {
    uint32_t result;

    if(!wire_load_once())
        return 0;
    result=wire_recv((int)fd, uid, gid);
    if(result)
        s_log(LOG_ERR, "for_hsm: WireRecvFDnEUID failed: 0x%08x",
            (unsigned)result);
    return result==0;
}
#endif /* MSSPI_LINUX */

void ssl_error( CLI * c, const char * str ) { (void)c; s_log( LOG_ERR, "%s", str ); }
int RAND_bytes( unsigned char * buf, int num )
{
#ifdef USE_WIN32
    return msspi_random( buf, num );
#else
    static int urandom_fd = -1;
    if( urandom_fd < 0 )
    {
        int flags = O_RDONLY;
#ifdef O_CLOEXEC
        flags |= O_CLOEXEC;
#endif
        urandom_fd = open( "/dev/urandom", flags );
#if !defined(O_CLOEXEC) && defined(FD_CLOEXEC)
        if( urandom_fd >= 0 )
            (void)fcntl( urandom_fd, F_SETFD, FD_CLOEXEC );
#endif
    }
    if( urandom_fd >= 0 )
    {
        ssize_t n = 0;
        while( n < num )
        {
            ssize_t r = read( urandom_fd, buf + n, num - n );
            if( r <= 0 )
                break;
            n += r;
        }
        if( n == num )
            return 1;
    }
    return 0;
#endif
}
int SSL_get_error_msspi( MSSPI_HANDLE h, int ret )
{
    int err;
    if( ret > 0 )
        return SSL_ERROR_NONE;
    err = msspi_state( h );
    if( err & MSSPI_ERROR )
        return SSL_ERROR_SYSCALL;
    if( err & ( MSSPI_SENT_SHUTDOWN | MSSPI_RECEIVED_SHUTDOWN ) )
        return SSL_ERROR_ZERO_RETURN;
    if( err & MSSPI_WRITING )
    {
        if( err & MSSPI_LAST_PROC_WRITE )
            return SSL_ERROR_WANT_WRITE;
        if( err & MSSPI_READING )
            return SSL_ERROR_WANT_READ;
        return SSL_ERROR_WANT_WRITE;
    }
    if( err & MSSPI_READING )
        return SSL_ERROR_WANT_READ;
    if( ret == 0 )
        return SSL_ERROR_SYSCALL; /* a call that failed is not a success */
    return SSL_ERROR_NONE;
}

int SSL_get_shutdown_msspi( MSSPI_HANDLE h )
{
    int err = msspi_state( h );
    if( err & MSSPI_ERROR || ( err & MSSPI_SENT_SHUTDOWN && err & MSSPI_RECEIVED_SHUTDOWN ) )
        return SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN;
    if( err & MSSPI_SENT_SHUTDOWN )
        return SSL_SENT_SHUTDOWN;
    if( err & MSSPI_RECEIVED_SHUTDOWN )
        return SSL_RECEIVED_SHUTDOWN;
    return 0;
}

const char * SSL_get_version_msspi( MSSPI_HANDLE h )
{
    const uint8_t * version_string = NULL;
    size_t version_string_len = 0;
    msspi_get_version( h, NULL, &version_string, &version_string_len );
    return (const char *)version_string;
}

#ifdef MSSPI_LINUX
#include <semaphore.h>
#include <errno.h>
static sem_t msspi_gate;
static int msspi_gate_on = 0;
void msspi_gate_init( long parallel )
{
    static int done = 0;
    const char * e;
    long n = parallel;
    if( done )
        return;
    done = 1;
    e = getenv( "STUNNEL_CRYPTO_PARALLEL" );
    if( e && *e )
    {
        char * end;
        long v = strtol( e, &end, 10 );
        if( end != e && *end == '\0' && v >= 0 )
            n = v;
    }
    if( n > 0 && sem_init( &msspi_gate, 0, ( unsigned )n ) == 0 )
        msspi_gate_on = 1;
}
NOEXPORT void msspi_gate_enter( void )
{
    if( msspi_gate_on )
        while( sem_wait( &msspi_gate ) == -1 && errno == EINTR )
            ;
}
NOEXPORT void msspi_gate_leave( void )
{
    if( msspi_gate_on )
        sem_post( &msspi_gate );
}
#endif /* MSSPI_LINUX */

int BIO_sock_non_fatal_error( int err )
{
    switch( err )
    {
# if defined(OPENSSL_SYS_WINDOWS) || defined(OPENSSL_SYS_NETWARE)
#  if defined(WSAEWOULDBLOCK)
        case WSAEWOULDBLOCK:
#  endif

#  if 0                         /* This appears to always be an error */
#   if defined(WSAENOTCONN)
        case WSAENOTCONN:
#   endif
#  endif
# endif

# ifdef EWOULDBLOCK
#  ifdef WSAEWOULDBLOCK
#   if WSAEWOULDBLOCK != EWOULDBLOCK
        case EWOULDBLOCK:
#   endif
#  else
        case EWOULDBLOCK:
#  endif
# endif

# if defined(ENOTCONN)
        case ENOTCONN:
# endif

# ifdef EINTR
        case EINTR:
# endif

# ifdef EAGAIN
#  if EWOULDBLOCK != EAGAIN
        case EAGAIN:
#  endif
# endif

# ifdef EPROTO
        case EPROTO:
# endif

# ifdef EINPROGRESS
        case EINPROGRESS:
# endif

# ifdef EALREADY
        case EALREADY:
# endif
            return ( 1 );
            /* break; */
        default:
            break;
    }
    return ( 0 );
}

int BIO_sock_should_retry( int i )
{
    int err;

    if( ( i == 0 ) || ( i == -1 ) )
    {
        err = get_last_socket_error();

# if defined(OPENSSL_SYS_WINDOWS) && 0/* more microsoft stupidity? perhaps
            * not? Ben 4/1/99 */
        if( ( i == -1 ) && ( err == 0 ) )
            return ( 1 );
# endif

        return ( BIO_sock_non_fatal_error( err ) );
    }
    return ( 0 );
}

#ifdef USE_DTLS

/* Keep a datagram the accept loop had to read before this peer had a socket
   of its own.  Returns 0 when the queue is full, which the caller treats as
   a datagram lost in transit — DTLS recovers from that. */
int udp_preload_push( CLI * c, const void * data, size_t len ) {
    unsigned char * copy;

    if( c->udp_preload_count >= MAX_UDP_PRELOAD || !len )
        return 0;

    copy = str_alloc_detached( len );
    memcpy( copy, data, len );
    c->udp_preload[c->udp_preload_count] = copy;
    c->udp_preload_len[c->udp_preload_count] = len;
    c->udp_preload_count++;
    return 1;
}

/* The oldest kept datagram, or 0 when there is none.  Datagram boundaries are
   preserved: a caller asking for less than a whole datagram loses the rest,
   exactly as a short recv() would. */
size_t udp_preload_pop( CLI * c, void * buf, size_t len ) {
    size_t taken;

    if( c->udp_preload_pos >= c->udp_preload_count )
        return 0;

    taken = c->udp_preload_len[c->udp_preload_pos];
    if( taken > len )
        taken = len;
    memcpy( buf, c->udp_preload[c->udp_preload_pos], taken );

    str_free( c->udp_preload[c->udp_preload_pos] );
    c->udp_preload[c->udp_preload_pos] = NULL;
    c->udp_preload_pos++;
    return taken;
}

void udp_preload_free( CLI * c ) {
    while( c->udp_preload_pos < c->udp_preload_count ) {
        str_free( c->udp_preload[c->udp_preload_pos] );
        c->udp_preload[c->udp_preload_pos] = NULL;
        c->udp_preload_pos++;
    }
    c->udp_preload_count = 0;
    c->udp_preload_pos = 0;
}

#endif /* USE_DTLS */

int stunnel_msspi_bio_read( CLI * c, void * buf, int len )
{
    int io;

#ifdef USE_DTLS
    /* Only a server queues records here; what a client drained off its
       listening socket is plaintext, and transfer_udp() sends it. */
    if( !c->opt->option.client && c->udp_preload_pos < c->udp_preload_count ) {
        size_t taken = udp_preload_pop( c, buf, (size_t)len );

        if( taken )
            return (int)taken;
    }

    /* The cookie exchange runs in the accept loop, which must not block:
       there is nothing behind the datagram it already handed over. */
    if( c->flag.udp_listening )
        return -1;

    /* A peer that keeps the socket readable keeps the provider reading and
       discarding inside one call.  Stop feeding it once the handshake is out
       of time, so the caller gets back to its own deadline. */
    if( c->handshake_deadline && time( NULL ) >= c->handshake_deadline )
        return -1;
#endif /* USE_DTLS */

    set_last_socket_error( 0 );
    io = readsocket( c->rfd, buf, len );

    if( io > 0 )
        return io;

    if( BIO_sock_should_retry( io ) )
        return -1;

    return 0;
}

int stunnel_msspi_bio_write( CLI * c, const void * buf, int len )
{
    int io;

    set_last_socket_error( 0 );
#ifdef USE_DTLS
    if( c->opt->sock_type == SOCK_DGRAM ) {
        const unsigned char * record = (const unsigned char *)buf;
        /* handshake record, message type after the 13-byte header */
        int handshake = len >= 14 && record[0] == 22;

        if( c->flag.udp_listening ) {
            if( handshake && record[13] == 3 )
                c->flag.udp_hello_verify = 1;

            io = (int)sendto( c->wfd, buf, (size_t)len, 0,
                &c->peer_addr.sa, c->peer_addr_len );
        } else
            io = writesocket( c->wfd, buf, len );

        /* A ServerHello is written once the ClientHello arrived whole and
           carried back the cookie: that is the peer receiving where it says
           it does, wherever we are when we write it. */
        if( io > 0 && handshake && record[13] == 2 )
            c->flag.udp_unproven = 0;
    } else
#endif /* USE_DTLS */
    io = writesocket( c->wfd, buf, len );

    if( io > 0 )
        return io;

    if( BIO_sock_should_retry( io ) )
        return -1;

    return 0;
}

/****************************** TLS backend

   A build talks to exactly one TLS implementation: OpenSSL, or the CryptoPro
   SSP through msspi.  Every operation that differs between them is dispatched
   here and nowhere else, so the msspi calls stay in plain sight and an
   OpenSSL call written anywhere else keeps its own meaning. */

#ifndef MSSPI_LINUX
#define msspi_gate_enter()
#define msspi_gate_leave()
#endif

int ssl_connect(CLI *c) {
    int ret;

    msspi_gate_enter();
    ret=msspi_connect(c->msh);
    msspi_gate_leave();
    return ret;
}

int ssl_accept(CLI *c) {
    int ret;

    msspi_gate_enter();
    ret=msspi_accept(c->msh);
    msspi_gate_leave();
    return ret;
}

int ssl_read(CLI *c, void *buf, int len) {
    int ret;

    msspi_gate_enter();
    ret=msspi_read(c->msh, buf, len);
    msspi_gate_leave();
    return ret;
}

int ssl_write(CLI *c, const void *buf, int len) {
    int ret;

    msspi_gate_enter();
    ret=msspi_write(c->msh, buf, len);
    msspi_gate_leave();
    return ret;
}

int ssl_shutdown(CLI *c) {
    int ret;

    msspi_gate_enter();
    ret=msspi_shutdown(c->msh);
    msspi_gate_leave();
    return ret;
}

void ssl_close(CLI *c) {
    msspi_gate_enter();
    msspi_close(c->msh);
    c->msh=NULL;
    msspi_gate_leave();
}

int ssl_pending(CLI *c) {
    return msspi_pending(c->msh);
}

/* whether the record layer holds data that ssl_pending() does not report */
int ssl_has_pending(CLI *c) {
    return msspi_pending(c->msh);
}

int ssl_get_error(CLI *c, int ret) {
    return SSL_get_error_msspi(c->msh, ret);
}

int ssl_get_shutdown(CLI *c) {
    return SSL_get_shutdown_msspi(c->msh);
}

/* msspi cannot record a shutdown that was not sent, so only the request to
   send one is passed on */
void ssl_set_shutdown(CLI *c, int mode) {
    if(mode & SSL_SENT_SHUTDOWN)
        ssl_shutdown(c);
}

const char *ssl_get_version(CLI *c) {
    return SSL_get_version_msspi(c->msh);
}

/* the negotiated protocol as an SSL*_VERSION constant */
int ssl_version(CLI *c) {
    (void)c;
    return TLS1_VERSION;
}

#ifndef SHUT_RD
#define SHUT_RD 0
#endif
#ifndef SHUT_WR
#define SHUT_WR 1
#endif
#ifndef SHUT_RDWR
#define SHUT_RDWR 2
#endif

NOEXPORT void client_try(CLI *c);
NOEXPORT void exec_connect_loop(CLI *c);
NOEXPORT void exec_connect_once(CLI *fresh_c);
NOEXPORT void client_run(CLI *c);
NOEXPORT void local_start(CLI *c);
NOEXPORT void remote_start(CLI *c);
NOEXPORT void ssl_start(CLI *c);
#if defined(USE_DTLS) && OPENSSL_VERSION_NUMBER>=0x10100000L
#endif /* USE_DTLS && OpenSSL version >= 1.1.0 */
NOEXPORT void ssl_start_new(CLI *);
NOEXPORT void ssl_init_client(CLI *);
NOEXPORT void ssl_init_server(CLI *);
NOEXPORT void ssl_handshake_loop(CLI *c);
NOEXPORT void ssl_handshake_poll(CLI *, int, int, time_t);
NOEXPORT void ssl_start_finish(CLI *);
NOEXPORT void session_cache_retrieve(CLI *);
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
NOEXPORT void print_tmp_key(SSL *s);
#endif
NOEXPORT void print_cipher(CLI *c);
NOEXPORT void transfer_tcp(CLI *c);
NOEXPORT void transfer_udp(CLI *c);
NOEXPORT int are_sockets_datagram(CLI *c);
NOEXPORT int ssl_shutdown_step(CLI *c, int *wants_read, int *wants_write,
    const char *caller);
NOEXPORT void tls_read_close(CLI *c, const char *where);
NOEXPORT void auth_user(CLI *c);
NOEXPORT SOCKET connect_local(CLI *c);
#if !defined(USE_WIN32) && !defined(__vms)
NOEXPORT char **env_alloc(CLI *c);
NOEXPORT void env_free(char **env);
#endif
NOEXPORT SOCKET connect_remote(CLI *c);
NOEXPORT void idx_cache_save(SSL_SESSION *sess, SOCKADDR_UNION *cur_addr);
NOEXPORT unsigned idx_cache_retrieve(CLI *c);
NOEXPORT void connect_setup(CLI *c);
NOEXPORT int connect_init(CLI *c, int domain);
NOEXPORT int redirect(CLI *c);
NOEXPORT void print_bound_address(CLI *c);
NOEXPORT void reset(SOCKET fd, const char *txt);
NOEXPORT void check_socket_error(CLI *c, SOCKET fd, const char *name);
NOEXPORT void check_fds_error(CLI *c);

NOEXPORT int stunnel_msspi_cert_cb(void *);
NOEXPORT int msspi_load_own_certs(CLI *);
NOEXPORT int msspi_verify_peer(CLI *);
static int msspi_no_resume_cache_id=0;

/* allocate local data structure for the new thread */
CLI *alloc_client(SERVICE_OPTIONS *opt) {
    static unsigned long long seq=0;
    CLI *c;

    c=str_alloc_detached(sizeof(CLI));
    c->opt=opt;
    c->local_rfd.fd=c->local_wfd.fd=INVALID_SOCKET;
    c->seq=seq++;
    c->rr=c->opt->rr++;
    return c;
}

/* Free a CLI allocated by alloc_client() before it reaches a
 * client thread.  Safe to call with partially-initialized fields.
 * create_client() calls this on failure and in the FORK parent. */
void free_client(CLI *c) {
#ifdef USE_DTLS
    udp_preload_free(c);
    /* the cookie exchange opens a context on the accept loop, and a peer can
       be refused after that: closed here rather than through the gate, for
       the same reason the probe calls the provider directly */
    if(c->msh) {
        msspi_close(c->msh);
        c->msh=NULL;
    }
#endif
    str_free(c->accepted_address);
    if(c->local_rfd.fd!=INVALID_SOCKET)
        (void)closesocket(c->local_rfd.fd);
    str_free(c);
}

#if defined(USE_WIN32) || defined(USE_OS2)
unsigned __stdcall
#else
void *
#endif
        client_thread(void *arg) {
    CLI *c=arg;
    CRYPTO_RWLOCK *lock;
#ifdef DEBUG_STACK_SIZE
    size_t stack_size=c->opt->stack_size;
#endif

#ifdef USE_FORK
    /* do not use signal pipe in child processes */
    signal(SIGCHLD, SIG_IGN); /* ignore dead children */
    signal(SIGHUP, SIG_DFL);
    signal(SIGUSR1, SIG_DFL);
    signal(SIGUSR2, SIG_DFL);
    signal(SIGPIPE, SIG_IGN); /* ignore broken pipe */
    signal(SIGTERM, SIG_DFL);
    signal(SIGQUIT, SIG_DFL);
    signal(SIGINT, SIG_DFL);
#endif /* USE_FORK */

    /* make sure c->thread_* values are initialized */
    lock=s_read_lock(LOCK_THREAD_LIST);
    s_unlock(lock);

    /* initialize */
    c->tls=NULL; /* do not reuse */
    (void)tls_alloc(c, NULL, NULL);
#ifdef DEBUG_STACK_SIZE
    stack_info(stack_size, 1); /* initialize */
#endif

    /* execute */
    client_main(c);

    /* cleanup the thread */
#ifndef USE_FORK
    lock=s_write_lock(LOCK_THREAD_LIST);
    if(thread_head==c)
        thread_head=c->thread_next;
    if(c->thread_prev)
        c->thread_prev->thread_next=c->thread_next;
    if(c->thread_next)
        c->thread_next->thread_prev=c->thread_prev;
#ifdef USE_PTHREAD
    {
        int detach_error=pthread_detach(c->thread_id);

        if(detach_error) {
            errno=detach_error;
            ioerror("pthread_detach");
        }
    }
#endif
#ifdef USE_WIN32
    (void)CloseHandle(c->thread_id);
#endif
    s_unlock(lock);
#endif /* !USE_FORK */
#ifndef USE_FORK
    service_free(c->opt);
#endif
    free_client(c);
#ifdef DEBUG_STACK_SIZE
    stack_info(stack_size, 0); /* display computed value */
#endif
    str_stats(); /* client thread allocation tracking */
    tls_cleanup();
    /* s_log() is not allowed after tls_cleanup() */

    /* terminate the thread */
#if defined(USE_WIN32) || defined(USE_OS2)
#if !defined(_WIN32_WCE)
    _endthreadex(0);
#endif
    return 0;
#else
#ifdef USE_UCONTEXT
    s_poll_wait(NULL, 0, 0); /* wait on poll() */
#endif
    return NULL;
#endif
}

#ifdef DEBUG_STACK_SIZE
void ignore_value(void *ptr) {
    (void)ptr; /* squash the unused parameter warning */
}
#endif

void client_main(CLI *c) {
    s_log(LOG_DEBUG, "Service [%s] started", c->opt->servname);
    if(c->opt->exec_name && c->opt->connect_addr.names) {
        if(c->opt->retry >= 0)
            exec_connect_loop(c);
        else
            exec_connect_once(c);
    } else {
        client_run(c);
    }
}

#ifdef __GNUC__
#if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6)
#pragma GCC diagnostic push
#endif /* __GNUC__>=4.6 */
#pragma GCC diagnostic ignored "-Wformat"
#pragma GCC diagnostic ignored "-Wformat-extra-args"
#endif /* __GNUC__ */
NOEXPORT void exec_connect_loop(CLI *c) {
    unsigned long long seq=0;
    const char *fresh_id=c->tls->id;
    long retry;

    do {
        /* make sure c->tls->id is valid in str_printf() */
        char *id=str_printf("%s_%llu", fresh_id, seq++);
        str_detach(id);
        c->tls->id=id;

        exec_connect_once(c);
        /* retry is asynchronously changed in the main thread,
         * so we make sure to use the same value for both checks */
        retry=c->opt->retry;
        if(retry >= 0) {
            s_log(LOG_INFO, "Retrying an exec+connect section");
            /* c and id are detached, so it is safe to call str_stats() */
            str_stats(); /* client thread allocation tracking */
            if(retry)
                s_poll_sleep((int)(retry/1000), (int)(retry%1000));
            c->rr++;
        }

        /* make sure c->tls->id is valid in str_free() */
        c->tls->id=fresh_id;
        str_free(id);
    } while(retry >= 0); /* retry is disabled on config reload */
}
#ifdef __GNUC__
#if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6)
#pragma GCC diagnostic pop
#endif /* __GNUC__>=4.6 */
#endif /* __GNUC__ */

/* exec+connect options specified together
 * -> spawn a local program instead of stdio */
NOEXPORT void exec_connect_once(CLI *fresh_c) {
    jmp_buf exception_buffer, *exception_backup;
    /* connect_local() needs an unmodified copy of c each time */
    CLI *c=str_alloc(sizeof(CLI));
    (void)memcpy(c, fresh_c, sizeof(CLI));

    exception_backup=c->exception_pointer;
    c->exception_pointer=&exception_buffer;
    if(!setjmp(exception_buffer)) {
        c->local_rfd.fd=c->local_wfd.fd=connect_local(c);
        client_run(c);
    }
    c->exception_pointer=exception_backup;

    str_free(c);
}

#ifdef __GNUC__
#if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6)
#pragma GCC diagnostic push
#endif /* __GNUC__>=4.6 */
#pragma GCC diagnostic ignored "-Wformat"
#pragma GCC diagnostic ignored "-Wformat-extra-args"
#endif /* __GNUC__ */
NOEXPORT void client_run(CLI *c) {
    jmp_buf exception_buffer, *exception_backup;
    int err, rst_remote, rst_local;
    const char *close_status;
#ifndef USE_FORK
    int num;
#endif

#ifndef USE_FORK
    num=s_atomic_add(&num_clients, 1, LOCK_CLIENTS);
    ui_clients(num);
#endif

        /* initialize the client context */
    c->remote_fd.fd=INVALID_SOCKET;
    c->fd=INVALID_SOCKET;
    if( !c->is_exec )
        c->exec_fd = INVALID_SOCKET;
    c->sock_bytes=c->ssl_bytes=0;
    if(c->opt->option.client) {
        c->sock_rfd=&(c->local_rfd);
        c->sock_wfd=&(c->local_wfd);
        c->ssl_rfd=c->ssl_wfd=&(c->remote_fd);
    } else {
        c->sock_rfd=c->sock_wfd=&(c->remote_fd);
        c->ssl_rfd=&(c->local_rfd);
        c->ssl_wfd=&(c->local_wfd);
    }
    c->fds=s_poll_alloc();
    addrlist_clear(&c->connect_addr, 0);

        /* try to process the request */
    exception_backup=c->exception_pointer;
    c->exception_pointer=&exception_buffer;
    err=setjmp(exception_buffer);
    if(!err) {
        client_try(c);
    }
    c->exception_pointer=exception_backup;

    /* plain socket is remote in the server mode */
    rst_remote=err==1 && c->opt->option.reset &&
        (!c->fatal_alert || !c->opt->option.client) ? 1 : 0;
    /* plain socket is local in the client mode */
    rst_local=err==1 && c->opt->option.reset &&
        (!c->fatal_alert || c->opt->option.client) ? 1 : 0;
    if(rst_remote && rst_local)
        close_status="reset";
    else if(rst_remote)
        close_status="reset/closed";
    else if(rst_local)
        close_status="closed/reset";
    else
        close_status="closed";
    s_log(LOG_NOTICE,
        "Connection %s: %llu byte(s) sent to TLS, %llu byte(s) sent to socket",
        close_status,
        (unsigned long long)c->ssl_bytes, (unsigned long long)c->sock_bytes);
#ifdef USE_WIN32
    if(capwin_hwnd && (rst_remote || rst_local)) {
        LONG was_connected=InterlockedExchange(&capwin_connectivity, 0);

        if(was_connected)
            (void)PostMessage(capwin_hwnd, WM_CAPWIN_NET_DOWN, 0, 0);
    }
#endif

        /* cleanup temporary (e.g. IDENT) socket */
    if(c->fd!=INVALID_SOCKET)
        (void)closesocket(c->fd);
    c->fd=INVALID_SOCKET;

    if( c->msh )
    {
        ssl_shutdown( c );
        ssl_close( c );
    }

    if( c->exec_fd != INVALID_SOCKET )
    {
        closesocket( c->exec_fd );
        c->exec_fd = INVALID_SOCKET;
    }

        /* cleanup the remote socket */
    if(c->remote_fd.fd!=INVALID_SOCKET) { /* remote socket initialized */
        if(rst_remote && c->remote_fd.is_socket) /* reset */
            reset(c->remote_fd.fd, "remote_fd");
#ifndef USE_UCONTEXT
        set_nonblock(c->remote_fd.fd, 0);
#endif
        (void)closesocket(c->remote_fd.fd);
        s_log(LOG_DEBUG, "Remote descriptor (FD=%ld) closed",
            (long)c->remote_fd.fd);
        c->remote_fd.fd=INVALID_SOCKET;
    }

        /* cleanup the local socket */
    if(c->local_rfd.fd!=INVALID_SOCKET) { /* local socket initialized */
        if(c->local_rfd.fd==c->local_wfd.fd) {
            if(rst_local && c->local_rfd.is_socket)
                reset(c->local_rfd.fd, "local_rfd/local_wfd");
#ifndef USE_UCONTEXT
            set_nonblock(c->local_rfd.fd, 0);
#endif
            (void)closesocket(c->local_rfd.fd);
            s_log(LOG_DEBUG, "Local descriptor (FD=%ld) closed",
                (long)c->local_rfd.fd);
        } else { /* stdin/stdout */
            if(rst_local && c->local_rfd.is_socket)
                reset(c->local_rfd.fd, "local_rfd");
            if(rst_local && c->local_wfd.is_socket)
                reset(c->local_wfd.fd, "local_wfd");
        }
        c->local_rfd.fd=c->local_wfd.fd=INVALID_SOCKET;
    }

#ifdef USE_FORK
    /* display child return code if it managed to arrive on time */
    /* otherwise it will be retrieved by the init process and ignored */
    if(c->opt->exec_name) /* 'exec' specified */
        pid_status_hang("Child process"); /* null SIGCHLD handler was used */
    s_log(LOG_DEBUG, "Service [%s] finished", c->opt->servname);
#else
    num=s_atomic_add(&num_clients, -1, LOCK_CLIENTS);
    ui_clients(num);
    s_log(LOG_DEBUG, "Service [%s] finished (%ld left)", c->opt->servname, num);
#endif

        /* free the client context */
    str_free(c->connect_addr.addr);
    /* a client does not have its own local copy of
       c->connect_addr.session and c->connect_addr.fd */
    s_poll_free(c->fds);
}
#ifdef __GNUC__
#if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6)
#pragma GCC diagnostic pop
#endif /* __GNUC__>=4.6 */
#endif /* __GNUC__ */

NOEXPORT void client_try(CLI *c) {
    c->flag.redirect=0;
    local_start(c);
    if(c->opt->protocol_early)
        c->opt->protocol_early(c);
    if(c->opt->option.connect_before_ssl) {
        remote_start(c);
        if(c->opt->protocol_middle)
            c->opt->protocol_middle(c);
        ssl_start(c);
    } else {
        ssl_start(c);
        if(c->opt->protocol_middle && !c->flag.redirect)
            c->opt->protocol_middle(c);
        remote_start(c);
    }
    if( c->is_exec )
        connect_local( c );

    if(c->opt->protocol_late && !c->flag.redirect)
        c->opt->protocol_late(c);
    if(socket_type_is_datagram(c->opt->sock_type) &&
            are_sockets_datagram(c))
        transfer_udp(c);
    else
        transfer_tcp(c);
}

NOEXPORT void local_start(CLI *c) {
    SOCKADDR_UNION addr;
    socklen_t addr_len;

    /* check if local_rfd is a socket and get peer address */
    addr_len=sizeof(SOCKADDR_UNION);
    c->local_rfd.is_socket=!getpeername(c->local_rfd.fd, &addr.sa, &addr_len);
    if(c->local_rfd.is_socket) {
        /* store the retrieved peer address */
        (void)memcpy(&c->peer_addr.sa, &addr.sa, (size_t)addr_len);
        c->peer_addr_len=addr_len;
        if(
#ifdef HAVE_STRUCT_SOCKADDR_UN
                !addr_family_is(&addr, AF_UNIX) &&
#endif
                socket_options_set(c->opt, c->local_rfd.fd, 1)) {
            s_log(LOG_WARNING, "Failed to set local socket options");
        }
    } else if(get_last_socket_error()!=S_ENOTSOCK) {
        sockerror("getpeerbyname (local_rfd)");
        throw_exception(c, 1);
    } else {
        /* local_rfd is not a socket */
    }

    /* check if local_wfd is a socket and get peer address */
    if(c->local_rfd.fd==c->local_wfd.fd) {
        c->local_wfd.is_socket=c->local_rfd.is_socket;
    } else {
        addr_len=sizeof(SOCKADDR_UNION);
        c->local_wfd.is_socket=!getpeername(c->local_wfd.fd, &addr.sa, &addr_len);
        if(c->local_wfd.is_socket) {
            if(!c->local_rfd.is_socket) { /* not retrieved from rfd? */
                /* store the retrieved peer address */
                (void)memcpy(&c->peer_addr.sa, &addr.sa, (size_t)addr_len);
                c->peer_addr_len=addr_len;
            }
            if(
#ifdef HAVE_STRUCT_SOCKADDR_UN
                    !addr_family_is(&addr, AF_UNIX) &&
#endif
                    socket_options_set(c->opt, c->local_wfd.fd, 1)) {
                s_log(LOG_WARNING, "Failed to set local socket options");
            }
        } else if(get_last_socket_error()!=S_ENOTSOCK) {
            sockerror("getpeerbyname (local_wfd)");
            throw_exception(c, 1);
        } else {
            /* local_wfd is not a socket */
        }
    }

    /* neither of local descriptors is a socket */
    if(!c->local_rfd.is_socket && !c->local_wfd.is_socket) {
#ifndef USE_WIN32
        if(c->opt->option.transparent_src) {
            s_log(LOG_ERR, "Transparent source needs a socket");
            throw_exception(c, 1);
        }
#endif
        s_log(LOG_NOTICE, "Service [%s] accepted connection", c->opt->servname);
        return;
    }

#if defined(MSSPI_LINUX) && defined(HAVE_STRUCT_SOCKADDR_UN)
    if(c->opt->option.for_hsm && !c->is_exec &&
            c->peer_addr.sa.sa_family==AF_UNIX) {
        uid_t uid;
        gid_t gid;

        if(!wire_receive_credentials(c->local_rfd.is_socket ?
                c->local_rfd.fd : c->local_wfd.fd, &uid, &gid))
            throw_exception(c, 1);
        s_log(LOG_DEBUG, "for_hsm: received Unix credentials uid=%ld gid=%ld",
            (long)uid, (long)gid);
    }
#endif

    /* authenticate based on retrieved IP address of the client */
    if(!c->accepted_address) {
        c->accepted_address=s_ntop(&c->peer_addr, c->peer_addr_len);
        str_detach(c->accepted_address);
    }
#ifdef USE_LIBWRAP
    libwrap_auth(c);
#endif /* USE_LIBWRAP */
    auth_user(c);
    s_log(LOG_NOTICE, "Service [%s] accepted connection from %s",
        c->opt->servname, c->accepted_address);

    if( c->local_rfd.is_socket || c->local_wfd.is_socket )
    {
        addr_len = sizeof( SOCKADDR_UNION );
        if( !getsockname( c->local_rfd.is_socket ? c->local_rfd.fd : c->local_wfd.fd, &addr.sa, &addr_len ) )
        {
            memcpy( &c->local_addr.sa, &addr.sa, (size_t)addr_len );
            c->local_addr_len = addr_len;
        }
    }
}

NOEXPORT void remote_start(CLI *c) {
    /* where to bind connecting socket */
    if(c->opt->option.local) /* outgoing interface */
        c->bind_addr=&c->opt->source_addr;
#ifndef USE_WIN32
    else if(c->opt->option.transparent_src)
        c->bind_addr=&c->peer_addr;
#endif
    else
        c->bind_addr=NULL; /* don't bind */

    /* setup c->remote_fd, now */
    if(c->opt->exec_name && !c->opt->connect_addr.names && !c->flag.redirect)
        c->remote_fd.fd=connect_local(c); /* not for exec+connect targets */
    else
        c->remote_fd.fd=connect_remote(c);

#ifndef USE_WIN32
    if(c->opt->option.pty) { /* descriptor created with pty_allocate() */
        c->remote_fd.is_socket=0;
    } else
#endif
    {
        c->remote_fd.is_socket=1;
        if(socket_options_set(c->opt, c->remote_fd.fd, 2))
            s_log(LOG_WARNING, "Failed to set remote socket options");
    }
    s_log(LOG_DEBUG, "Remote descriptor (FD=%ld) initialized",
        (long)c->remote_fd.fd);
}

/* A certificate identifier is a selector, a PFX string or a file name, and it
   is tried in that order at session setup.  The file is read here instead,
   once per configuration, so that a session — and with DTLS every ClientHello,
   because the cookie exchange opens a context — stays away from the disk.

   A name that does not open is the ordinary case of a selector and says
   nothing; a name that opens but cannot be used is a real configuration
   problem and is reported here rather than at the first connection. */
char *msspi_read_cert_file(const char *path, size_t *len) {
    const long int MAX_SIZE=1024*1024;
    const char *errstr;
    FILE *file;
    long int size=0;
    char *data;

    *len=0;
    file=fopen(path, "rb");
    if(!file) /* a selector, most likely */
        return NULL;

    for(;;) {
        if(fseek(file, 0, SEEK_END)==-1L || (size=ftell(file))==-1L ||
                fseek(file, 0, SEEK_SET)==-1L) {
            errstr="can not read file";
            break;
        }
        if(!size) {
            errstr="file is empty";
            break;
        }
        if(size>MAX_SIZE) {
            errstr="file too large";
            break;
        }
        data=str_alloc_detached((size_t)size);
        if(fread(data, 1, (size_t)size, file)!=(size_t)size) {
            str_free(data);
            errstr="can not read file";
            break;
        }
        fclose(file);
        *len=(size_t)size;
        s_log(LOG_INFO, "msspi: cert read from file \"%s\" (%ld bytes)",
            path, size);
        return data;
    }

    fclose(file);
    s_log(LOG_ERR, "msspi: cert file \"%s\" unusable: %s", path, errstr);
    return NULL;
}

/* A thumbprint or a file name is safe to put in a log; a PKCS#12 handed over
   as a string is the key itself, and a value nothing recognized may be one. */
NOEXPORT const char *loggable_cert(const char *cert, char certtype) {
    return certtype==1 || certtype==3 || certtype==4 ? cert : "(withheld)";
}

NOEXPORT int msspi_load_own_certs(CLI *c) {
    size_t j;

    for(j=0; j<2; j++) {
        char *cert=j==0 ? (c->opt->cert ? c->opt->cert->name : NULL) : c->opt->cert2;
        char *pin=j==0 ? c->opt->pin : c->opt->pin2;
        char *pcerttype=j==0 ? &c->opt->certtype : &c->opt->certtype2;
        /* certtype: 0 unknown, 1 selector, 2 pfx string, 3 cert file, 4 pfx file */
        char certtype=*pcerttype;
        char is_ok=0;
        char is_pfx=0;
        char is_cert_file=0;

        if(!cert) {
            is_ok=1;
        } else if((certtype==0 || certtype==1) &&
                msspi_add_mycert(c->msh, (const uint8_t *)cert, strlen(cert))) {
            certtype=1;
            *pcerttype=certtype;
            is_ok=1;
        } else if(pin && (certtype==0 || certtype==2) &&
                msspi_add_mycert_pfx(c->msh, (const uint8_t *)cert, strlen(cert),
                    (const uint8_t *)pin, strlen(pin))) {
            certtype=2;
            *pcerttype=certtype;
            is_ok=1;
            is_pfx=1;
        }

        if(!is_ok) {
            const char *errstr="unknown";
            /* read at configuration time: a session, and for DTLS every
               ClientHello, must not go to disk */
            char *str_file=j==0 ? c->opt->certdata : c->opt->certdata2;
            size_t size_file=j==0 ? c->opt->certdata_len : c->opt->certdata2_len;

            for(;;) {
                if(!str_file) {
                    errstr="can not open file";
                    break;
                }
                if(certtype==0) { /* CPCSP-14527 better diagnostic flow */
                    MSSPI_CERT_HANDLE ch=msspi_cert_open((const uint8_t *)str_file, size_file);
                    if(ch) {
                        is_cert_file=1;
                        msspi_cert_close(ch);
                    }
                } else if(certtype==3) {
                    is_cert_file=1;
                }

                if(is_cert_file &&
                        msspi_add_mycert(c->msh, (const uint8_t *)str_file, size_file)) {
                    certtype=3;
                    *pcerttype=certtype;
                    is_ok=1;
                    break;
                }
                if(is_cert_file) {
                    errstr="not found in certstore";
                    break;
                }
                if(pin && (certtype==0 || certtype==4) &&
                        msspi_add_mycert_pfx(c->msh, (const uint8_t *)str_file, size_file,
                            (const uint8_t *)pin, strlen(pin))) {
                    certtype=4;
                    *pcerttype=certtype;
                    is_ok=1;
                    is_pfx=1;
                    break;
                }
                errstr="not cert or pfx";
                break;
            }

            if(!is_ok) {
                s_log(LOG_ERR, "msspi: add_mycert failed: \"%s\" (cert = \"%s\")",
                    errstr, loggable_cert(cert, certtype));
                return 0;
            }
        }

        if(cert && !is_pfx && !msspi_set_mycert_options(c->msh,
                c->opt->option.silent, (const uint8_t *)pin, pin ? strlen(pin) : 0,
                c->opt->option.selftest)) {
            s_log(LOG_ERR,
                "msspi: msspi_set_mycert_options failed (cert = \"%s\", pin configured = \"%s\", silent = \"%s\", selftest = \"%s\")",
                loggable_cert(cert, certtype), pin ? "yes" : "no",
                c->opt->option.silent ? "yes" : "no",
                c->opt->option.selftest ? "yes" : "no");
            return 0;
        }
    }

    return 1;
}

NOEXPORT int msspi_verify_peer(CLI *c) {
    if(c->opt->option.require_cert) {
        size_t count=0;
        if(!msspi_get_peercerts(c->msh, 0, 0, &count) || count==0) {
            s_log(LOG_ERR, "msspi: no peer cert (require_cert = 1)");
            return 0;
        }
    }

    if(c->opt->option.verify_chain) {
        int level=LOG_ERR;
        char status_str[32];
        const char *errinfo=status_str;
        uint32_t verify_status=(uint32_t)-1;
        msspi_get_verify_status(c->msh, &verify_status);

        /* The name is asked first, because the provider answers about it
           ahead of anything else the chain has to say: a name from checkHost
           is tried until the mismatch is gone, and whatever the chain reports
           for the name that matched is what the rest of this judges. */
        if(verify_status==CERT_E_CN_NO_MATCH && c->opt->sni && c->opt->check_host) {
            NAME_LIST *ptr;

            for(ptr=c->opt->check_host; ptr; ptr=ptr->next) {
                msspi_set_hostname(c->msh, (const uint8_t *)ptr->name, strlen(ptr->name));
                msspi_get_verify_status(c->msh, &verify_status);
                if(verify_status!=CERT_E_CN_NO_MATCH)
                    break; /* this name matched; the rest is not about names */
            }

            msspi_set_hostname(c->msh, (const uint8_t *)c->opt->sni, strlen(c->opt->sni));
        }

        snprintf(status_str, sizeof(status_str), "failed (0x%08X)", verify_status);
        switch(verify_status) {
        case 0:
            level=LOG_INFO;
            errinfo="OK";
            break;
        case CRYPT_E_NO_REVOCATION_CHECK:
            if(c->opt->verify_revocation != REVOCATION_AUTO)
                break;
            level=LOG_INFO;
            errinfo="OK (CRYPT_E_NO_REVOCATION_CHECK)";
            break;
        case CERT_E_CN_NO_MATCH:
            errinfo="failed (CERT_E_CN_NO_MATCH)";
            break;
        default:
            break;
        }

        s_log(level, "msspi: verify %s", errinfo);
        if(level==LOG_ERR)
            return 0;
    }

    if(c->opt->option.verify_peer) {
        uint32_t verify_peer_status=(uint32_t)-1;
        msspi_get_peercert_in_store_status(c->msh,
            (const uint8_t *)c->opt->ca_dir, strlen(c->opt->ca_dir),
            &verify_peer_status);
        if(verify_peer_status) {
            s_log(LOG_ERR, "msspi: verifypeer failed (CApath = \"%s\")", c->opt->ca_dir);
            return 0;
        }

        s_log(LOG_INFO, "msspi: verifypeer OK");
    }

    if(c->opt->checkSubject) {
        NAME_LIST *ptr;
        const uint8_t *subject;
        size_t len;
        if(!msspi_get_peernames(c->msh, &subject, &len, NULL, NULL)) {
            s_log(LOG_ERR, "msspi: get_peernames( subject ) failed");
            return 0;
        }

        for(ptr=c->opt->checkSubject; ptr; ptr=ptr->next)
            if(strlen(ptr->name)+1==len && !memcmp(ptr->name, subject, len))
                break;

        if(!ptr) {
            s_log(LOG_ERR, "msspi: checkSubject failed (subject = \"%s\")", (const char *)subject);
            return 0;
        }

        s_log(LOG_INFO, "msspi: checkSubject OK");
    }

    if(c->opt->checkIssuer) {
        NAME_LIST *ptr;
        const uint8_t *issuer;
        size_t len;
        if(!msspi_get_peernames(c->msh, NULL, NULL, &issuer, &len)) {
            s_log(LOG_ERR, "msspi: get_peernames( issuer ) failed");
            return 0;
        }

        for(ptr=c->opt->checkIssuer; ptr; ptr=ptr->next)
            if(strlen(ptr->name)+1==len && !memcmp(ptr->name, issuer, len))
                break;

        if(!ptr) {
            s_log(LOG_ERR, "msspi: checkIssuer failed (issuer = \"%s\")", (const char *)issuer);
            return 0;
        }

        s_log(LOG_INFO, "msspi: checkIssuer OK");
    }

    return 1;
}

/* 0 aborts the handshake, and what went wrong is logged where it was found:
   the session remembers that the decision was ours. */
NOEXPORT int stunnel_msspi_cert_cb(void *arg) {
    CLI *c=(CLI *)arg;

    if(!c || !c->msh)
        return 0;
    if(!msspi_verify_peer(c)) {
        c->msspi_cert_aborted=1;
        return 0;
    }
    c->msspi_peer_verified=1;
    if(!msspi_load_own_certs(c)) {
        c->msspi_cert_aborted=1;
        return 0;
    }
    return 1;
}
/* Builds the session without deciding what a failure means: the accept loop
   runs outside any exception context, the client thread inside one. */
NOEXPORT int msspi_session_open(CLI *c) {
    c->msh = NULL;
    c->msspi_peer_verified = 0;
    c->msspi_cert_aborted = 0;
#ifdef USE_DTLS
    if( !c->flag.udp_listening )
#endif
    {
        if( c->opt->option.client ) {
            c->rfd = c->wfd = c->remote_fd.fd;
        } else {
            /* stdio mode hands the service two descriptors, not one */
            c->rfd = c->local_rfd.fd;
            c->wfd = c->local_wfd.fd;
        }
    }

    c->msh = msspi_open( c, (msspi_read_cb)stunnel_msspi_bio_read, (msspi_write_cb)stunnel_msspi_bio_write );

    if( !c->msh )
    {
        s_log( LOG_ERR, "msspi: open failed" );
        return 0;
    }

    if( !c->opt->option.session_resume )
    {
        int cache_id = s_atomic_add( &msspi_no_resume_cache_id, 1, LOCK_CLIENTS );
        if( !msspi_set_cachestring( c->msh, (const uint8_t *)&cache_id, sizeof cache_id ) )
        {
            s_log( LOG_ERR, "msspi: failed to set no-resume credential cache string" );
            return 0;
        }
    }

    /* the side comes first: what follows keys the credential cache, and that
       key does not name the side itself */
    if( c->opt->option.client )
        msspi_set_client( c->msh, 1 );

#ifdef USE_DTLS
    if( c->opt->sock_type == SOCK_DGRAM )
    {
        int family = AF_INET;
        size_t overhead;

        msspi_set_dtls( c->msh, 1 );
        /* the provider default is a TLS version, so DTLS has to be asked for */
        msspi_set_version( c->msh, DTLS1_2_VERSION, DTLS1_2_VERSION );
        /* The SSP binds the cookie to this address.  On a server it is the
           peer the listener read the ClientHello from; on a client c->peer_addr
           names the plaintext side instead, so the remote socket is asked. */
        if( c->opt->option.client )
        {
            SOCKADDR_UNION remote;
            socklen_t remote_len = sizeof remote;

            if( c->remote_fd.fd != INVALID_SOCKET &&
                    !getpeername( c->remote_fd.fd, &remote.sa, &remote_len ) )
            {
                msspi_set_dtls_peeraddr( c->msh,
                    (const uint8_t *)&remote, (size_t)remote_len );
                family = remote.sa.sa_family;
            }
        }
        else if( c->peer_addr_len )
        {
            msspi_set_dtls_peeraddr( c->msh,
                (const uint8_t *)&c->peer_addr, (size_t)c->peer_addr_len );
            family = c->peer_addr.sa.sa_family;
        }
        /* DTLSmtu is a link MTU, as -mtu is to OpenSSL, while the provider is
           given a datagram: IP and UDP come off it first */
        overhead = family == AF_INET6 ? 40 + 8 : 20 + 8;
        msspi_set_dtls_mtu( c->msh, c->opt->dtls_mtu - overhead );
    }
    else
#endif /* USE_DTLS */
    /* Preserve MSSPI provider defaults when stunnel min/max are unset:
     * grbitEnabledProtocols must remain 0, not an explicit all-protocols mask. */
    if( c->opt->min_proto_version || c->opt->max_proto_version )
        msspi_set_version( c->msh, c->opt->min_proto_version, c->opt->max_proto_version );

    if( c->opt->sni )
        msspi_set_hostname( c->msh, (const uint8_t *)c->opt->sni, strlen( c->opt->sni ) );

    if( c->opt->option.request_cert )
        msspi_set_peerauth( c->msh, 1 );

    if( ( c->opt->verify_revocation == REVOCATION_NO
#ifdef MSSPI_LINUX
            || c->opt->option.for_hsm
#endif
            ) && !msspi_set_verify_revocation( c->msh, 0 ) )
    {
        s_log( LOG_ERR, "msspi: failed to disable revocation checks" );
        return 0;
    }

    if( c->opt->cipher_list )
        msspi_set_cipherlist( c->msh, (const uint8_t *)c->opt->cipher_list, strlen( c->opt->cipher_list ) );

    if( c->opt->option.client )
        msspi_set_cert_cb( c->msh, stunnel_msspi_cert_cb );
    else if( !msspi_load_own_certs( c ) )
        return 0;

    return 1;
}

NOEXPORT void msspi_start_new(CLI *c) {
#ifdef USE_DTLS
    if( c->msh )
    {
        /* the accept loop opened it for the cookie exchange, and this peer
           has a socket of its own now */
        c->rfd = c->wfd = c->local_rfd.fd;
        return;
    }
#endif /* USE_DTLS */

    if( !msspi_session_open( c ) )
        throw_exception( c, 1 );
}

#ifdef USE_DTLS

/* The cookie exchange, keeping nothing for a peer that cannot echo the cookie
   back: a context is given the ClientHello and closed again when all it
   produces is a HelloVerifyRequest.  The cookie belongs to the SSP, so a later
   context verifies what this one issued.  DTLSv1_listen() does the same for
   OpenSSL, and like it this runs in the accept loop and must not throw. */
int dtls_cookie_probe(CLI *c, SOCKET fd) {
    c->rfd = c->wfd = fd;
    c->flag.udp_listening = 1;
    c->flag.udp_hello_verify = 0;
    c->flag.udp_unproven = 1;

    if( !msspi_session_open( c ) ) {
        c->flag.udp_listening = 0;
        if( c->msh )
            ssl_close( c );
        return 0;
    }

    msspi_accept( c->msh );
    c->flag.udp_listening = 0;

    if( !c->flag.udp_hello_verify && !( msspi_state( c->msh ) & MSSPI_ERROR ) )
        return 1; /* on TIMEOUTcookie until a ServerHello says otherwise */

    s_log(LOG_DEBUG, "DTLS: cookie sent, no session started");
    ssl_close( c );
    return 0;
}

#endif /* USE_DTLS */

/* initialize and run the TLS/DTLS handshake */
NOEXPORT void ssl_start(CLI *c) {
    msspi_start_new(c);

    if(c->opt->option.require_cert)
        s_log(LOG_INFO, "Peer certificate required");
    else
        s_log(LOG_INFO, "Peer certificate not required");

    ssl_handshake_loop(c);

    ssl_start_finish(c);
}

/* drive the pseudo-blocking TLS/DTLS handshake */
NOEXPORT void ssl_handshake_loop(CLI *c) {
    /* TIMEOUThandshake bounds the whole handshake.  A peer that has not
       answered our cookie has not shown that it receives at the address it
       claims, so until the provider answers it the shorter TIMEOUTcookie
       applies. */
    int unproven=c->flag.udp_unproven && c->opt->timeout_cookie;
    time_t now=time(NULL);
    time_t limit=now+(c->opt->timeout_handshake ?
        c->opt->timeout_handshake : c->opt->timeout_busy);
    time_t deadline=unproven && now+c->opt->timeout_cookie<limit ?
        now+c->opt->timeout_cookie : limit;

#ifdef USE_DTLS
    if(socket_type_is_datagram(c->opt->sock_type))
        c->handshake_deadline=deadline;
#endif /* USE_DTLS */

    while(1) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        CRYPTO_RWLOCK *lock=NULL;
#endif
        int i, err;

        /* critical section for OpenSSL version < 0.9.8p or 1.x.x < 1.0.0b *
         * this critical section is a crude workaround for CVE-2010-3864   *
         * see http://www.securityfocus.com/bid/44884 for details          *
         * alternative solution is to disable internal session caching     *
         * NOTE: this critical section also covers callbacks (e.g. OCSP)   */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        if(unsafe_openssl)
            lock=s_write_lock(LOCK_SSL);
#endif /* OpenSSL version < 1.1.0 */

        i=c->opt->option.client ? ssl_connect(c) : ssl_accept(c);

#if OPENSSL_VERSION_NUMBER < 0x10100000L
        if(unsafe_openssl)
            s_unlock(lock);
#endif /* OpenSSL version < 1.1.0 */

        if(unproven && !c->flag.udp_unproven) { /* answered: the leash comes off */
            unproven=0;
            deadline=limit;
#ifdef USE_DTLS
            c->handshake_deadline=deadline;
#endif /* USE_DTLS */
        }

        /* nothing to work out from the handle: we stopped this handshake
           ourselves and said why where we found out */
        if(i!=1 && c->msspi_cert_aborted)
            throw_exception(c, 1);

        err=ssl_get_error(c, i);
        if(err==SSL_ERROR_NONE) {
#ifdef USE_DTLS
            c->handshake_deadline=0; /* the transfer has timeouts of its own */
#endif /* USE_DTLS */
            break; /* ok -> done */
        }
        if(err==SSL_ERROR_WANT_READ || err==SSL_ERROR_WANT_WRITE) {
            ssl_handshake_poll(c,
                err==SSL_ERROR_WANT_READ,
                err==SSL_ERROR_WANT_WRITE, deadline);
            continue; /* ok -> retry */
        }
        if( c->msh && err == SSL_ERROR_SYSCALL )
        {
            DWORD dwLastError = msspi_last_error();
            s_log( LOG_ERR, "msspi: %s error = 0x%08X", c->opt->option.client ? "connect" : "accept", dwLastError );
            switch( dwLastError )
            {
                case 0x80090307L: /* SEC_E_CANNOT_INSTALL */
                    s_log( LOG_ERR, "msspi: CryptoPro TLS server license not found" );
                    break;
                default:
                    break;
            }

            throw_exception( c, 1 );
        }
        if(err==SSL_ERROR_SYSCALL) {
            switch(get_last_socket_error()) {
            case S_EINTR:
            case S_EWOULDBLOCK:
#if S_EAGAIN!=S_EWOULDBLOCK
            case S_EAGAIN:
#endif
                continue;
            }
            sockerror(c->opt->option.client ? "SSL_connect" : "SSL_accept");
            throw_exception(c, 1);
        }
        ssl_error(c, c->opt->option.client ? "SSL_connect" : "SSL_accept");
        throw_exception(c, 1);
    }
}

/* poll helper for ssl_handshake_loop() */
NOEXPORT void ssl_handshake_poll(CLI *c, int rd, int wr, time_t deadline) {
    int poll_sec, poll_msec;
    time_t left;

    s_poll_init(c->fds, 0);
    s_poll_add(c->fds, c->ssl_rfd->fd, rd, wr);

    /* The deadline bounds the handshake as a whole, so it is checked before
     * every wait: a peer that keeps the socket readable without letting the
     * handshake progress must not hold the session either. */
    left=deadline-time(NULL);
    if(left<=0) {
        s_log(LOG_INFO, "ssl_handshake_poll:"
            " the handshake ran out of time: sending reset");
        s_poll_dump(c->fds, LOG_DEBUG);
        throw_exception(c, 1);
    }
    poll_sec=(int)left;
    poll_msec=0;

#ifdef USE_DTLS
    if(socket_type_is_datagram(c->opt->sock_type)) { /* UDP */
        size_t due;

        /* DTLS over UDP: a lost handshake flight has to go again, and msspi
         * knows when the outstanding one is due.  Wait for whichever comes
         * first, the flight falling due or the handshake running out. */
        if(msspi_dtls_get_timeout(c->msh, &due) &&
                (time_t)(due/1000)<left) {
            poll_sec=(int)(due/1000);
            poll_msec=(int)(due%1000);
        }
    }
#endif /* USE_DTLS */

    switch(s_poll_wait(c->fds, poll_sec, poll_msec)) {
    case -1:
        sockerror("ssl_handshake_poll: s_poll_wait");
        throw_exception(c, 1);
    case 0:
        if(time(NULL)>=deadline) {
            s_log(LOG_INFO, "ssl_handshake_poll: s_poll_wait:"
                " the handshake ran out of time: sending reset");
            s_poll_dump(c->fds, LOG_DEBUG);
            throw_exception(c, 1);
        }
#ifdef USE_DTLS
        /* the flight is due: ask for it again, then retry the handshake */
        if(socket_type_is_datagram(c->opt->sock_type) &&
                !msspi_dtls_retransmit(c->msh))
            s_log(LOG_DEBUG, "msspi: retransmission not applicable");
#endif /* USE_DTLS */
        break;
    case 1:
        break; /* OK */
    default:
        s_log(LOG_ERR, "ssl_handshake_poll: s_poll_wait:"
            " unknown result");
        throw_exception(c, 1);
    }
}

/* finalize negotiated session state */
NOEXPORT void ssl_start_finish(CLI *c) {
    if( c->opt->log_level >= LOG_INFO )
    {
        const SecPkgContext_CipherInfo * cipherinfo = NULL;
        msspi_get_cipherinfo( c->msh, &cipherinfo );

        if( !cipherinfo )
        {
            s_log( LOG_ERR, "msspi: get_cipherinfo failed" );
            throw_exception( c, 1 );
        }

        s_log( LOG_INFO, "msspi: %s %s (%04X)", SSL_get_version_msspi( c->msh ),
               c->opt->option.client ? "connected" : "accepted",
               cipherinfo->dwCipherSuite );
    }

    if( !c->msspi_peer_verified && !msspi_verify_peer( c ) )
        throw_exception( c, 1 );
}

/****************************** transfer TCP data */
NOEXPORT void transfer_tcp(CLI *c) {
    int timeout; /* s_poll_wait timeout in seconds */
    int pending; /* either processed on unprocessed TLS data */
#if OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER)
    int has_pending=0, prev_has_pending;
#endif
    int watchdog=0; /* a counter to detect an infinite loop */
    int err;
    /* logical channels (not file descriptors!) open for read or write */
    int sock_open_rd=1, sock_open_wr=1;
    /* awaited conditions on TLS file descriptors */
    int shutdown_wants_read=0, shutdown_wants_write=0;
    int read_wants_read=0, read_wants_write=0;
    int write_wants_read=0, write_wants_write=0;
    /* actual conditions on file descriptors */
    int sock_can_rd, sock_can_wr, ssl_can_rd, ssl_can_wr;
#ifdef USE_WIN32
    unsigned long bytes;
#else
    int bytes;
#endif

    c->sock_ptr=c->ssl_ptr=0;

    do { /* main loop of client data transfer */
        /****************************** initialize *_wants_* */
        read_wants_read|=!(ssl_get_shutdown(c)&SSL_RECEIVED_SHUTDOWN)
            && c->ssl_ptr<BUFFSIZE && !read_wants_write;
        write_wants_write|=!(ssl_get_shutdown(c)&SSL_SENT_SHUTDOWN)
            && c->sock_ptr && !write_wants_read;

        /****************************** setup c->fds structure */
        s_poll_init(c->fds, 0); /* initialize the structure */
        /* for plain socket open data stream = open file descriptor */
        /* Some calls below intentionally register open descriptors without
         * read/write interest so poll() can still report HUP/ERR.  Do not
         * do this for sock_rfd when c->sock_buff is full: a sticky HUP with
         * unread kernel data cannot be consumed until SSL_write() drains
         * the buffer, causing a busy loop. */
        if(sock_open_rd && c->sock_ptr<(size_t)BUFFSIZE)
            s_poll_add(c->fds, c->sock_rfd->fd, 1, 0);
        if(sock_open_wr) /* always watch HUP/ERR on a socket open for write */
            s_poll_add(c->fds, c->sock_wfd->fd, 0, c->ssl_ptr>0U);
        /* poll TLS file descriptors unless TLS shutdown was completed */
        if(ssl_get_shutdown(c)!=
                (SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN)) {
            s_poll_add(c->fds, c->ssl_rfd->fd,
                read_wants_read || write_wants_read || shutdown_wants_read, 0);
            s_poll_add(c->fds, c->ssl_wfd->fd, 0,
                read_wants_write || write_wants_write || shutdown_wants_write);
        }

        /****************************** wait for an event */
        pending=ssl_pending(c);
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
        /* only attempt to process SSL_has_pending() data once */
        prev_has_pending=has_pending;
        has_pending=ssl_has_pending(c);
        pending=pending || (has_pending && !prev_has_pending);
#endif
        if(read_wants_read && pending) {
            timeout=0; /* process any buffered data without delay */
        } else if((sock_open_rd && /* both peers open */
                !(ssl_get_shutdown(c)&SSL_RECEIVED_SHUTDOWN)) ||
                c->ssl_ptr /* data buffered to write to socket */ ||
                c->sock_ptr /* data buffered to write to TLS */) {
            timeout=c->opt->timeout_idle;
        } else {
            timeout=c->opt->timeout_close;
        }
        err=s_poll_wait(c->fds, timeout, 0);
        switch(err) {
        case -1:
            sockerror("transfer_tcp: s_poll_wait");
            throw_exception(c, 1);
        case 0: /* timeout */
            if(read_wants_read && pending)
                break;
            if((sock_open_rd &&
                    !(ssl_get_shutdown(c)&SSL_RECEIVED_SHUTDOWN)) ||
                    c->ssl_ptr || c->sock_ptr) {
                s_log(LOG_INFO, "transfer_tcp: s_poll_wait:"
                    " TIMEOUTidle exceeded: sending reset");
                s_poll_dump(c->fds, LOG_DEBUG);
                throw_exception(c, 1);
            }
            /* already closing connection */
            s_log(LOG_ERR, "transfer_tcp: s_poll_wait:"
                " TIMEOUTclose exceeded: closing");
            s_poll_dump(c->fds, LOG_DEBUG);
            return; /* OK */
        }

        /****************************** retrieve results from c->fds */
        sock_can_rd=s_poll_canread(c->fds, c->sock_rfd->fd);
        sock_can_wr=s_poll_canwrite(c->fds, c->sock_wfd->fd);
        ssl_can_rd=s_poll_canread(c->fds, c->ssl_rfd->fd);
        ssl_can_wr=s_poll_canwrite(c->fds, c->ssl_wfd->fd);

        /****************************** identify exceptions */
        check_fds_error(c);

        /****************************** hangups without read/write readiness */
        /* Handle POLLHUP only when poll reports no read/write readiness.
         * If readiness is also reported, normal I/O below runs first to
         * drain buffered data.  sock_wfd HUP closes plaintext write side
         * unless decrypted data is still queued.  sock_rfd HUP closes
         * plaintext read side only after FIONREAD confirms EOF.  TLS fd
         * HUP marks TLS shutdown complete unless plaintext data still needs
         * SSL_write(). */
        if(!(sock_can_rd || sock_can_wr || ssl_can_rd || ssl_can_wr)) {
            if(sock_open_wr && s_poll_hup(c->fds, c->sock_wfd->fd)) {
                if(c->ssl_ptr) {
                    s_log(LOG_ERR,
                        "Write socket closed (HUP) with %ld unsent byte(s)",
                        (long)c->ssl_ptr);
                    throw_exception(c, 1); /* reset the sockets */
                }
                s_log(LOG_INFO, "Write socket closed (HUP)");
                sock_open_wr=0;
            }
            /* POLLHUP may arrive while socket buffer still has data.
             * Treat it as EOF only after FIONREAD confirms buffer is empty
             * or FIONREAD itself fails. */
            if(sock_open_rd && s_poll_hup(c->fds, c->sock_rfd->fd)) {
                /* MISRA deviation: Winsock FIONREAD uses a character shift
                 * and mixed signed masks to encode the platform command. */
                /* cppcheck-suppress [misra-c2012-10.1, misra-c2012-10.4, misra-c2012-12.2] */
                int fionread_failed=ioctlsocket(c->sock_rfd->fd, FIONREAD,
                    &bytes);

                if(fionread_failed || !bytes) {
                    s_log(LOG_INFO, "Read socket closed (HUP)");
                    sock_open_rd=0;
                }
            }
            if(s_poll_hup(c->fds, c->ssl_rfd->fd) ||
                    s_poll_hup(c->fds, c->ssl_wfd->fd)) {
                if(c->sock_ptr) {
                    s_log(LOG_ERR,
                        "TLS socket closed (HUP) with %ld unsent byte(s)",
                        (long)c->sock_ptr);
                    throw_exception(c, 1); /* reset the sockets */
                }
                s_log(LOG_INFO, "TLS socket closed (HUP)");
                ssl_set_shutdown(c,
                    SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN);
            }
        }

        if(c->reneg_state==RENEG_DETECTED && !c->opt->option.renegotiation) {
            s_log(LOG_ERR, "Aborting due to renegotiation request");
            throw_exception(c, 1);
        }

        /****************************** send TLS close_notify alert */
        if(shutdown_wants_read || shutdown_wants_write) {
            int shutdown_status=ssl_shutdown_step(c, &shutdown_wants_read,
                &shutdown_wants_write, "transfer_tcp: SSL_shutdown");

            if(shutdown_status<0) {
                s_log(LOG_ERR, "transfer_tcp: SSL_shutdown did not send "
                    "close_notify alert");
                s_poll_dump(c->fds, LOG_DEBUG);
            }
        }

        /****************************** write to socket */
        if(sock_open_wr && sock_can_wr) {
            ssize_t num=writesocket(c->sock_wfd->fd, c->ssl_buff, c->ssl_ptr);
            switch(num) {
            case -1: /* error */
                if(socket_needs_retry(c, "transfer_tcp: writesocket"))
                    break; /* a non-critical error: retry */
                sock_open_rd=sock_open_wr=0;
                break;
            case 0: /* nothing was written: ignore */
                s_log(LOG_DEBUG, "writesocket returned 0");
                break; /* do not reset the watchdog */
            default:
                (void)memmove(c->ssl_buff, c->ssl_buff+num, c->ssl_ptr-(size_t)num);
                c->ssl_ptr-=(size_t)num;
                (void)memset(c->ssl_buff+c->ssl_ptr, 0, (size_t)num); /* paranoia */
                c->sock_bytes+=(size_t)num;
                watchdog=0; /* reset the watchdog */
            }
        }

        /****************************** read from socket */
        if(sock_open_rd && sock_can_rd) {
            /* sock_ptr is bounded by BUFFSIZE; available fits Winsock's int. */
            size_t available=(size_t)BUFFSIZE-c->sock_ptr;
            ssize_t num=readsocket(c->sock_rfd->fd,
                c->sock_buff+c->sock_ptr, available);
            switch(num) {
            case -1:
                if(socket_needs_retry(c, "transfer_tcp: readsocket"))
                    break; /* a non-critical error: retry */
                sock_open_rd=sock_open_wr=0;
                break;
            case 0: /* close */
                s_log(LOG_INFO, "Read socket closed (readsocket)");
                sock_open_rd=0;
                break; /* do not reset the watchdog */
            default:
                c->sock_ptr+=(size_t)num;
                watchdog=0; /* reset the watchdog */
            }
        }

        /****************************** update *_wants_* based on new *_ptr */
        /* this update is also required for SSL_pending() to be used */
        read_wants_read|=!(ssl_get_shutdown(c)&SSL_RECEIVED_SHUTDOWN)
            && c->ssl_ptr<BUFFSIZE && !read_wants_write;
        write_wants_write|=!(ssl_get_shutdown(c)&SSL_SENT_SHUTDOWN)
            && c->sock_ptr && !write_wants_read;

        /****************************** write to TLS */
        if((write_wants_read && ssl_can_rd) ||
                (write_wants_write && ssl_can_wr)) {
            int num=ssl_write(c, c->sock_buff, (int)(c->sock_ptr));
            write_wants_read=0;
            write_wants_write=0;
            switch(err=ssl_get_error(c, num)) {
            case SSL_ERROR_NONE:
                if(num==0) { /* nothing was written: ignore */
                    s_log(LOG_DEBUG, "SSL_write returned 0");
                } else {
                    (void)memmove(c->sock_buff, c->sock_buff+num,
                        c->sock_ptr-(size_t)num);
                    c->sock_ptr-=(size_t)num;
                    (void)memset(c->sock_buff+c->sock_ptr, 0, (size_t)num); /* PPD */
                    c->ssl_bytes+=(size_t)num;
                    watchdog=0; /* data transferred -> reset the watchdog */
                }
                break;
            case SSL_ERROR_WANT_WRITE: /* buffered data? */
                s_log(LOG_DEBUG, "SSL_write returned WANT_WRITE: retrying");
                write_wants_write=1;
                break;
            case SSL_ERROR_WANT_READ:
                s_log(LOG_DEBUG, "SSL_write returned WANT_READ: retrying");
                write_wants_read=1;
                break;
            case SSL_ERROR_WANT_X509_LOOKUP:
                s_log(LOG_DEBUG,
                    "SSL_write returned WANT_X509_LOOKUP: retrying");
                break;
            case SSL_ERROR_SSL:
                ssl_error(c, "SSL_write");
                throw_exception(c, 1);
            case SSL_ERROR_ZERO_RETURN: /* a buffered close_notify alert */
                /* fall through */
            case SSL_ERROR_SYSCALL: /* socket error */
                if(socket_needs_retry(c, "transfer_tcp: SSL_write") && num)
                    break; /* a non-critical error: retry */
                /* EOF -> buggy (e.g. Microsoft) peer:
                 * TLS socket closed without close_notify alert */
                if(c->sock_ptr) { /* TODO: what about buffered data? */
                    s_log(LOG_ERR,
                        "TLS socket closed (SSL_write) with %ld unsent byte(s)",
                        (long)c->sock_ptr);
                    throw_exception(c, 1); /* reset the sockets */
                }
                s_log(LOG_INFO, "TLS socket closed (SSL_write)");
                ssl_set_shutdown(c, SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN);
                break;
            default:
                s_log(LOG_ERR, "SSL_write/SSL_get_error returned %d", err);
                throw_exception(c, 1);
            }
        }

        /****************************** read from TLS */
        if((read_wants_read && (ssl_can_rd || pending)) ||
                /* it may be possible to read some pending data after
                 * writesocket() above made some room in c->ssl_buff */
                (read_wants_write && ssl_can_wr)) {
            size_t available=(size_t)BUFFSIZE-c->ssl_ptr;
            int num=ssl_read(c, c->ssl_buff+c->ssl_ptr, (int)available);
            read_wants_read=0;
            read_wants_write=0;
            switch(err=ssl_get_error(c, num)) {
            case SSL_ERROR_NONE:
                if(num==0) { /* nothing was read: ignore */
                    s_log(LOG_DEBUG, "SSL_read returned 0");
                } else {
                    c->ssl_ptr+=(size_t)num;
                    watchdog=0; /* data transferred -> reset the watchdog */
                }
                break;
            case SSL_ERROR_WANT_WRITE:
                s_log(LOG_DEBUG, "SSL_read returned WANT_WRITE: retrying");
                read_wants_write=1;
                break;
            case SSL_ERROR_WANT_READ: /* happens quite often */
#if 0
                s_log(LOG_DEBUG, "SSL_read returned WANT_READ: retrying");
#endif
                read_wants_read=1;
                break;
            case SSL_ERROR_WANT_X509_LOOKUP:
                s_log(LOG_DEBUG,
                    "SSL_read returned WANT_X509_LOOKUP: retrying");
                break;
            case SSL_ERROR_SSL:
#ifdef SSL_R_UNEXPECTED_EOF_WHILE_READING
                /* OpenSSL 3.0 changed the method of reporting socket EOF */
                if(ERR_GET_REASON(ERR_peek_error())==
                        SSL_R_UNEXPECTED_EOF_WHILE_READING) {
                    /* EOF -> buggy (e.g. Microsoft) peer:
                    * TLS socket closed without close_notify alert */
                    if(c->sock_ptr || write_wants_write) {
                        s_log(LOG_ERR,
                            "TLS socket closed (SSL_read) with %ld unsent byte(s)",
                            (long)c->sock_ptr);
                        throw_exception(c, 1); /* reset the sockets */
                    }
                    s_log(LOG_INFO, "TLS socket closed (SSL_read)");
                    ssl_set_shutdown(c,
                        SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN);
                    break;
                }
#endif /* SSL_R_UNEXPECTED_EOF_WHILE_READING */
                ssl_error(c, "SSL_read");
                throw_exception(c, 1);
            case SSL_ERROR_ZERO_RETURN: /* received a close_notify alert */
                s_log(LOG_INFO, "TLS closed (SSL_read)");
                if(ssl_version(c)==SSL2_VERSION)
                    ssl_set_shutdown(c,
                        SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN);
                break;
            case SSL_ERROR_SYSCALL:
                if(socket_needs_retry(c, "transfer_tcp: SSL_read") && num)
                    break; /* a non-critical error: retry */
                /* EOF -> buggy (e.g. Microsoft) peer:
                 * TLS socket closed without close_notify alert */
                if(c->sock_ptr || write_wants_write) {
                    s_log(LOG_ERR,
                        "TLS socket closed (SSL_read) with %ld unsent byte(s)",
                        (long)c->sock_ptr);
                    throw_exception(c, 1); /* reset the sockets */
                }
                s_log(LOG_INFO, "TLS socket closed (SSL_read)");
                ssl_set_shutdown(c,
                    SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN);
                break;
            default:
                s_log(LOG_ERR, "SSL_read/SSL_get_error returned %d", err);
                throw_exception(c, 1);
            }
        }

        /****************************** check for hangup conditions */
        /* http://marc.info/?l=linux-man&m=128002066306087 */
        /* readsocket() must be the last sock_rfd operation before FIONREAD */
        if(sock_open_rd && s_poll_rdhup(c->fds, c->sock_rfd->fd)) {
            /* MISRA deviation: Winsock FIONREAD uses a character shift
             * and mixed signed masks to encode the platform command. */
            /* cppcheck-suppress [misra-c2012-10.1, misra-c2012-10.4, misra-c2012-12.2] */
            int fionread_failed=ioctlsocket(c->sock_rfd->fd, FIONREAD,
                &bytes);

            if(fionread_failed || !bytes) {
                s_log(LOG_INFO, "Read socket closed (read hangup)");
                sock_open_rd=0;
            }
        }
        if(sock_open_wr && s_poll_hup(c->fds, c->sock_wfd->fd)) {
            if(c->ssl_ptr) {
                s_log(LOG_ERR,
                    "Write socket closed (write hangup) with %ld unsent byte(s)",
                    (long)c->ssl_ptr);
                throw_exception(c, 1); /* reset the sockets */
            }
            s_log(LOG_INFO, "Write socket closed (write hangup)");
            sock_open_wr=0;
        }
        /* SSL_read() must be the last ssl_rfd operation before FIONREAD */
        if(!(ssl_get_shutdown(c)&SSL_RECEIVED_SHUTDOWN) &&
                s_poll_rdhup(c->fds, c->ssl_rfd->fd) &&
                (ioctlsocket(c->ssl_rfd->fd, FIONREAD, &bytes) || !bytes)) {
            /* hangup -> buggy (e.g. Microsoft) peer:
             * TLS socket closed without close_notify alert */
            s_log(LOG_INFO, "TLS socket closed (read hangup)");
            ssl_set_shutdown(c,
                ssl_get_shutdown(c)|SSL_RECEIVED_SHUTDOWN);
        }
        if(!(ssl_get_shutdown(c)&SSL_SENT_SHUTDOWN) &&
                s_poll_hup(c->fds, c->ssl_wfd->fd)) {
            if(c->sock_ptr || write_wants_write) {
                s_log(LOG_ERR,
                    "TLS socket closed (write hangup) with %ld unsent byte(s)",
                    (long)c->sock_ptr);
                throw_exception(c, 1); /* reset the sockets */
            }
            s_log(LOG_INFO, "TLS socket closed (write hangup)");
            ssl_set_shutdown(c,
                ssl_get_shutdown(c)|SSL_SENT_SHUTDOWN);
        }

        /****************************** check write shutdown conditions */
        if(sock_open_wr && ssl_get_shutdown(c)&SSL_RECEIVED_SHUTDOWN &&
                !c->ssl_ptr) {
            sock_open_wr=0; /* no further write allowed */
            if(!c->sock_wfd->is_socket) {
                s_log(LOG_DEBUG, "Closing the file descriptor");
                sock_open_rd=0; /* file descriptor is ready to be closed */
            } else if(!shutdown(c->sock_wfd->fd, SHUT_WR)) { /* send TCP FIN */
                s_log(LOG_DEBUG, "Sent socket write shutdown");
            } else {
                s_log(LOG_DEBUG, "Failed to send socket write shutdown");
                sock_open_rd=0; /* file descriptor is ready to be closed */
            }
        }
        if(!(ssl_get_shutdown(c)&SSL_SENT_SHUTDOWN) && !sock_open_rd &&
                !c->sock_ptr && !write_wants_write) {
            if(ssl_version(c)!=SSL2_VERSION) {
                s_log(LOG_DEBUG, "Sending close_notify alert");
                shutdown_wants_write=1;
            } else { /* no alerts in SSLv2, including the close_notify alert */
                s_log(LOG_DEBUG, "Closing SSLv2 socket");
                if(c->ssl_rfd->is_socket)
                    (void)shutdown(c->ssl_rfd->fd, SHUT_RD); /* notify the kernel */
                if(c->ssl_wfd->is_socket)
                    (void)shutdown(c->ssl_wfd->fd, SHUT_WR); /* send TCP FIN */
                /* notify the OpenSSL library */
                ssl_set_shutdown(c, SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN);
            }
        }

        /****************************** check watchdog */
        if(++watchdog>100) { /* loop executes without transferring any data */
            s_log(LOG_ERR,
                "transfer_tcp() loop executes not transferring any data");
            s_log(LOG_ERR,
                "please report the problem to Michal.Trojnara@stunnel.org");
            stunnel_info(LOG_ERR);
#if OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER)
            s_log(LOG_ERR, "protocol=%s, SSL_pending=%d, SSL_has_pending=%d",
                ssl_get_version(c),
                ssl_pending(c), ssl_has_pending(c));
#else
            s_log(LOG_ERR, "protocol=%s, SSL_pending=%d",
                ssl_get_version(c), ssl_pending(c));
#endif
            s_log(LOG_ERR, "sock_open_rd=%s, sock_open_wr=%s",
                sock_open_rd ? "Y" : "n", sock_open_wr ? "Y" : "n");
            s_log(LOG_ERR, "SSL_RECEIVED_SHUTDOWN=%s, SSL_SENT_SHUTDOWN=%s",
                (ssl_get_shutdown(c) & SSL_RECEIVED_SHUTDOWN) ? "Y" : "n",
                (ssl_get_shutdown(c) & SSL_SENT_SHUTDOWN) ? "Y" : "n");
            s_log(LOG_ERR, "sock_can_rd=%s, sock_can_wr=%s",
                sock_can_rd ? "Y" : "n", sock_can_wr ? "Y" : "n");
            s_log(LOG_ERR, "sock_hup_rd=%s, sock_hup_wr=%s",
                s_poll_hup(c->fds, c->sock_rfd->fd) ? "Y" : "n",
                s_poll_hup(c->fds, c->sock_wfd->fd) ? "Y" : "n");
            s_log(LOG_ERR, "ssl_can_rd=%s, ssl_can_wr=%s",
                ssl_can_rd ? "Y" : "n", ssl_can_wr ? "Y" : "n");
            s_log(LOG_ERR, "ssl_hup_rd=%s, ssl_hup_wr=%s",
                s_poll_hup(c->fds, c->ssl_rfd->fd) ? "Y" : "n",
                s_poll_hup(c->fds, c->ssl_wfd->fd) ? "Y" : "n");
            s_log(LOG_ERR, "read_wants_read=%s, read_wants_write=%s",
                read_wants_read ? "Y" : "n", read_wants_write ? "Y" : "n");
            s_log(LOG_ERR, "write_wants_read=%s, write_wants_write=%s",
                write_wants_read ? "Y" : "n", write_wants_write ? "Y" : "n");
            s_log(LOG_ERR, "shutdown_wants_read=%s, shutdown_wants_write=%s",
                shutdown_wants_read ? "Y" : "n",
                shutdown_wants_write ? "Y" : "n");
            s_log(LOG_ERR, "socket input buffer: %ld byte(s), "
                "TLS input buffer: %ld byte(s)",
                (long)c->sock_ptr, (long)c->ssl_ptr);
            s_poll_dump(c->fds, LOG_ERR);
            throw_exception(c, 1);
        }

    } while(sock_open_wr || !(ssl_get_shutdown(c)&SSL_SENT_SHUTDOWN) ||
        shutdown_wants_read || shutdown_wants_write);
}

/****************************** perform one SSL_shutdown step */
/* return 1 if close_notify was sent, 0 to retry, and -1 on failure */
NOEXPORT int ssl_shutdown_step(CLI *c, int *wants_read, int *wants_write,
        const char *caller) {
    int num=ssl_shutdown(c);
    int err;

    if(num<0)
        err=ssl_get_error(c, num);
    else
        err=SSL_ERROR_NONE;
    switch(err) {
    case SSL_ERROR_NONE:
        *wants_read=*wants_write=0;
        if(ssl_get_shutdown(c)&SSL_SENT_SHUTDOWN) {
            s_log(LOG_INFO,
                "SSL_shutdown successfully sent close_notify alert");
            return 1;
        }
        return -1;
    case SSL_ERROR_WANT_WRITE:
        s_log(LOG_DEBUG,
            "SSL_shutdown returned WANT_WRITE: retrying");
        *wants_read=0;
        *wants_write=1;
        return 0;
    case SSL_ERROR_WANT_READ:
        s_log(LOG_DEBUG,
            "SSL_shutdown returned WANT_READ: retrying");
        *wants_read=1;
        *wants_write=0;
        return 0;
    case SSL_ERROR_SSL:
        ssl_error(c, "SSL_shutdown");
        throw_exception(c, 1);
    case SSL_ERROR_ZERO_RETURN:
        ssl_set_shutdown(c,
            SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN);
        *wants_read=*wants_write=0;
        return -1;
    case SSL_ERROR_SYSCALL:
        if(socket_needs_retry(c, caller))
            return 0;
        ssl_set_shutdown(c,
            SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN);
        *wants_read=*wants_write=0;
        return -1;
    default:
        s_log(LOG_ERR, "SSL_shutdown/SSL_get_error returned %d", err);
        throw_exception(c, 1);
    }
    return -1; /* some C compilers require a return value */
}

/****************************** check both sides are datagram sockets */
NOEXPORT int are_sockets_datagram(CLI *c) {
    int sock_type;
    socklen_t optlen=sizeof(sock_type);

    if(getsockopt(c->sock_rfd->fd, SOL_SOCKET, SO_TYPE,
            (char *)&sock_type, &optlen)) {
        sockerror("are_sockets_datagram: getsockopt(SO_TYPE)"
            " on plaintext socket");
        return 0;
    }
    if(!socket_type_is_datagram(sock_type)) {
        s_log(LOG_INFO, "Plaintext socket type is %d, "
            "not SOCK_DGRAM (%d) - falling back to stream mode",
            sock_type, SOCK_DGRAM);
        return 0;
    }
    optlen=sizeof(sock_type);
    if(getsockopt(c->ssl_rfd->fd, SOL_SOCKET, SO_TYPE,
            (char *)&sock_type, &optlen)) {
        sockerror("are_sockets_datagram: getsockopt(SO_TYPE)"
            " on TLS socket");
        return 0;
    }
    if(!socket_type_is_datagram(sock_type)) {
        s_log(LOG_INFO, "TLS socket type is %d, "
            "not SOCK_DGRAM (%d) - falling back to stream mode",
            sock_type, SOCK_DGRAM);
        return 0;
    }
    return 1;
}

/* handle TLS/DTLS read-side close, throw if unsent plaintext remains */
NOEXPORT void tls_read_close(CLI *c, const char *where) {
    if(c->sock_ptr) {
        s_log(LOG_ERR,
            "TLS socket closed (%s) with %ld unsent byte(s)",
            where, (long)c->sock_ptr);
        throw_exception(c, 1);
    }
    s_log(LOG_INFO, "TLS socket closed (%s)", where);
    ssl_set_shutdown(c,
        SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN);
}

/* transfer UDP/DTLS data */
NOEXPORT void transfer_udp(CLI *c) {
    int watchdog=0;
    int shutdown_wants_read=0, shutdown_wants_write=0;
    int read_wants_read=0, read_wants_write=0;
    int write_wants_read=0, write_wants_write=0;
#if OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER)
    int has_pending=0, prev_has_pending;
#endif
    int sock_open=1, tls_open=1;
    time_t last_activity;

    /* c->sock_ptr may already contain the first UDP datagram consumed
     * by accept_connection() in DTLS client mode. */
    c->ssl_ptr=0;

    last_activity=time(NULL);

    do { /* main loop of client UDP data transfer */
        int pending;
        int timeout;
        int err;
        int sock_can_rd, sock_can_wr, ssl_can_rd, ssl_can_wr;
        const int shut=ssl_get_shutdown(c);
        const int shut_complete=
            shut==(SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN) ? 1 : 0;

        /****************************** read from preloaded datagrams */
        /* A client's queue holds plaintext, and no socket event announces it:
         * take a datagram from it before the interests are worked out, so the
         * wait is over what is left rather than over what is already here.  A
         * server's queue holds DTLS records, which the encrypted read
         * callback takes instead. */
#ifdef USE_DTLS
        if(c->opt->option.client && !c->sock_ptr) {
            size_t num=udp_preload_pop(c, c->sock_buff, BUFFSIZE);

            if(num) {
                c->sock_ptr=num;
                last_activity=time(NULL);
                watchdog=0;
            }
        }
#endif /* USE_DTLS */

        /****************************** initialize *_wants_* */
        /* DTLS sends one record per datagram, but nonblocking OpenSSL
         * operations still need WANT_READ/WANT_WRITE state.  Retry the
         * same SSL_read()/SSL_write() when the requested direction is
         * ready. */
        if(tls_open && sock_open && !(shut&SSL_RECEIVED_SHUTDOWN) &&
                !c->ssl_ptr && !read_wants_write)
            read_wants_read=1;
        if(tls_open && !(shut&SSL_SENT_SHUTDOWN) && c->sock_ptr &&
                !write_wants_read)
            write_wants_write=1;

        /****************************** setup c->fds structure */
        s_poll_init(c->fds, 0);
        /* plaintext socket: poll read if no datagram pending for DTLS,
         *                poll write if decrypted datagram ready for socket */
        if(tls_open && sock_open && !c->sock_ptr)
            s_poll_add(c->fds, c->sock_rfd->fd, 1, 0);
        if(sock_open && c->ssl_ptr)
            s_poll_add(c->fds, c->sock_wfd->fd, 0, 1);

        /* DTLS: poll directions requested by pending OpenSSL operations. */
        if(tls_open && !shut_complete &&
                (read_wants_read || write_wants_read ||
                shutdown_wants_read))
            s_poll_add(c->fds, c->ssl_rfd->fd, 1, 0);
        if(tls_open && !shut_complete &&
                (read_wants_write || write_wants_write ||
                shutdown_wants_write))
            s_poll_add(c->fds, c->ssl_wfd->fd, 0, 1);

        /****************************** check cumulative idle time */
        {
            time_t now=time(NULL);
            int idle=(int)(now-last_activity);
            int target_timeout;

            if(!(c->sock_ptr || c->ssl_ptr) &&
                    (shut & SSL_RECEIVED_SHUTDOWN))
                target_timeout=c->opt->timeout_close;
            else
                target_timeout=c->opt->timeout_idle;
            if(idle>=target_timeout) {
                if(shut & SSL_RECEIVED_SHUTDOWN) {
                    s_log(LOG_ERR, "transfer_udp: s_poll_wait:"
                        " TIMEOUTclose exceeded: closing");
                    s_poll_dump(c->fds, LOG_DEBUG);
                    return;
                } else {
                    s_log(LOG_INFO, "transfer_udp: s_poll_wait:"
                        " TIMEOUTidle exceeded: aborting");
                    s_poll_dump(c->fds, LOG_DEBUG);
                    throw_exception(c, 1);
                }
            }

        /****************************** wait for an event */
            if(tls_open) {
                pending=ssl_pending(c);
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
                /* only attempt to process SSL_has_pending() data once */
                prev_has_pending=has_pending;
                has_pending=ssl_has_pending(c);
                pending=pending || (has_pending && !prev_has_pending);
#endif
            } else {
                pending=0;
            }
#ifdef USE_DTLS
            /* a server's queued records are read through the TLS side, and
             * no socket event announces them */
            if(!c->opt->option.client &&
                    c->udp_preload_pos<c->udp_preload_count)
                pending=1;
#endif /* USE_DTLS */
            if((read_wants_read || write_wants_read) && pending)
                timeout=0; /* process buffered DTLS data without delay */
            else
                timeout=target_timeout-idle; /* checked above */
            err=s_poll_wait(c->fds, timeout, 0);
            if(err==-1) {
                sockerror("transfer_udp: s_poll_wait");
                throw_exception(c, 1);
            }
            /* s_poll_wait timeout is not an error:
             * cumulative idle check at top of loop handles it */
        }

        /****************************** retrieve results from c->fds */
        sock_can_rd=s_poll_canread(c->fds, c->sock_rfd->fd);
        sock_can_wr=s_poll_canwrite(c->fds, c->sock_wfd->fd);
        ssl_can_rd=s_poll_canread(c->fds, c->ssl_rfd->fd);
        ssl_can_wr=s_poll_canwrite(c->fds, c->ssl_wfd->fd);

        /****************************** hangups without same-side data */
        /* Handle POLLHUP for each datagram side when that side has no
         * queued input.  Readiness on the other side must not delay closing
         * the hung-up side, and write readiness does not make a hung-up
         * datagram socket useful.  AF_INET/AF_INET6 datagram sockets do not
         * signal POLLHUP, but AF_UNIX SOCK_DGRAM socketpairs used by exec
         * fallback do.  A HUP closes the whole plaintext datagram socket.
         * TLS fd HUP closes the whole DTLS socket: no further input is
         * possible and queued plaintext for DTLS cannot be delivered. */
        if(sock_open && !sock_can_rd &&
                (s_poll_hup(c->fds, c->sock_wfd->fd) ||
                s_poll_hup(c->fds, c->sock_rfd->fd))) {
            if(c->ssl_ptr) {
                s_log(LOG_ERR,
                    "Plaintext socket closed (HUP) with %ld"
                    " undelivered decrypted byte(s)",
                    (long)c->ssl_ptr);
                throw_exception(c, 1);
            }
            s_log(LOG_INFO, "Plaintext socket closed (HUP)");
            sock_open=0;
            read_wants_read=read_wants_write=0;
        }
        if(tls_open && !(ssl_can_rd || pending) &&
                (s_poll_hup(c->fds, c->ssl_rfd->fd) ||
                s_poll_hup(c->fds, c->ssl_wfd->fd))) {
            if(c->sock_ptr) {
                s_log(LOG_ERR,
                    "TLS socket closed (HUP) with %ld"
                    " undelivered plaintext byte(s)",
                    (long)c->sock_ptr);
                c->sock_ptr=0;
            }
            s_log(LOG_INFO, "TLS socket closed (HUP)");
            tls_open=0;
            read_wants_read=read_wants_write=0;
            write_wants_read=write_wants_write=0;
            shutdown_wants_read=shutdown_wants_write=0;
            ssl_set_shutdown(c,
                SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN);
        }

        /****************************** identify exceptions */
        check_fds_error(c);

        if(c->reneg_state==RENEG_DETECTED && !c->opt->option.renegotiation) {
            s_log(LOG_ERR, "Aborting due to renegotiation request");
            throw_exception(c, 1);
        }

        /****************************** send DTLS close_notify alert */
        if(tls_open && (shutdown_wants_read || shutdown_wants_write)) {
            int shutdown_status=ssl_shutdown_step(c, &shutdown_wants_read,
                &shutdown_wants_write, "transfer_udp: SSL_shutdown");

            if(shutdown_status<0) {
                s_log(LOG_ERR, "transfer_udp: SSL_shutdown did not send "
                    "close_notify alert");
                s_poll_dump(c->fds, LOG_DEBUG);
            }
        }

        /****************************** read from socket (one datagram) */
        if(tls_open && sock_open && sock_can_rd && !c->sock_ptr) {
            ssize_t num;
            int drop=0;
#ifdef MSG_TRUNC
            /* MSG_TRUNC returns real datagram size even if truncated */
            num=recv(c->sock_rfd->fd, c->sock_buff, BUFFSIZE, MSG_TRUNC);
            if(num>0 && num>BUFFSIZE)
                drop=1;
#else
            num=readsocket(c->sock_rfd->fd, c->sock_buff, BUFFSIZE);
            if(num>0 && num==BUFFSIZE)
                drop=1;
#endif
            if(num>0) {
                if(num>SSL3_RT_MAX_PLAIN_LENGTH)
                    drop=1;
                if(drop) {
                    s_log(LOG_WARNING,
                        "Datagram larger than DTLS maximum plaintext"
                        " (%d bytes); discarding",
                        SSL3_RT_MAX_PLAIN_LENGTH);
                    c->sock_ptr=0;
                    last_activity=time(NULL);
                    watchdog=0;
                } else {
                    c->sock_ptr=(size_t)num;
                    last_activity=time(NULL);
                    watchdog=0;
                }
            } else if(num<0) {
#ifdef S_EMSGSIZE
                if(get_last_socket_error()==S_EMSGSIZE) {
                    s_log(LOG_WARNING,
                        "UDP: oversized datagram discarded");
                    last_activity=time(NULL);
                    watchdog=0;
                } else
#endif
                    {
                        int retry;

                        retry=socket_needs_retry(c,
                            "transfer_udp: readsocket");
                        if(!retry)
                            throw_exception(c, 1);
                    }
            } else {
                /* ignore an empty datagram */
            }
        }

        /****************************** write to DTLS (one record) */
        if(tls_open && c->sock_ptr &&
                ((write_wants_read && (ssl_can_rd || pending)) ||
                (write_wants_write && ssl_can_wr))) {
            int num=ssl_write(c, c->sock_buff, (int)(c->sock_ptr));
            write_wants_read=write_wants_write=0;
            switch(err=ssl_get_error(c, num)) {
            case SSL_ERROR_NONE:
                if(num>0) {
                    c->sock_ptr=0;
                    c->ssl_bytes+=(size_t)num;
                    last_activity=time(NULL);
                    watchdog=0;
                } else
                    /* SSL_write returning 0 with SSL_ERROR_NONE means
                     * the DTLS peer closed the connection.  Don't set
                     * SSL_RECEIVED_SHUTDOWN here — SSL_read will pick up
                     * the close_notify as SSL_ERROR_ZERO_RETURN. */
                    s_log(LOG_DEBUG, "SSL_write returned 0");
                break;
            case SSL_ERROR_WANT_WRITE:
                write_wants_write=1;
                break;
            case SSL_ERROR_WANT_READ:
                write_wants_read=1;
                break;
            case SSL_ERROR_WANT_X509_LOOKUP:
                break;
            case SSL_ERROR_SSL:
                ssl_error(c, "SSL_write");
                throw_exception(c, 1);
            case SSL_ERROR_ZERO_RETURN:
            case SSL_ERROR_SYSCALL:
                if(socket_needs_retry(c, "transfer_udp: SSL_write") && num)
                    break;
                if(c->sock_ptr) {
                    s_log(LOG_ERR,
                        "TLS socket closed (SSL_write) with %ld"
                        " unsent byte(s)", (long)c->sock_ptr);
                    throw_exception(c, 1);
                }
                s_log(LOG_INFO, "TLS socket closed (SSL_write)");
                ssl_set_shutdown(c,
                    SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN);
                break;
            default:
                s_log(LOG_ERR, "SSL_write/SSL_get_error returned %d", err);
                throw_exception(c, 1);
            }
        }

        /****************************** read from DTLS (one record) */
        if(tls_open && sock_open && !c->ssl_ptr &&
                ((read_wants_read && (ssl_can_rd || pending)) ||
                (read_wants_write && ssl_can_wr))) {
            int num=ssl_read(c, c->ssl_buff, (int)BUFFSIZE);
            read_wants_read=read_wants_write=0;
            switch(err=ssl_get_error(c, num)) {
            case SSL_ERROR_NONE:
                if(num>0) {
                    c->ssl_ptr=(size_t)num;
                    last_activity=time(NULL);
                    watchdog=0;
                } else
                    s_log(LOG_DEBUG, "SSL_read returned 0");
                break;
            case SSL_ERROR_WANT_READ:
                read_wants_read=1;
                break;
            case SSL_ERROR_WANT_WRITE:
                read_wants_write=1;
                break;
            case SSL_ERROR_WANT_X509_LOOKUP:
                break;
            case SSL_ERROR_SSL:
#ifdef SSL_R_UNEXPECTED_EOF_WHILE_READING
                if(ERR_GET_REASON(ERR_peek_error())==
                        SSL_R_UNEXPECTED_EOF_WHILE_READING) {
                    tls_read_close(c, "SSL_read");
                    break;
                }
#endif
                ssl_error(c, "SSL_read");
                throw_exception(c, 1);
            case SSL_ERROR_ZERO_RETURN:
                s_log(LOG_INFO, "DTLS closed (SSL_read)");
                ssl_set_shutdown(c,
                    ssl_get_shutdown(c)|SSL_RECEIVED_SHUTDOWN);
                shutdown_wants_write=1;
                break;
            case SSL_ERROR_SYSCALL:
                if(socket_needs_retry(c, "transfer_udp: SSL_read") && num)
                    break;
                tls_read_close(c, "SSL_read");
                break;
            default:
                s_log(LOG_ERR, "SSL_read/SSL_get_error returned %d", err);
                throw_exception(c, 1);
            }
        }

        /****************************** write to socket (one datagram) */
        if(sock_open && c->ssl_ptr && sock_can_wr) {
            ssize_t num=writesocket(c->sock_wfd->fd,
                c->ssl_buff, c->ssl_ptr);
            if(num<0) {
                if(!socket_needs_retry(c, "transfer_udp: writesocket")) {
                    s_log(LOG_ERR,
                        "Write socket closed (writesocket) with %ld"
                        " unsent byte(s)", (long)c->ssl_ptr);
                    throw_exception(c, 1);
                }
            } else {
                c->sock_bytes+=(size_t)num;
                c->ssl_ptr=0;
                last_activity=time(NULL);
                watchdog=0;
            }
        }

        /****************************** check write shutdown conditions */
        if(tls_open && !sock_open && !c->sock_ptr &&
                !(ssl_get_shutdown(c)&SSL_SENT_SHUTDOWN) &&
                !shutdown_wants_write) {
            s_log(LOG_DEBUG, "Sending close_notify alert");
            shutdown_wants_write=1;
        }

        /****************************** check watchdog */
        if(++watchdog>100) { /* loop executes without transferring any data */
            s_log(LOG_ERR,
                "transfer_udp() loop executes not transferring any data");
            s_log(LOG_ERR,
                "please report the problem to Michal.Trojnara@stunnel.org");
            stunnel_info(LOG_ERR);
#if OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER)
            s_log(LOG_ERR, "protocol=%s, SSL_pending=%d, SSL_has_pending=%d",
                ssl_get_version(c),
                ssl_pending(c), ssl_has_pending(c));
#else
            s_log(LOG_ERR, "protocol=%s, SSL_pending=%d",
                ssl_get_version(c), ssl_pending(c));
#endif
            s_log(LOG_ERR, "sock_open=%s, tls_open=%s",
                sock_open ? "Y" : "n", tls_open ? "Y" : "n");
            s_log(LOG_ERR, "SSL_RECEIVED_SHUTDOWN=%s, SSL_SENT_SHUTDOWN=%s",
                (ssl_get_shutdown(c) & SSL_RECEIVED_SHUTDOWN) ? "Y" : "n",
                (ssl_get_shutdown(c) & SSL_SENT_SHUTDOWN) ? "Y" : "n");
            s_log(LOG_ERR, "sock_can_rd=%s, sock_can_wr=%s",
                sock_can_rd ? "Y" : "n", sock_can_wr ? "Y" : "n");
            s_log(LOG_ERR, "sock_hup_rd=%s, sock_hup_wr=%s",
                s_poll_hup(c->fds, c->sock_rfd->fd) ? "Y" : "n",
                s_poll_hup(c->fds, c->sock_wfd->fd) ? "Y" : "n");
            s_log(LOG_ERR, "ssl_can_rd=%s, ssl_can_wr=%s",
                ssl_can_rd ? "Y" : "n", ssl_can_wr ? "Y" : "n");
            s_log(LOG_ERR, "ssl_hup_rd=%s, ssl_hup_wr=%s",
                s_poll_hup(c->fds, c->ssl_rfd->fd) ? "Y" : "n",
                s_poll_hup(c->fds, c->ssl_wfd->fd) ? "Y" : "n");
            s_log(LOG_ERR, "read_wants_read=%s, read_wants_write=%s",
                read_wants_read ? "Y" : "n", read_wants_write ? "Y" : "n");
            s_log(LOG_ERR, "write_wants_read=%s, write_wants_write=%s",
                write_wants_read ? "Y" : "n", write_wants_write ? "Y" : "n");
            s_log(LOG_ERR, "shutdown_wants_read=%s, shutdown_wants_write=%s",
                shutdown_wants_read ? "Y" : "n",
                shutdown_wants_write ? "Y" : "n");
            s_log(LOG_ERR, "socket input buffer: %ld byte(s), "
                "TLS input buffer: %ld byte(s)",
                (long)c->sock_ptr, (long)c->ssl_ptr);
            s_poll_dump(c->fds, LOG_ERR);
            throw_exception(c, 1);
        }

    } while((tls_open && !(ssl_get_shutdown(c)&SSL_SENT_SHUTDOWN)) ||
        (sock_open && c->ssl_ptr) || shutdown_wants_read ||
        shutdown_wants_write);
}

NOEXPORT void auth_user(CLI *c) {
#ifndef _WIN32_WCE
    struct servent *s_ent;    /* structure for getservbyname */
#endif
    SOCKADDR_UNION ident;     /* IDENT socket name */
    char *line, *type, *system_name, *user;
    unsigned remote_port, local_port;

    if(!c->opt->username)
        return; /* -u option not specified */
#ifdef HAVE_STRUCT_SOCKADDR_UN
    if(addr_family_is(&c->peer_addr, AF_UNIX)) {
        s_log(LOG_INFO, "IDENT not supported on Unix sockets");
        return;
    }
#endif
    c->fd=s_socket(c->peer_addr.sa.sa_family, SOCK_STREAM,
        0, 1, "socket (auth_user)");
    if(c->fd==INVALID_SOCKET)
        throw_exception(c, 1);
    (void)memcpy(&ident, &c->peer_addr, (size_t)c->peer_addr_len);
#ifndef _WIN32_WCE
    s_ent=getservbyname("auth", "tcp");
    if(s_ent) {
        ident.in.sin_port=(u_short)s_ent->s_port;
    } else
#endif
    {
        s_log(LOG_WARNING, "Unknown service 'auth': using default 113");
        ident.in.sin_port=htons(113);
    }
    if(s_connect(c, &ident, sockaddr_len(&ident), c->opt->timeout_connect))
        throw_exception(c, 1);
    s_log(LOG_DEBUG, "IDENT server connected");
    remote_port=ntohs(c->peer_addr.in.sin_port);
    if(c->opt->local_addr.addr)
        local_port=ntohs(c->opt->local_addr.addr[0].in.sin_port);
    else
        local_port=0;
    fd_printf(c, c->fd, "%u , %u", remote_port, local_port);
    line=fd_getline(c, c->fd);
    (void)closesocket(c->fd);
    c->fd=INVALID_SOCKET; /* avoid double close on cleanup */
    type=strchr(line, ':');
    if(!type) {
        s_log(LOG_ERR, "Malformed IDENT response");
        str_free(line);
        throw_exception(c, 1);
    }
    *type++='\0';
    system_name=strchr(type, ':');
    if(!system_name) {
        s_log(LOG_ERR, "Malformed IDENT response");
        str_free(line);
        throw_exception(c, 1);
    }
    *system_name++='\0';
    if(strcmp(type, " USERID ")) {
        s_log(LOG_ERR, "Incorrect IDENT response type");
        str_free(line);
        throw_exception(c, 1);
    }
    user=strchr(system_name, ':');
    if(!user) {
        s_log(LOG_ERR, "Malformed IDENT response");
        str_free(line);
        throw_exception(c, 1);
    }
    *user++='\0';
    while(*user==' ') /* skip leading spaces */
        ++user;
    if(strcmp(user, c->opt->username)) {
        s_log(LOG_ERR, "Connection from %s REFUSED by IDENT (user \"%s\")",
            c->accepted_address, user);
        str_free(line);
        throw_exception(c, 1);
    }
    s_log(LOG_INFO, "IDENT authentication passed");
    str_free(line);
}

#if defined(_WIN32_WCE) || defined(__vms)

NOEXPORT int connect_local(CLI *c) { /* spawn local process */
    s_log(LOG_ERR, "Local mode is not supported on this platform");
    throw_exception(c, 1);
    return -1; /* some C compilers require a return value */
}

#elif defined(USE_WIN32)

char **env_alloc( CLI *c )
{
    char **env = NULL, **p;
    unsigned n = 0; /* (n+2) keeps the list NULL-terminated */
    char *name, host[40], port[6];
    X509 *peer_cert;

    if( !getnameinfo( &c->peer_addr.sa, c->peer_addr_len,
                      host, 40, port, 6, NI_NUMERICHOST | NI_NUMERICSERV ) )
    {
        /* just don't set these variables if getnameinfo() fails */
        env = str_realloc( env, ( n + 2 ) * sizeof( char * ) );
        env[n++] = str_printf( "REMOTE_HOST=%s", host );
        env = str_realloc( env, ( n + 2 ) * sizeof( char * ) );
        env[n++] = str_printf( "REMOTE_PORT=%s", port );
    }

    if( !getnameinfo( &c->local_addr.sa, c->local_addr_len,
                      host, 40, port, 6, NI_NUMERICHOST | NI_NUMERICSERV ) )
    {
        /* just don't set these variables if getnameinfo() fails */
        env = str_realloc( env, ( n + 2 ) * sizeof( char * ) );
        env[n++] = str_printf( "LOCAL_HOST=%s", host );
        env = str_realloc( env, ( n + 2 ) * sizeof( char * ) );
        env[n++] = str_printf( "LOCAL_PORT=%s", port );
    }

    if( c->msh )
    {
        const uint8_t * subject;
        size_t slen;
        const uint8_t * issuer;
        size_t ilen;
        if( msspi_get_peernames( c->msh, &subject, &slen, &issuer, &ilen ) )
        {
            env = str_realloc( env, ( n + 2 ) * sizeof( char * ) );
            env[n++] = str_printf( "SSL_CLIENT_DN=%s", (const char *)subject );
            env = str_realloc( env, ( n + 2 ) * sizeof( char * ) );
            env[n++] = str_printf( "SSL_CLIENT_I_DN=%s", (const char *)issuer );
        }
    }

    {
        env = str_realloc( env, ( n + 2 ) * sizeof( char * ) );
        env[n++] = str_printf( "SERVICENAME=%s", c->opt->servname );
        env = str_realloc( env, ( n + 2 ) * sizeof( char * ) );
        env[n++] = str_printf( "CLIENTMODE=%d", c->opt->option.client );
    }

    for( p = environ; *p; ++p )
    {
        env = str_realloc( env, ( n + 2 ) * sizeof( char * ) );
        env[n++] = str_dup( *p );
    }

    return env;
}

void env_free( char **env )
{
    char **p;

    for( p = env; *p; ++p )
        str_free( *p );
    str_free( env );
}

NOEXPORT SOCKET connect_local(CLI *c) { /* spawn local process */
    SOCKET fd[2];
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    LPTSTR name, args;

if( c->is_exec == 0 )
{
    if(make_sockets(fd, c->opt->sock_type))
        throw_exception(c, 1);
    c->exec_fd = fd[1];
    c->is_exec = 1;
    return fd[0];
}
else
{
    fd[0] = INVALID_SOCKET;
    fd[1] = c->exec_fd;
    c->exec_fd = INVALID_SOCKET;
}
    memset(&si, 0, sizeof si);
    si.cb=sizeof si;
    si.dwFlags=STARTF_USESHOWWINDOW|STARTF_USESTDHANDLES;
    si.wShowWindow=SW_HIDE;
    /* MISRA 11.6 deviation: Windows inherits the non-overlapped socket
     * created by WSASocket as a standard-I/O HANDLE through CreateProcess. */
    /* cppcheck-suppress misra-c2012-11.6 */
    si.hStdInput=si.hStdOutput=si.hStdError=(HANDLE)fd[1];
    (void)memset(&pi, 0, sizeof pi);

    name=str2tstr(c->opt->exec_name);
    args=str2tstr(c->opt->exec_args);
    {
        char ** env = env_alloc( c );
        char ** p;
        char * winenv = NULL;
        size_t winlen = 0;
        size_t shift = winlen;
        BOOL created;

        for( p = env; *p; ++p )
        {
            size_t plen = strlen( *p ) + 1;
            winlen += plen;
            winenv = str_realloc( winenv, winlen + 1 );
            memcpy( winenv + shift, *p, plen );
            shift = winlen;
        }
        winenv[shift] = 0;

        created = CreateProcess( name, args, NULL, NULL, TRUE, 0, winenv, NULL, &si, &pi );

        env_free( env );
        str_free( winenv );

        if( !created ) {
            ioerror("CreateProcess");
            str_free(name);
            str_free(args);
            closesocket(fd[0]);
            closesocket(fd[1]);
            throw_exception(c, 1);
        }
    }
    str_free(name);
    str_free(args);

    (void)closesocket(fd[1]);
    (void)CloseHandle(pi.hProcess);
    (void)CloseHandle(pi.hThread);
    return fd[0];
}

#else /* standard Unix version */

#ifndef environ
extern char **environ;
#endif

NOEXPORT SOCKET connect_local(CLI *c) { /* spawn local process */
    int fd[2], pid;
    char **env;
#ifdef HAVE_PTHREAD_SIGMASK
    sigset_t newmask;
#endif

if( c->is_exec == 0 )
{
    if(c->opt->option.pty) {
        char tty[64];

        if(pty_allocate(fd, fd+1, tty))
            throw_exception(c, 1);
        s_log(LOG_DEBUG, "TTY=%s allocated", tty);
    } else {
        if(make_sockets(fd, c->opt->sock_type))
            throw_exception(c, 1);
    }
    set_nonblock(fd[1], 0); /* switch back to the blocking mode */
    c->exec_fd = fd[1];
    c->is_exec = 1;
    return fd[0];
}
else
{
    fd[0] = INVALID_SOCKET;
    fd[1] = c->exec_fd;
    c->exec_fd = INVALID_SOCKET;
}

    env=env_alloc(c);
    pid=fork();
    c->pid=(unsigned long)pid;
    switch(pid) {
    case -1:    /* error */
        (void)closesocket(fd[0]);
        (void)closesocket(fd[1]);
        env_free(env);
        ioerror("fork");
        throw_exception(c, 1);
    case  0: {  /* child */
        int operation_result;
        void (*signal_result)(int);

        /* the child is not allowed to play with thread-local storage */
        /* see http://linux.die.net/man/3/pthread_atfork for details */
        (void)closesocket(fd[0]);
        /* dup2() does not copy FD_CLOEXEC flag */
        operation_result=dup2(fd[1], 0);
        if(operation_result<0)
            _exit(1);
        operation_result=dup2(fd[1], 1);
        if(operation_result<0)
            _exit(1);
        if(!c->opt->option.log_stderr) {
            operation_result=dup2(fd[1], 2);
            if(operation_result<0)
                _exit(1);
        }
        (void)closesocket(fd[1]); /* not really needed due to FD_CLOEXEC */
#ifdef HAVE_PTHREAD_SIGMASK
        operation_result=sigemptyset(&newmask);
        if(operation_result)
            _exit(1);
        operation_result=sigprocmask(SIG_SETMASK, &newmask, NULL);
        if(operation_result)
            _exit(1);
#endif
        /* POSIX defines the default handler through a pointer cast. */
        /* cppcheck-suppress-begin misra-c2012-11.6 */
        signal_result=signal(SIGCHLD, SIG_DFL);
        if(signal_result==SIG_ERR)
            _exit(1);
        signal_result=signal(SIGHUP, SIG_DFL);
        if(signal_result==SIG_ERR)
            _exit(1);
        signal_result=signal(SIGUSR1, SIG_DFL);
        if(signal_result==SIG_ERR)
            _exit(1);
        signal_result=signal(SIGUSR2, SIG_DFL);
        if(signal_result==SIG_ERR)
            _exit(1);
        signal_result=signal(SIGPIPE, SIG_DFL);
        if(signal_result==SIG_ERR)
            _exit(1);
        signal_result=signal(SIGTERM, SIG_DFL);
        if(signal_result==SIG_ERR)
            _exit(1);
        signal_result=signal(SIGQUIT, SIG_DFL);
        if(signal_result==SIG_ERR)
            _exit(1);
        signal_result=signal(SIGINT, SIG_DFL);
        if(signal_result==SIG_ERR)
            _exit(1);
        /* cppcheck-suppress-end misra-c2012-11.6 */
        (void)execve(c->opt->exec_name, c->opt->exec_args, env);
        _exit(1); /* failed, but there is no way to report an error here */
    }
    default: /* parent */
        (void)closesocket(fd[1]);
        env_free(env);
        s_log(LOG_INFO, "Local mode child started (PID=%lu)", c->pid);
        return fd[0];
    }
}

NOEXPORT char **env_alloc(CLI *c) {
    /* Some supported Unix headers do not declare this process-global symbol. */
    /* cppcheck-suppress [shadowVariable, misra-c2012-5.8] */
    extern char **environ;
    char **env=NULL, **p;
    unsigned n=0; /* (n+2) keeps the list NULL-terminated */
    char *name, host[40], port[6];
    X509 *peer_cert;

    if(!getnameinfo(&c->peer_addr.sa, c->peer_addr_len,
            host, 40, port, 6, NI_NUMERICHOST|NI_NUMERICSERV)) {
        /* just don't set these variables if getnameinfo() fails */
        env=str_realloc(env, (n+2U)*sizeof(char *));
        env[n++]=str_printf("REMOTE_HOST=%s", host);
        env=str_realloc(env, (n+2U)*sizeof(char *));
        env[n++]=str_printf("REMOTE_PORT=%s", port);
        if(c->opt->option.transparent_src) {
#ifndef LIBDIR
#define LIBDIR "."
#endif
#ifdef MACH64
            env=str_realloc(env, (n+2U)*sizeof(char *));
            env[n++]=str_dup("LD_PRELOAD_32=" LIBDIR "/libstunnel.so");
            env=str_realloc(env, (n+2U)*sizeof(char *));
            env[n++]=str_dup("LD_PRELOAD_64=" LIBDIR "/" MACH64 "/libstunnel.so");
#elif defined(__osf) || defined(__osf__)
            /* for Tru64 _RLD_LIST is used instead */
            env=str_realloc(env, (n+2U)*sizeof(char *));
            env[n++]=str_dup("_RLD_LIST=" LIBDIR "/libstunnel.so:DEFAULT");
#else
            env=str_realloc(env, (n+2U)*sizeof(char *));
            env[n++]=str_dup("LD_PRELOAD=" LIBDIR "/libstunnel.so");
#endif
        }
    }

    if( !getnameinfo( &c->local_addr.sa, c->local_addr_len,
                      host, 40, port, 6, NI_NUMERICHOST | NI_NUMERICSERV ) )
    {
        /* just don't set these variables if getnameinfo() fails */
        env = str_realloc( env, ( n + 2 ) * sizeof( char * ) );
        env[n++] = str_printf( "LOCAL_HOST=%s", host );
        env = str_realloc( env, ( n + 2 ) * sizeof( char * ) );
        env[n++] = str_printf( "LOCAL_PORT=%s", port );
    }

    if( c->msh )
    {
        const uint8_t * subject;
        size_t slen;
        const uint8_t * issuer;
        size_t ilen;
        if( msspi_get_peernames( c->msh, &subject, &slen, &issuer, &ilen ) )
        {
            env = str_realloc( env, ( n + 2 ) * sizeof( char * ) );
            env[n++] = str_printf( "SSL_CLIENT_DN=%s", (const char *)subject );
            env = str_realloc( env, ( n + 2 ) * sizeof( char * ) );
            env[n++] = str_printf( "SSL_CLIENT_I_DN=%s", (const char *)issuer );
        }
    }

    {
        env = str_realloc( env, ( n + 2 ) * sizeof( char * ) );
        env[n++] = str_printf( "SERVICENAME=%s", c->opt->servname );
        env = str_realloc( env, ( n + 2 ) * sizeof( char * ) );
        env[n++] = str_printf( "CLIENTMODE=%d", c->opt->option.client );
    }

    for(p=environ; *p; ++p) {
        env=str_realloc(env, (n+2U)*sizeof(char *));
        env[n++]=str_dup(*p);
    }

    return env;
}

NOEXPORT void env_free(char **env) {
    char **p;

    p=env;
    while(*p) {
        str_free(*p);
        ++p;
    }
    str_free(env);
}

#endif /* not USE_WIN32 or __vms */

/* connect remote host */
NOEXPORT SOCKET connect_remote(CLI *c) {
    SOCKET fd;
    unsigned idx_start, idx_try;

    connect_setup(c);
    switch(c->connect_addr.num) {
    case 0:
        s_log(LOG_ERR, "No remote host resolved");
        throw_exception(c, 1);
    case 1:
        idx_start=0;
        break;
    default:
        idx_start=idx_cache_retrieve(c);
    }

    /* try to connect each host from the list */
    for(idx_try=0; idx_try<c->connect_addr.num; idx_try++) {
        c->idx=(idx_start+idx_try)%c->connect_addr.num;
        if(!connect_init(c, c->connect_addr.addr[c->idx].sa.sa_family)) {
            if(!s_connect(c, &c->connect_addr.addr[c->idx],
                    sockaddr_len(&c->connect_addr.addr[c->idx]),
                    c->opt->timeout_connect)) {
#if defined(MSSPI_LINUX) && defined(HAVE_STRUCT_SOCKADDR_UN)
                if(c->opt->option.for_hsm &&
                        c->connect_addr.addr[c->idx].sa.sa_family==AF_UNIX &&
                        !wire_send_credentials(c->fd))
                    throw_exception(c, 1);
#endif
                print_bound_address(c);
                fd=c->fd;
                c->fd=INVALID_SOCKET;
                return fd; /* success! */
            }
        }
        if(c->fd!=INVALID_SOCKET) {
            (void)closesocket(c->fd);
            c->fd=INVALID_SOCKET;
        }
    }
    s_log(LOG_ERR, "No more addresses to connect");
    throw_exception(c, 1);
    return INVALID_SOCKET; /* some C compilers require a return value */
}

NOEXPORT void idx_cache_save(SSL_SESSION *sess, SOCKADDR_UNION *cur_addr) {
    SOCKADDR_UNION *old_addr, *new_addr;
    socklen_t len;
    char *addr_txt;
    int ok;

    /* make a copy of the address, so it may work with delayed resolver */
    len=sockaddr_len(cur_addr);
    new_addr=str_alloc_detached((size_t)len);
    (void)memcpy(new_addr, cur_addr, (size_t)len);

    addr_txt=s_ntop(cur_addr, len);
    s_log(LOG_INFO, "persistence: %s cached", addr_txt);
    str_free(addr_txt);

}

NOEXPORT unsigned idx_cache_retrieve(CLI *c) {
    unsigned i;
    SOCKADDR_UNION addr, *ptr;
    socklen_t len;
    char *addr_txt;

    if(c->opt->failover==FAILOVER_RR) {
        i=(c->connect_addr.start+c->rr)%c->connect_addr.num;
        s_log(LOG_INFO, "failover: round-robin, starting at entry #%d", i);
    } else {
        i=0;
        s_log(LOG_INFO, "failover: priority, starting at entry #0");
    }
    return i;
}

NOEXPORT void connect_setup(CLI *c) {
    if(c->flag.redirect) { /* process "redirect" first */
        s_log(LOG_NOTICE, "Redirecting connection");
        /* c->connect_addr.addr may be allocated in protocol negotiations */
        str_free(c->connect_addr.addr);
        (void)addrlist_dup(&c->connect_addr, &c->opt->redirect_addr);
        return;
    }

    /* check if the address was already set in protocol negotiations */
    /* used by the following protocols: CONNECT, SOCKS */
    if(c->connect_addr.num)
        return;

    /* transparent destination */
    if(c->opt->option.transparent_dst) {
        c->connect_addr.num=1;
        c->connect_addr.addr=str_alloc(sizeof(SOCKADDR_UNION));
        if(original_dst(c->local_rfd.fd, c->connect_addr.addr))
            throw_exception(c, 1);
        return;
    }

    /* default "connect" target */
    (void)addrlist_dup(&c->connect_addr, &c->opt->connect_addr);
}

NOEXPORT int connect_init(CLI *c, int domain) {
    SOCKADDR_UNION bind_addr;

    if(c->bind_addr) {
        /* setup bind_addr based on c->bind_addr */
        (void)memcpy(&bind_addr, c->bind_addr, (size_t)sockaddr_len(c->bind_addr));
        /* perform the initial sanity checks before creating a socket */
        if(!addr_family_is(&bind_addr, domain)) {
            s_log(LOG_DEBUG, "Cannot assign an AF=%d address an AF=%d socket",
                bind_addr.sa.sa_family, domain);
            return 1; /* failure */
        }
    } else {
        /* only needed to avoid a warning in MSVC */
        (void)memset(&bind_addr, 0, sizeof bind_addr);
    }

    /* create a new socket */
    c->fd=s_socket(domain,
        c->opt->sock_type,
        0, 1, "remote socket");
    if(c->fd==INVALID_SOCKET)
        return 1; /* failure */
    if(!c->bind_addr)
        return 0; /* success */

    /* enable non-local bind if needed (and supported) */
#ifndef USE_WIN32
    if(c->opt->option.transparent_src) {
#if defined(__linux__)
        /* Non-local bind is only needed for transparent source mode.
         * Keep direct setsockopt for Linux fallback semantics:
         * try IP_TRANSPARENT, then IP_FREEBIND, and let bind() decide. */
        int on=1;
        if(setsockopt(c->fd, SOL_IP, IP_TRANSPARENT, &on, sizeof on)) {
            sockerror("setsockopt IP_TRANSPARENT");
            if(setsockopt(c->fd, SOL_IP, IP_FREEBIND, &on, sizeof on))
                sockerror("setsockopt IP_FREEBIND");
            else
                s_log(LOG_INFO, "IP_FREEBIND socket option set");
        } else
            s_log(LOG_INFO, "IP_TRANSPARENT socket option set");
        /* ignore the error to retain Linux 2.2 compatibility */
        /* the error will be handled by bind(), anyway */
#elif defined(IP_BINDANY) && defined(IPV6_BINDANY)
        /* Non-local bind on FreeBSD is address-family specific,
         * unlike service socket option defaults. */
        int on=1;
        if(domain==AF_INET) { /* IPv4 */
            if(setsockopt(c->fd, IPPROTO_IP, IP_BINDANY, &on, sizeof on)) {
                sockerror("setsockopt IP_BINDANY");
                return 1; /* failure */
            }
        } else { /* IPv6 */
            if(setsockopt(c->fd, IPPROTO_IPV6, IPV6_BINDANY, &on, sizeof on)) {
                sockerror("setsockopt IPV6_BINDANY");
                return 1; /* failure */
            }
        }
#else
        /* unsupported platform */
        /* FIXME: move this check to options.c */
        s_log(LOG_ERR, "Transparent proxy in remote mode is not supported"
            " on this platform");
        throw_exception(c, 1);
#endif
    }
#endif /* !defined(USE_WIN32) */

    /* explicit local bind or transparent proxy */
    /* there is no need for a separate IPv6 logic here,
     * as port number is at the same offset in both structures */
    if(ntohs(bind_addr.in.sin_port)>=1024U) { /* security check */
        /* this is currently only possible with transparent_src */
        if(!bind(c->fd, &bind_addr.sa, sockaddr_len(&bind_addr))) {
            s_log(LOG_INFO, "bind succeeded on the original port");
            return 0; /* success */
        }
        if(get_last_socket_error()!=S_EADDRINUSE) {
            sockerror("bind (original port)");
            return 1; /* failure */
        }
    }
    bind_addr.in.sin_port=htons(0); /* retry with ephemeral port */
    if(!bind(c->fd, &bind_addr.sa, sockaddr_len(&bind_addr))) {
        s_log(LOG_INFO, "bind succeeded on an ephemeral port");
        return 0; /* success */
    }
    sockerror("bind (ephemeral port)");
    return 1; /* failure */
}

NOEXPORT int redirect(CLI *c) {
    SSL_SESSION *sess;
    void *ex_data;

    if(!c->opt->redirect_addr.names)
        return 0; /* redirect not configured */
    return 1;
}

NOEXPORT void print_bound_address(CLI *c) {
    char *txt;
    SOCKADDR_UNION addr;
    socklen_t addrlen=sizeof addr;

    if(c->opt->log_level<LOG_NOTICE) /* performance optimization */
        return;
    (void)memset(&addr, 0, (size_t)addrlen);
    /* getsockname() requires the generic sockaddr API view. */
    /* cppcheck-suppress misra-c2012-11.3 */
    if(getsockname(c->fd, (struct sockaddr *)&addr, &addrlen)) {
        sockerror("getsockname");
        return;
    }
    txt=s_ntop(&addr, addrlen);
    s_log(LOG_NOTICE,"Service [%s] connected remote server from %s",
        c->opt->servname, txt);
    str_free(txt);

    if( c->is_exec )
    {
        memcpy( &c->local_addr.sa, &addr.sa, (size_t)addrlen );

        addrlen = sizeof( SOCKADDR_UNION );
        if( !getpeername( c->fd, &addr.sa, &addrlen ) )
        {
            memcpy( &c->peer_addr.sa, &addr.sa, (size_t)addrlen );
            c->peer_addr_len = addrlen;
        }
    }
}

/* Set linger only on the reset path to force TCP RST.
 * This must not be a default socket option. */
NOEXPORT void reset(SOCKET fd, const char *txt) {
    struct linger l;

    s_log(LOG_DEBUG, "%s reset (FD=%ld)", txt, (long)fd);
    l.l_onoff=1;
    l.l_linger=0;
    if(setsockopt(fd, SOL_SOCKET, SO_LINGER, (void *)&l, sizeof l)) {
        int err=get_last_socket_error();
        char *message=str_printf("setsockopt(SO_LINGER) on %s", txt);

        log_error(LOG_INFO, err, message);
        str_free(message);
    }
}

NOEXPORT void check_fds_error(CLI *c) {
    if(c->sock_rfd->fd==c->sock_wfd->fd) {
        check_socket_error(c, c->sock_rfd->fd, "socket fd");
    } else {
        check_socket_error(c, c->sock_rfd->fd, "socket rfd");
        check_socket_error(c, c->sock_wfd->fd, "socket wfd");
    }
    if(c->ssl_rfd->fd==c->ssl_wfd->fd) {
        check_socket_error(c, c->ssl_rfd->fd, "TLS fd");
    } else {
        check_socket_error(c, c->ssl_rfd->fd, "TLS rfd");
        check_socket_error(c, c->ssl_wfd->fd, "TLS wfd");
    }
}

NOEXPORT void check_socket_error(CLI *c, SOCKET fd, const char *name) {
    if(s_poll_err(c->fds, fd)) {
        int err=get_socket_error(fd);

        if(!err) {
            s_log(LOG_DEBUG, "Spurious s_poll exception on %s", name);
        } else if(err==S_EWOULDBLOCK || err==S_EAGAIN) {
            log_error(LOG_DEBUG, err, name);
        } else {
            log_error(LOG_ERR, err, name);
            /* throwing an exception here truncated connections
             * in stunnel versions 4.34 - 5.08 */
            /* throw_exception(c, 1); */
        }
    }
}

void throw_exception(CLI *c, int v) {
    if(!c || !c->exception_pointer)
        fatal("No exception handler");
    longjmp(*c->exception_pointer, v);
}

/* end of client.c */
