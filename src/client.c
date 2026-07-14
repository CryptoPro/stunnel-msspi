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

#ifdef MSSPISSL
#ifdef NO_OPENSSLOFF
#else /* NO_OPENSSLOFF */
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
#define SSL_set_fd( s, fd ) c->rfd = c->wfd = fd
#define SSL_set_rfd( s, fd ) c->rfd = fd
#define SSL_set_wfd( s, fd ) c->wfd = fd
#define SSL_has_pending( s ) msspi_pending( c->msh )
#endif /* NO_OPENSSLOFF */
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
int msspi_gate_connect( CLI * c )
{
    int ret;
    msspi_gate_enter();
    ret = msspi_connect( c->msh );
    msspi_gate_leave();
    return ret;
}
int msspi_gate_accept( CLI * c )
{
    int ret;
    msspi_gate_enter();
    ret = msspi_accept( c->msh );
    msspi_gate_leave();
    return ret;
}
int msspi_gate_read( CLI * c, void * buf, int len )
{
    int ret;
    msspi_gate_enter();
    ret = msspi_read( c->msh, buf, len );
    msspi_gate_leave();
    return ret;
}
int msspi_gate_write( CLI * c, const void * buf, int len )
{
    int ret;
    msspi_gate_enter();
    ret = msspi_write( c->msh, buf, len );
    msspi_gate_leave();
    return ret;
}
int msspi_gate_shutdown( CLI * c )
{
    int ret;
    msspi_gate_enter();
    ret = msspi_shutdown( c->msh );
    msspi_gate_leave();
    return ret;
}
void msspi_gate_close( CLI * c )
{
    msspi_gate_enter();
    msspi_close( c->msh );
    c->msh = NULL;
    msspi_gate_leave();
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

int stunnel_msspi_bio_read( CLI * c, void * buf, int len )
{
    int io;

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
    io = writesocket( c->wfd, buf, len );

    if( io > 0 )
        return io;

    if( BIO_sock_should_retry( io ) )
        return -1;

    return 0;
}
#endif /* MSSPISSL */

#ifndef SHUT_RD
#define SHUT_RD 0
#endif
#ifndef SHUT_WR
#define SHUT_WR 1
#endif
#ifndef SHUT_RDWR
#define SHUT_RDWR 2
#endif

NOEXPORT void client_try(CLI *);
NOEXPORT void exec_connect_loop(CLI *);
NOEXPORT void exec_connect_once(CLI *);
NOEXPORT void client_run(CLI *);
NOEXPORT void local_start(CLI *);
NOEXPORT void remote_start(CLI *);
NOEXPORT void ssl_start(CLI *);
NOEXPORT void session_cache_retrieve(CLI *);
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
NOEXPORT void print_tmp_key(SSL *s);
#endif
NOEXPORT void print_cipher(CLI *);
NOEXPORT void transfer(CLI *);

NOEXPORT void auth_user(CLI *);
NOEXPORT SOCKET connect_local(CLI *);
#if !defined(USE_WIN32) && !defined(__vms)
NOEXPORT char **env_alloc(CLI *);
NOEXPORT void env_free(char **);
#endif
NOEXPORT SOCKET connect_remote(CLI *);
NOEXPORT void idx_cache_save(SSL_SESSION *, SOCKADDR_UNION *);
NOEXPORT unsigned idx_cache_retrieve(CLI *);
NOEXPORT void connect_setup(CLI *);
NOEXPORT int connect_init(CLI *, int);
NOEXPORT int redirect(CLI *);
NOEXPORT void print_bound_address(CLI *);
NOEXPORT void reset(SOCKET, const char *);
NOEXPORT void check_socket_error(CLI *, SOCKET, const char *);

#ifdef MSSPISSL
NOEXPORT int stunnel_msspi_cert_cb(void *);
NOEXPORT int msspi_load_own_certs(CLI *);
NOEXPORT int msspi_verify_peer(CLI *);
static int msspi_no_resume_cache_id=0;
#endif

/* allocate local data structure for the new thread */
CLI *alloc_client_session(SERVICE_OPTIONS *opt, SOCKET rfd, SOCKET wfd) {
    static unsigned long long seq=0;
    CLI *c;

    c=str_alloc_detached(sizeof(CLI));
    c->opt=opt;
    c->local_rfd.fd=rfd;
    c->local_wfd.fd=wfd;
    c->seq=seq++;
    c->rr=c->opt->rr++;
    return c;
}

#if defined(USE_WIN32) || defined(USE_OS2)
unsigned __stdcall
#else
void *
#endif
        client_thread(void *arg) {
    CLI *c=arg;
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
    CRYPTO_THREAD_read_lock(stunnel_locks[LOCK_THREAD_LIST]);
    CRYPTO_THREAD_unlock(stunnel_locks[LOCK_THREAD_LIST]);

    /* initialize */
    c->tls=NULL; /* do not reuse */
    tls_alloc(c, NULL, NULL);
#ifdef DEBUG_STACK_SIZE
    stack_info(stack_size, 1); /* initialize */
#endif

    /* execute */
    client_main(c);

    /* cleanup the thread */
#ifndef USE_FORK
    CRYPTO_THREAD_write_lock(stunnel_locks[LOCK_THREAD_LIST]);
    if(thread_head==c)
        thread_head=c->thread_next;
    if(c->thread_prev)
        c->thread_prev->thread_next=c->thread_next;
    if(c->thread_next)
        c->thread_next->thread_prev=c->thread_prev;
#ifdef USE_PTHREAD
    pthread_detach(c->thread_id);
#endif
#ifdef USE_WIN32
    CloseHandle(c->thread_id);
#endif
    CRYPTO_THREAD_unlock(stunnel_locks[LOCK_THREAD_LIST]);
#endif /* !USE_FORK */
    client_free(c);
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

void client_free(CLI *c) {
#ifndef USE_FORK
    service_free(c->opt);
#endif
    str_free(c);
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
    memcpy(c, fresh_c, sizeof(CLI));

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
    char *close_status;
#ifndef USE_FORK
    int num;
#endif

#ifndef USE_FORK
#ifdef USE_OS_THREADS
    CRYPTO_atomic_add(&num_clients, 1, &num, stunnel_locks[LOCK_CLIENTS]);
#else
    num=++num_clients;
#endif
    ui_clients(num);
#endif

        /* initialize the client context */
    c->remote_fd.fd=INVALID_SOCKET;
    c->fd=INVALID_SOCKET;
#ifdef MSSPISSL
    if( !c->is_exec )
        c->exec_fd = INVALID_SOCKET;
#endif
    c->ssl=NULL;
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
        (!c->fatal_alert || !c->opt->option.client);
    /* plain socket is local in the client mode */
    rst_local=err==1 && c->opt->option.reset &&
        (!c->fatal_alert || c->opt->option.client);
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
    if(capwin_hwnd && (rst_remote || rst_local)
            && InterlockedExchange(&capwin_connectivity, 0))
        PostMessage(capwin_hwnd, WM_CAPWIN_NET_DOWN, 0, 0);
#endif

        /* cleanup temporary (e.g. IDENT) socket */
    if(c->fd!=INVALID_SOCKET)
        closesocket(c->fd);
    c->fd=INVALID_SOCKET;

#ifdef NO_OPENSSLOFF

        /* cleanup the TLS context */
    if(c->ssl) { /* TLS initialized */
        SSL_set_shutdown(c->ssl, SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN);
        SSL_free(c->ssl);
        c->ssl=NULL;
#if OPENSSL_VERSION_NUMBER >= 0x10100006L
        /* OpenSSL version >= 1.1.0-pre6 */
        /* the function is no longer needed */
#elif OPENSSL_VERSION_NUMBER >= 0x10100004L
        /* OpenSSL version 1.1.0-pre4 or 1.1.0-pre5 */
        ERR_remove_thread_state();
#elif OPENSSL_VERSION_NUMBER >= 0x10000000L
        /* OpenSSL version >= 1.0.0 */
        ERR_remove_thread_state(NULL);
#else
        /* OpenSSL version < 1.0.0 */
        ERR_remove_state(0);
#endif
    }

#endif /* NO_OPENSSLOFF */
#ifdef MSSPISSL
    if( c->msh )
    {
#ifdef MSSPI_LINUX
        msspi_gate_shutdown( c );
        msspi_gate_close( c );
#else
        msspi_shutdown( c->msh );
        msspi_close( c->msh );
        c->msh = NULL;
#endif
    }

    if( c->exec_fd != INVALID_SOCKET )
    {
        closesocket( c->exec_fd );
        c->exec_fd = INVALID_SOCKET;
    }
#endif /* MSSPISSL */

        /* cleanup the remote socket */
    if(c->remote_fd.fd!=INVALID_SOCKET) { /* remote socket initialized */
        if(rst_remote && c->remote_fd.is_socket) /* reset */
            reset(c->remote_fd.fd, "remote_fd");
#ifndef USE_UCONTEXT
        set_nonblock(c->remote_fd.fd, 0);
#endif
        closesocket(c->remote_fd.fd);
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
            closesocket(c->local_rfd.fd);
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
#ifdef USE_OS_THREADS
    CRYPTO_atomic_add(&num_clients, -1, &num, stunnel_locks[LOCK_CLIENTS]);
#else
    num=--num_clients;
#endif
    ui_clients(num);
    s_log(LOG_DEBUG, "Service [%s] finished (%ld left)", c->opt->servname, num);
#endif

        /* free the client context */
    str_free(c->connect_addr.addr);
    /* a client does not have its own local copy of
       c->connect_addr.session and c->connect_addr.fd */
    s_poll_free(c->fds);
    str_free(c->accepted_address);
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
#ifdef MSSPISSL
    if( c->is_exec )
        connect_local( c );
#endif

    if(c->opt->protocol_late && !c->flag.redirect)
        c->opt->protocol_late(c);
    transfer(c);
}

NOEXPORT void local_start(CLI *c) {
    SOCKADDR_UNION addr;
    socklen_t addr_len;

    /* check if local_rfd is a socket and get peer address */
    addr_len=sizeof(SOCKADDR_UNION);
    c->local_rfd.is_socket=!getpeername(c->local_rfd.fd, &addr.sa, &addr_len);
    if(c->local_rfd.is_socket) {
        /* store the retrieved peer address */
        memcpy(&c->peer_addr.sa, &addr.sa, (size_t)addr_len);
        c->peer_addr_len=addr_len;
        if(
#ifdef HAVE_STRUCT_SOCKADDR_UN
                addr.sa.sa_family!=AF_UNIX &&
#endif
                socket_options_set(c->opt, c->local_rfd.fd, 1)) {
            s_log(LOG_WARNING, "Failed to set local socket options");
        }
    } else if(get_last_socket_error()!=S_ENOTSOCK) {
        sockerror("getpeerbyname (local_rfd)");
        throw_exception(c, 1);
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
                memcpy(&c->peer_addr.sa, &addr.sa, (size_t)addr_len);
                c->peer_addr_len=addr_len;
            }
            if(
#ifdef HAVE_STRUCT_SOCKADDR_UN
                    addr.sa.sa_family!=AF_UNIX &&
#endif
                    socket_options_set(c->opt, c->local_wfd.fd, 1)) {
                s_log(LOG_WARNING, "Failed to set local socket options");
            }
        } else if(get_last_socket_error()!=S_ENOTSOCK) {
            sockerror("getpeerbyname (local_wfd)");
            throw_exception(c, 1);
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

    /* authenticate based on retrieved IP address of the client */
    c->accepted_address=s_ntop(&c->peer_addr, c->peer_addr_len);
#ifdef USE_LIBWRAP
    libwrap_auth(c);
#endif /* USE_LIBWRAP */
    auth_user(c);
    s_log(LOG_NOTICE, "Service [%s] accepted connection from %s",
        c->opt->servname, c->accepted_address);

#ifdef MSSPISSL
    if( c->local_rfd.is_socket || c->local_wfd.is_socket )
    {
        addr_len = sizeof( SOCKADDR_UNION );
        if( !getsockname( c->local_rfd.is_socket ? c->local_rfd.fd : c->local_wfd.fd, &addr.sa, &addr_len ) )
        {
            memcpy( &c->local_addr.sa, &addr.sa, (size_t)addr_len );
            c->local_addr_len = addr_len;
        }
    }
#endif
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

#ifdef MSSPISSL
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
            const long int MAX_SIZE=1024*1024;
            const char *errstr="unknown";
            long int size_file=0;
            FILE *cert_file=NULL;
            char *str_file=NULL;

            s_log(LOG_INFO, "msspi: try open cert = \"%s\" as file", cert);

            for(;;) {
                if((cert_file=fopen(cert, "rb"))==NULL) {
                    errstr="can not open file";
                    break;
                }
                if(fseek(cert_file, 0, SEEK_END)==-1L) {
                    errstr="can not read file";
                    break;
                }
                if((size_file=ftell(cert_file))>MAX_SIZE) {
                    errstr="file too large";
                    break;
                }
                if(fseek(cert_file, 0, 0)==-1L) {
                    errstr="can not read file";
                    break;
                }
                if((str_file=(char *)malloc(sizeof(char)*(size_t)size_file))==NULL) {
                    errstr="can not allocate memory for file";
                    break;
                }
                if(fread(str_file, sizeof(char), (size_t)size_file, cert_file) !=
                        (unsigned long int)size_file) {
                    errstr="can not read file";
                    break;
                }
                if(certtype==0) { /* CPCSP-14527 better diagnostic flow */
                    MSSPI_CERT_HANDLE ch=msspi_cert_open((const uint8_t *)str_file, (size_t)size_file);
                    if(ch) {
                        is_cert_file=1;
                        msspi_cert_close(ch);
                    }
                } else if(certtype==3) {
                    is_cert_file=1;
                }

                if(is_cert_file &&
                        msspi_add_mycert(c->msh, (const uint8_t *)str_file, (size_t)size_file)) {
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
                        msspi_add_mycert_pfx(c->msh, (const uint8_t *)str_file, (size_t)size_file,
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

            if(cert_file)
                fclose(cert_file);
            if(str_file)
                free(str_file);
            if(!is_ok) {
                s_log(LOG_ERR, "msspi: add_mycert failed: \"%s\" (cert = \"%s\")", errstr, cert);
                return 0;
            }
        }

        if(cert && !is_pfx && !msspi_set_mycert_options(c->msh,
                c->opt->option.silent, (const uint8_t *)pin, pin ? strlen(pin) : 0,
                c->opt->option.selftest)) {
            s_log(LOG_ERR,
                "msspi: msspi_set_mycert_options failed (cert = \"%s\", pin = \"%s\", silent = \"%s\", selftest = \"%s\")",
                cert, pin ? pin : "", c->opt->option.silent ? "yes" : "no",
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
        const char *errinfo="failed (MSSPI_VERIFY_ERROR)";
        uint32_t verify_status=(uint32_t)-1;
        msspi_get_verify_status(c->msh, &verify_status);
        switch(verify_status) {
        case 0:
            level=LOG_INFO;
            errinfo="OK";
            break;
        case CERT_E_CN_NO_MATCH:
            if(c->opt->sni && c->opt->check_host) {
                NAME_LIST *ptr;
                for(ptr=c->opt->check_host; ptr; ptr=ptr->next) {
                    msspi_set_hostname(c->msh, (const uint8_t *)ptr->name, strlen(ptr->name));
                    msspi_get_verify_status(c->msh, &verify_status);
                    if(verify_status==0)
                        break;
                }

                msspi_set_hostname(c->msh, (const uint8_t *)c->opt->sni, strlen(c->opt->sni));

                if(ptr) {
                    level=LOG_INFO;
                    errinfo="OK";
                    break;
                }
            }
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

NOEXPORT int stunnel_msspi_cert_cb(void *arg) {
    CLI *c=(CLI *)arg;

    if(!c || !c->msh)
        return 0;
    if(!msspi_verify_peer(c))
        return 0;
    c->msspi_peer_verified=1;
    return msspi_load_own_certs(c);
}
#endif /* MSSPISSL */

NOEXPORT void ssl_start(CLI *c) {
    int i, err;
    SSL_SESSION *sess;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    int unsafe_openssl;
#endif /* OpenSSL version < 1.1.0 */

#ifdef NO_OPENSSLOFF

    c->ssl=SSL_new(c->opt->ctx);
    if(!c->ssl) {
        ssl_error(c, "SSL_new");
        throw_exception(c, 1);
    }
    /* for callbacks */
    if(!SSL_set_ex_data(c->ssl, index_ssl_cli, c)) {
        ssl_error(c, "SSL_set_ex_data");
        throw_exception(c, 1);
    }
    if(c->opt->option.client) {
#ifndef OPENSSL_NO_TLSEXT
#ifndef OPENSSL_NO_OCSP
        if(!SSL_set_tlsext_status_type(c->ssl, TLSEXT_STATUSTYPE_ocsp)) {
            ssl_error(c, "OCSP: SSL_set_tlsext_status_type");
            throw_exception(c, 1);
        }
#endif /* !defined(OPENSSL_NO_OCSP) */
        /* c->opt->sni should always be initialized at this point,
         * either explicitly with "sni"
         * or implicitly with "protocolHost" or "connect" */
        if(c->opt->sni && *c->opt->sni) {
            s_log(LOG_INFO, "SNI: sending servername: %s", c->opt->sni);
            if(!SSL_set_tlsext_host_name(c->ssl, c->opt->sni)) {
                ssl_error(c, "SSL_set_tlsext_host_name");
                throw_exception(c, 1);
            }
        } else { /* c->opt->sni was set to an empty value */
            s_log(LOG_INFO, "SNI: extension disabled");
        }
#endif
        session_cache_retrieve(c);
        SSL_set_fd(c->ssl, (int)c->remote_fd.fd);
        SSL_set_connect_state(c->ssl);
    } else { /* TLS server */
        if(c->local_rfd.fd==c->local_wfd.fd)
            SSL_set_fd(c->ssl, (int)c->local_rfd.fd);
        else {
           /* does it make sense to have TLS on STDIN/STDOUT? */
            SSL_set_rfd(c->ssl, (int)c->local_rfd.fd);
            SSL_set_wfd(c->ssl, (int)c->local_wfd.fd);
        }
        SSL_set_accept_state(c->ssl);
    }

#endif /* NO_OPENSSLOFF */

#ifdef MSSPISSL
    c->msh = NULL;
    c->msspi_peer_verified = 0;
    if( c->opt->option.msspi )
    {
        if( c->opt->option.client )
            c->rfd = c->wfd = c->remote_fd.fd;
        else
            c->rfd = c->wfd = c->local_rfd.fd;

        c->msh = msspi_open( c, (msspi_read_cb)stunnel_msspi_bio_read, (msspi_write_cb)stunnel_msspi_bio_write );

        if( !c->msh )
        {
            s_log( LOG_ERR, "msspi: open failed" );
            throw_exception( c, 1 );
        }

        if( !c->opt->option.session_resume )
        {
            int cache_id;
#ifdef USE_OS_THREADS
            CRYPTO_atomic_add( &msspi_no_resume_cache_id, 1, &cache_id, stunnel_locks[LOCK_CLIENTS] );
#else
            cache_id = ++msspi_no_resume_cache_id;
#endif
            if( !msspi_set_cachestring( c->msh, (const uint8_t *)&cache_id, sizeof cache_id ) )
            {
                s_log( LOG_ERR, "msspi: failed to set no-resume credential cache string" );
                throw_exception( c, 1 );
            }
        }

        /* Preserve MSSPI provider defaults when stunnel min/max are unset:
         * grbitEnabledProtocols must remain 0, not an explicit all-protocols mask. */
        if( c->opt->min_proto_version || c->opt->max_proto_version )
            msspi_set_version( c->msh, c->opt->min_proto_version, c->opt->max_proto_version );

        if( c->opt->sni )
            msspi_set_hostname( c->msh, (const uint8_t *)c->opt->sni, strlen( c->opt->sni ) );

        if( c->opt->option.request_cert )
            msspi_set_peerauth( c->msh, 1 );

        if( c->opt->option.client )
            msspi_set_client( c->msh, 1 );

        if( c->opt->cipher_list )
            msspi_set_cipherlist( c->msh, (const uint8_t *)c->opt->cipher_list, strlen( c->opt->cipher_list ) );

        if( c->opt->option.client )
            msspi_set_cert_cb( c->msh, stunnel_msspi_cert_cb );
        else if( !msspi_load_own_certs( c ) )
            throw_exception( c, 1 );
    }
#endif /* MSSPISSL */

    if(c->opt->option.require_cert)
        s_log(LOG_INFO, "Peer certificate required");
    else
        s_log(LOG_INFO, "Peer certificate not required");
#ifdef NO_OPENSSLOFF
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    unsafe_openssl=OpenSSL_version_num()<0x0090810fL ||
        (OpenSSL_version_num()>=0x10000000L &&
        OpenSSL_version_num()<0x1000002fL);
#endif /* OpenSSL version < 1.1.0 */
#endif /* NO_OPENSSLOFF */
    while(1) {
#ifdef NO_OPENSSLOFF
        /* critical section for OpenSSL version < 0.9.8p or 1.x.x < 1.0.0b *
         * this critical section is a crude workaround for CVE-2010-3864   *
         * see http://www.securityfocus.com/bid/44884 for details          *
         * alternative solution is to disable internal session caching     *
         * NOTE: this critical section also covers callbacks (e.g. OCSP)   */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        if(unsafe_openssl)
            CRYPTO_THREAD_write_lock(stunnel_locks[LOCK_SSL]);
#endif /* OpenSSL version < 1.1.0 */
#endif /* NO_OPENSSLOFF */

        i=c->opt->option.client ? SSL_connect(c->ssl) : SSL_accept(c->ssl);

#ifdef NO_OPENSSLOFF
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        if(unsafe_openssl)
            CRYPTO_THREAD_unlock(stunnel_locks[LOCK_SSL]);
#endif /* OpenSSL version < 1.1.0 */
#endif /* NO_OPENSSLOFF */

        err=SSL_get_error(c->ssl, i);
        if(err==SSL_ERROR_NONE)
            break; /* ok -> done */
        if(err==SSL_ERROR_WANT_READ || err==SSL_ERROR_WANT_WRITE) {
            s_poll_init(c->fds, 0);
            s_poll_add(c->fds, c->ssl_rfd->fd,
                err==SSL_ERROR_WANT_READ,
                err==SSL_ERROR_WANT_WRITE);
            switch(s_poll_wait(c->fds, c->opt->timeout_busy, 0)) {
            case -1:
                sockerror("ssl_start: s_poll_wait");
                throw_exception(c, 1);
            case 0:
                s_log(LOG_INFO, "ssl_start: s_poll_wait:"
                    " TIMEOUTbusy exceeded: sending reset");
                s_poll_dump(c->fds, LOG_DEBUG);
                throw_exception(c, 1);
            case 1:
                break; /* OK */
            default:
                s_log(LOG_ERR, "ssl_start: s_poll_wait: unknown result");
                throw_exception(c, 1);
            }
            continue; /* ok -> retry */
        }
#ifdef MSSPISSL
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
#endif /* MSSPISSL */
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
#ifdef MSSPISSL
    if( c->msh )
    {
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

        return;
    }
}
#else /* MSSPISSL */
    ERR_clear_error(); /* silence any cached errors */
    print_cipher(c);
    sess=SSL_get1_session(c->ssl);
    if(sess) {
        X509 *peer_cert=SSL_get_peer_certificate(c->ssl);
        if(peer_cert) {
            X509_free(peer_cert);
        } else { /* no authentication was performed */
            if(!SSL_SESSION_set_ex_data(sess,
                    index_session_authenticated, NULL)) {
                ssl_error(c, "SSL_SESSION_set_ex_data");
                SSL_SESSION_free(sess);
                throw_exception(c, 1);
            }
        }
        if(SSL_session_reused(c->ssl)) {
            /* otherwise printed from sess_new_cb() */
            print_session_id("Session id", sess);
        } else { /* a new session was negotiated */
            /* SSL_SESS_CACHE_NO_INTERNAL_STORE prevented automatic caching */
            if(!c->opt->option.client)
                SSL_CTX_add_session(c->opt->ctx, sess);
        }
        SSL_SESSION_free(sess);
    } else if(c->opt->redirect_addr.names) {
        s_log(LOG_ERR, "No session available for redirection");
        throw_exception(c, 1);
    }
    c->flag.redirect=(unsigned)redirect(c)&1;
}
#endif /* MSSPISSL */

#ifdef NO_OPENSSLOFF
NOEXPORT void session_cache_retrieve(CLI *c) {
    SSL_SESSION *sess=NULL;

    CRYPTO_THREAD_read_lock(stunnel_locks[LOCK_SESSION]);
    if(c->opt->connect_session) /* per-destination client session */
        sess=c->opt->connect_session[c->idx];
    if(!sess) /* either no per-destination cache or no session cached */
        sess=c->opt->session; /* fallback session */
    if(sess)
        SSL_set_session(c->ssl, sess);
    CRYPTO_THREAD_unlock(stunnel_locks[LOCK_SESSION]);

    if(sess)
        print_session_id("Attempting to resume", sess);
    else
        s_log(LOG_DEBUG, "No previous session to resume");
}

#if OPENSSL_VERSION_NUMBER >= 0x10101000L
NOEXPORT void print_tmp_key(SSL *s) {
    EVP_PKEY *key;
    long tmp_key_found;

#ifdef SSL_CTRL_GET_PEER_TMP_KEY
    tmp_key_found=SSL_get_peer_tmp_key(s, &key);
#else
    tmp_key_found=SSL_get_server_tmp_key(s, &key);
#endif
    if(!tmp_key_found) {
        s_log(LOG_INFO, "No peer temporary key received");
#if OPENSSL_VERSION_NUMBER>=0x30000000L
        if(SSL_version(s) == TLS1_3_VERSION) {
            s_log(LOG_INFO, "Negotiated TLSv1.3 group: %s",
                SSL_group_to_name(s, (int)SSL_get_negotiated_group(s)));
        }
#endif /* OPENSSL_VERSION_NUMBER>=0x30000000L */
        return;
    }
    switch(EVP_PKEY_id(key)) {
#if OPENSSL_VERSION_NUMBER>=0x30000000L
    case EVP_PKEY_KEYMGMT:
        {
            const char *keyname=EVP_PKEY_get0_type_name(key);

            if(keyname)
                s_log(LOG_INFO, "Peer temporary key: %s, %d bits",
                    keyname, EVP_PKEY_bits(key));
            else
                s_log(LOG_INFO, "Unable to determine temporary key type");
        }
        break;
#endif /* OPENSSL_VERSION_NUMBER>=0x30000000L */
    case EVP_PKEY_RSA:
        s_log(LOG_INFO, "Peer temporary key: RSA, %d bits", EVP_PKEY_bits(key));
        break;
    case EVP_PKEY_DH:
        s_log(LOG_INFO, "Peer temporary key: DH, %d bits", EVP_PKEY_bits(key));
        break;
#ifndef OPENSSL_NO_EC
    case EVP_PKEY_EC:
        {
            EC_KEY *ec=EVP_PKEY_get1_EC_KEY(key);
            int nid=EC_GROUP_get_curve_name(EC_KEY_get0_group(ec));
            const char *cname=EC_curve_nid2nist(nid);

            EC_KEY_free(ec);
            if (cname == NULL)
                cname=OBJ_nid2sn(nid);
            s_log(LOG_INFO, "Peer temporary key: ECDH, %s, %d bits", cname, EVP_PKEY_bits(key));
        }
        break;
#endif
    default:
        {
            int keyid=EVP_PKEY_id(key);

            if(keyid != NID_undef)
                s_log(LOG_INFO, "Peer temporary key: %s, %d bits",
                    OBJ_nid2sn(keyid), EVP_PKEY_bits(key));
            else
                s_log(LOG_INFO, "Unable to determine temporary key type");
        }
    }
    EVP_PKEY_free(key);
}
#endif /* OpenSSL 1.1.1 or later */

NOEXPORT void print_cipher(CLI *c) { /* print negotiated cipher */
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
    const SSL_CIPHER *cipher;
#else
    SSL_CIPHER *cipher;
#endif /* OpenSSL 1.1.1 or later */
#ifndef OPENSSL_NO_COMP
    const COMP_METHOD *compression, *expansion;
#endif

    if(c->opt->log_level<LOG_INFO) /* performance optimization */
        return;

#ifndef OPENSSL_NO_PSK
    if(c->flag.psk_found) {
        if(c->opt->option.client) {
            s_log(LOG_ERR, "INTERNAL ERROR: PSK found on a client");
        } else {
            s_log(LOG_INFO, "TLS accepted: PSK");
        }
    } else
#endif /* !defined(OPENSSL_NO_PSK) */
        s_log(LOG_INFO, "TLS %s: %s",
            c->opt->option.client ? "connected" : "accepted",
            SSL_session_reused(c->ssl) ?
                "previous session reused" : "new session negotiated");

    cipher=(SSL_CIPHER *)SSL_get_current_cipher(c->ssl);
    s_log(LOG_INFO, "%s ciphersuite: %s (%d-bit encryption)",
        SSL_get_version(c->ssl), SSL_CIPHER_get_name(cipher),
        SSL_CIPHER_get_bits(cipher, NULL));
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
    print_tmp_key(c->ssl);
#endif

#ifndef OPENSSL_NO_COMP
    compression=SSL_get_current_compression(c->ssl);
    expansion=SSL_get_current_expansion(c->ssl);
    s_log(compression||expansion ? LOG_INFO : LOG_DEBUG,
        "Compression: %s, expansion: %s",
        compression ? SSL_COMP_get_name(compression) : "null",
        expansion ? SSL_COMP_get_name(expansion) : "null");
#endif
}

#endif /* NO_OPENSSLOFF */

/****************************** transfer data */
NOEXPORT void transfer(CLI *c) {
    int timeout; /* s_poll_wait timeout in seconds */
    int pending; /* either processed on unprocessed TLS data */
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
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
        read_wants_read|=!(SSL_get_shutdown(c->ssl)&SSL_RECEIVED_SHUTDOWN)
            && c->ssl_ptr<BUFFSIZE && !read_wants_write;
        write_wants_write|=!(SSL_get_shutdown(c->ssl)&SSL_SENT_SHUTDOWN)
            && c->sock_ptr && !write_wants_read;

        /****************************** setup c->fds structure */
        s_poll_init(c->fds, 0); /* initialize the structure */
        /* for plain socket open data stream = open file descriptor */
        /* make sure to add each open socket to receive exceptions! */
        if(sock_open_rd) /* only poll if the read file descriptor is open */
            s_poll_add(c->fds, c->sock_rfd->fd, c->sock_ptr<BUFFSIZE, 0);
        if(sock_open_wr) /* only poll if the write file descriptor is open */
            s_poll_add(c->fds, c->sock_wfd->fd, 0, c->ssl_ptr>0);
        /* poll TLS file descriptors unless TLS shutdown was completed */
        if(SSL_get_shutdown(c->ssl)!=
                (SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN)) {
            s_poll_add(c->fds, c->ssl_rfd->fd,
                read_wants_read || write_wants_read || shutdown_wants_read, 0);
            s_poll_add(c->fds, c->ssl_wfd->fd, 0,
                read_wants_write || write_wants_write || shutdown_wants_write);
        }

        /****************************** wait for an event */
        pending=SSL_pending(c->ssl);
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
        /* only attempt to process SSL_has_pending() data once */
        prev_has_pending=has_pending;
        has_pending=SSL_has_pending(c->ssl);
        pending=pending || (has_pending && !prev_has_pending);
#endif
        if(read_wants_read && pending) {
            timeout=0; /* process any buffered data without delay */
        } else if((sock_open_rd && /* both peers open */
                !(SSL_get_shutdown(c->ssl)&SSL_RECEIVED_SHUTDOWN)) ||
                c->ssl_ptr /* data buffered to write to socket */ ||
                c->sock_ptr /* data buffered to write to TLS */) {
            timeout=c->opt->timeout_idle;
        } else {
            timeout=c->opt->timeout_close;
        }
        err=s_poll_wait(c->fds, timeout, 0);
        switch(err) {
        case -1:
            sockerror("transfer: s_poll_wait");
            throw_exception(c, 1);
        case 0: /* timeout */
            if(read_wants_read && pending)
                break;
            if((sock_open_rd &&
                    !(SSL_get_shutdown(c->ssl)&SSL_RECEIVED_SHUTDOWN)) ||
                    c->ssl_ptr || c->sock_ptr) {
                s_log(LOG_INFO, "transfer: s_poll_wait:"
                    " TIMEOUTidle exceeded: sending reset");
                s_poll_dump(c->fds, LOG_DEBUG);
                throw_exception(c, 1);
            }
            /* already closing connection */
            s_log(LOG_ERR, "transfer: s_poll_wait:"
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

        /****************************** hangups without read or write */
        if(!(sock_can_rd || sock_can_wr || ssl_can_rd || ssl_can_wr)) {
            if(s_poll_hup(c->fds, c->sock_wfd->fd)) {
                if(c->ssl_ptr) {
                    s_log(LOG_ERR,
                        "Write socket closed (HUP) with %ld unsent byte(s)",
                        (long)c->ssl_ptr);
                    throw_exception(c, 1); /* reset the sockets */
                }
                s_log(LOG_INFO, "Write socket closed (HUP)");
                sock_open_wr=0;
            }
            if(s_poll_hup(c->fds, c->sock_rfd->fd)) {
                s_log(LOG_INFO, "Read socket closed (HUP)");
                sock_open_rd=0;
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
                SSL_set_shutdown(c->ssl,
                    SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN);
            }
        }

        if(c->reneg_state==RENEG_DETECTED && !c->opt->option.renegotiation) {
            s_log(LOG_ERR, "Aborting due to renegotiation request");
            throw_exception(c, 1);
        }

        /****************************** send TLS close_notify alert */
        if(shutdown_wants_read || shutdown_wants_write) {
            int num=SSL_shutdown(c->ssl); /* send close_notify alert */
            if(num<0) /* -1 - not completed */
                err=SSL_get_error(c->ssl, num);
            else /* 0 or 1 - success */
                err=SSL_ERROR_NONE;
            switch(err) {
            case SSL_ERROR_NONE: /* the shutdown was successfully completed */
                s_log(LOG_INFO, "SSL_shutdown successfully sent close_notify alert");
                shutdown_wants_read=shutdown_wants_write=0;
                break;
            case SSL_ERROR_WANT_WRITE:
                s_log(LOG_DEBUG, "SSL_shutdown returned WANT_WRITE: retrying");
                shutdown_wants_read=0;
                shutdown_wants_write=1;
                break;
            case SSL_ERROR_WANT_READ:
                s_log(LOG_DEBUG, "SSL_shutdown returned WANT_READ: retrying");
                shutdown_wants_read=1;
                shutdown_wants_write=0;
                break;
            case SSL_ERROR_SSL: /* TLS error */
                ssl_error(c, "SSL_shutdown");
                throw_exception(c, 1);
            case SSL_ERROR_ZERO_RETURN: /* received a close_notify alert */
                SSL_set_shutdown(c->ssl, SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN);
                shutdown_wants_read=shutdown_wants_write=0;
                break;
            case SSL_ERROR_SYSCALL: /* socket error */
                if(socket_needs_retry(c, "transfer: SSL_shutdown"))
                    break; /* a non-critical error: retry */
                SSL_set_shutdown(c->ssl, SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN);
                shutdown_wants_read=shutdown_wants_write=0;
                break;
            default:
                s_log(LOG_ERR, "SSL_shutdown/SSL_get_error returned %d", err);
                throw_exception(c, 1);
            }
        }

        /****************************** write to socket */
        if(sock_open_wr && sock_can_wr) {
            ssize_t num=writesocket(c->sock_wfd->fd, c->ssl_buff, c->ssl_ptr);
            switch(num) {
            case -1: /* error */
                if(socket_needs_retry(c, "transfer: writesocket"))
                    break; /* a non-critical error: retry */
                sock_open_rd=sock_open_wr=0;
                break;
            case 0: /* nothing was written: ignore */
                s_log(LOG_DEBUG, "writesocket returned 0");
                break; /* do not reset the watchdog */
            default:
                memmove(c->ssl_buff, c->ssl_buff+num, c->ssl_ptr-(size_t)num);
                c->ssl_ptr-=(size_t)num;
                memset(c->ssl_buff+c->ssl_ptr, 0, (size_t)num); /* paranoia */
                c->sock_bytes+=(size_t)num;
                watchdog=0; /* reset the watchdog */
            }
        }

        /****************************** read from socket */
        if(sock_open_rd && sock_can_rd) {
            ssize_t num=readsocket(c->sock_rfd->fd,
                c->sock_buff+c->sock_ptr, BUFFSIZE-c->sock_ptr);
            switch(num) {
            case -1:
                if(socket_needs_retry(c, "transfer: readsocket"))
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
        read_wants_read|=!(SSL_get_shutdown(c->ssl)&SSL_RECEIVED_SHUTDOWN)
            && c->ssl_ptr<BUFFSIZE && !read_wants_write;
        write_wants_write|=!(SSL_get_shutdown(c->ssl)&SSL_SENT_SHUTDOWN)
            && c->sock_ptr && !write_wants_read;

        /****************************** write to TLS */
        if((write_wants_read && ssl_can_rd) ||
                (write_wants_write && ssl_can_wr)) {
            int num=SSL_write(c->ssl, c->sock_buff, (int)(c->sock_ptr));
            write_wants_read=0;
            write_wants_write=0;
            switch(err=SSL_get_error(c->ssl, num)) {
            case SSL_ERROR_NONE:
                if(num==0) { /* nothing was written: ignore */
                    s_log(LOG_DEBUG, "SSL_write returned 0");
                } else {
                    memmove(c->sock_buff, c->sock_buff+num,
                        c->sock_ptr-(size_t)num);
                    c->sock_ptr-=(size_t)num;
                    memset(c->sock_buff+c->sock_ptr, 0, (size_t)num); /* PPD */
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
                if(socket_needs_retry(c, "transfer: SSL_write") && num)
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
                SSL_set_shutdown(c->ssl, SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN);
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
            int num=SSL_read(c->ssl, c->ssl_buff+c->ssl_ptr, (int)(BUFFSIZE-c->ssl_ptr));
            read_wants_read=0;
            read_wants_write=0;
            switch(err=SSL_get_error(c->ssl, num)) {
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
                    SSL_set_shutdown(c->ssl,
                        SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN);
                    break;
                }
#endif /* SSL_R_UNEXPECTED_EOF_WHILE_READING */
                ssl_error(c, "SSL_read");
                throw_exception(c, 1);
            case SSL_ERROR_ZERO_RETURN: /* received a close_notify alert */
                s_log(LOG_INFO, "TLS closed (SSL_read)");
                if(SSL_version(c->ssl)==SSL2_VERSION)
                    SSL_set_shutdown(c->ssl,
                        SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN);
                break;
            case SSL_ERROR_SYSCALL:
                if(socket_needs_retry(c, "transfer: SSL_read") && num)
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
                SSL_set_shutdown(c->ssl,
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
        if(sock_open_rd && s_poll_rdhup(c->fds, c->sock_rfd->fd) &&
                (ioctlsocket(c->sock_rfd->fd, FIONREAD, &bytes) || !bytes)) {
            s_log(LOG_INFO, "Read socket closed (read hangup)");
            sock_open_rd=0;
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
        if(!(SSL_get_shutdown(c->ssl)&SSL_RECEIVED_SHUTDOWN) &&
                s_poll_rdhup(c->fds, c->ssl_rfd->fd) &&
                (ioctlsocket(c->ssl_rfd->fd, FIONREAD, &bytes) || !bytes)) {
            /* hangup -> buggy (e.g. Microsoft) peer:
             * TLS socket closed without close_notify alert */
            s_log(LOG_INFO, "TLS socket closed (read hangup)");
            SSL_set_shutdown(c->ssl,
                SSL_get_shutdown(c->ssl)|SSL_RECEIVED_SHUTDOWN);
        }
        if(!(SSL_get_shutdown(c->ssl)&SSL_SENT_SHUTDOWN) &&
                s_poll_hup(c->fds, c->ssl_wfd->fd)) {
            if(c->sock_ptr || write_wants_write) {
                s_log(LOG_ERR,
                    "TLS socket closed (write hangup) with %ld unsent byte(s)",
                    (long)c->sock_ptr);
                throw_exception(c, 1); /* reset the sockets */
            }
            s_log(LOG_INFO, "TLS socket closed (write hangup)");
            SSL_set_shutdown(c->ssl,
                SSL_get_shutdown(c->ssl)|SSL_SENT_SHUTDOWN);
        }

        /****************************** check write shutdown conditions */
        if(sock_open_wr && SSL_get_shutdown(c->ssl)&SSL_RECEIVED_SHUTDOWN &&
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
        if(!(SSL_get_shutdown(c->ssl)&SSL_SENT_SHUTDOWN) && !sock_open_rd &&
                !c->sock_ptr && !write_wants_write) {
            if(SSL_version(c->ssl)!=SSL2_VERSION) {
                s_log(LOG_DEBUG, "Sending close_notify alert");
                shutdown_wants_write=1;
            } else { /* no alerts in SSLv2, including the close_notify alert */
                s_log(LOG_DEBUG, "Closing SSLv2 socket");
                if(c->ssl_rfd->is_socket)
                    shutdown(c->ssl_rfd->fd, SHUT_RD); /* notify the kernel */
                if(c->ssl_wfd->is_socket)
                    shutdown(c->ssl_wfd->fd, SHUT_WR); /* send TCP FIN */
                /* notify the OpenSSL library */
                SSL_set_shutdown(c->ssl, SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN);
            }
        }

        /****************************** check watchdog */
        if(++watchdog>100) { /* loop executes without transferring any data */
            s_log(LOG_ERR,
                "transfer() loop executes not transferring any data");
            s_log(LOG_ERR,
                "please report the problem to Michal.Trojnara@stunnel.org");
            stunnel_info(LOG_ERR);
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
            s_log(LOG_ERR, "protocol=%s, SSL_pending=%d, SSL_has_pending=%d",
                SSL_get_version(c->ssl),
                SSL_pending(c->ssl), SSL_has_pending(c->ssl));
#else
            s_log(LOG_ERR, "protocol=%s, SSL_pending=%d",
                SSL_get_version(c->ssl), SSL_pending(c->ssl));
#endif
            s_log(LOG_ERR, "sock_open_rd=%s, sock_open_wr=%s",
                sock_open_rd ? "Y" : "n", sock_open_wr ? "Y" : "n");
            s_log(LOG_ERR, "SSL_RECEIVED_SHUTDOWN=%s, SSL_SENT_SHUTDOWN=%s",
                (SSL_get_shutdown(c->ssl) & SSL_RECEIVED_SHUTDOWN) ? "Y" : "n",
                (SSL_get_shutdown(c->ssl) & SSL_SENT_SHUTDOWN) ? "Y" : "n");
            s_log(LOG_ERR, "sock_can_rd=%s, sock_can_wr=%s",
                sock_can_rd ? "Y" : "n", sock_can_wr ? "Y" : "n");
            s_log(LOG_ERR, "ssl_can_rd=%s, ssl_can_wr=%s",
                ssl_can_rd ? "Y" : "n", ssl_can_wr ? "Y" : "n");
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
            throw_exception(c, 1);
        }

    } while(sock_open_wr || !(SSL_get_shutdown(c->ssl)&SSL_SENT_SHUTDOWN) ||
        shutdown_wants_read || shutdown_wants_write);
}

NOEXPORT void auth_user(CLI *c) {
#ifndef _WIN32_WCE
    struct servent *s_ent;    /* structure for getservbyname */
#endif
    SOCKADDR_UNION ident;     /* IDENT socket name */
    char *line, *type, *system, *user;
    unsigned remote_port, local_port;

    if(!c->opt->username)
        return; /* -u option not specified */
#ifdef HAVE_STRUCT_SOCKADDR_UN
    if(c->peer_addr.sa.sa_family==AF_UNIX) {
        s_log(LOG_INFO, "IDENT not supported on Unix sockets");
        return;
    }
#endif
    c->fd=s_socket(c->peer_addr.sa.sa_family, SOCK_STREAM,
        0, 1, "socket (auth_user)");
    if(c->fd==INVALID_SOCKET)
        throw_exception(c, 1);
    memcpy(&ident, &c->peer_addr, (size_t)c->peer_addr_len);
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
    if(s_connect(c, &ident, addr_len(&ident), c->opt->timeout_connect))
        throw_exception(c, 1);
    s_log(LOG_DEBUG, "IDENT server connected");
    remote_port=ntohs(c->peer_addr.in.sin_port);
    local_port=(unsigned)(c->opt->local_addr.addr ?
        ntohs(c->opt->local_addr.addr[0].in.sin_port) : 0);
    fd_printf(c, c->fd, "%u , %u", remote_port, local_port);
    line=fd_getline(c, c->fd);
    closesocket(c->fd);
    c->fd=INVALID_SOCKET; /* avoid double close on cleanup */
    type=strchr(line, ':');
    if(!type) {
        s_log(LOG_ERR, "Malformed IDENT response");
        str_free(line);
        throw_exception(c, 1);
    }
    *type++='\0';
    system=strchr(type, ':');
    if(!system) {
        s_log(LOG_ERR, "Malformed IDENT response");
        str_free(line);
        throw_exception(c, 1);
    }
    *system++='\0';
    if(strcmp(type, " USERID ")) {
        s_log(LOG_ERR, "Incorrect IDENT response type");
        str_free(line);
        throw_exception(c, 1);
    }
    user=strchr(system, ':');
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

#ifdef MSSPISSL
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

#ifdef MSSPISSL
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
#endif

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
#endif

NOEXPORT SOCKET connect_local(CLI *c) { /* spawn local process */
    SOCKET fd[2];
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    LPTSTR name, args;

#ifdef MSSPISSL
if( c->is_exec == 0 )
{
#endif
    if(make_sockets(fd))
        throw_exception(c, 1);
#ifdef MSSPISSL
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
#endif
    memset(&si, 0, sizeof si);
    si.cb=sizeof si;
    si.dwFlags=STARTF_USESHOWWINDOW|STARTF_USESTDHANDLES;
    si.wShowWindow=SW_HIDE;
    si.hStdInput=si.hStdOutput=si.hStdError=(HANDLE)fd[1];
    memset(&pi, 0, sizeof pi);

    name=str2tstr(c->opt->exec_name);
    args=str2tstr(c->opt->exec_args);
#ifdef MSSPISSL
    {
        char ** env = env_alloc( c );
        char ** p;
        char * winenv = NULL;
        size_t winlen = 0;
        size_t shift = winlen;

        for( p = env; *p; ++p )
        {
            size_t plen = strlen( *p ) + 1;
            winlen += plen;
            winenv = str_realloc( winenv, winlen + 1 );
            memcpy( winenv + shift, *p, plen );
            shift = winlen;
        }
        winenv[shift] = 0;

        CreateProcess( name, args, NULL, NULL, TRUE, 0, winenv, NULL, &si, &pi );

        env_free( env );
        str_free( winenv );
    }
#else
    CreateProcess(name, args, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
#endif
    str_free(name);
    str_free(args);

    closesocket(fd[1]);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
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

#ifdef MSSPISSL
if( c->is_exec == 0 )
{
#endif
    if(c->opt->option.pty) {
        char tty[64];

        if(pty_allocate(fd, fd+1, tty))
            throw_exception(c, 1);
        s_log(LOG_DEBUG, "TTY=%s allocated", tty);
    } else
        if(make_sockets(fd))
            throw_exception(c, 1);
    set_nonblock(fd[1], 0); /* switch back to the blocking mode */
#ifdef MSSPISSL
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
#endif

    env=env_alloc(c);
    pid=fork();
    c->pid=(unsigned long)pid;
    switch(pid) {
    case -1:    /* error */
        closesocket(fd[0]);
        closesocket(fd[1]);
        env_free(env);
        ioerror("fork");
        throw_exception(c, 1);
    case  0:    /* child */
        /* the child is not allowed to play with thread-local storage */
        /* see http://linux.die.net/man/3/pthread_atfork for details */
        closesocket(fd[0]);
        /* dup2() does not copy FD_CLOEXEC flag */
        dup2(fd[1], 0);
        dup2(fd[1], 1);
        if(!c->opt->option.log_stderr)
            dup2(fd[1], 2);
        closesocket(fd[1]); /* not really needed due to FD_CLOEXEC */
#ifdef HAVE_PTHREAD_SIGMASK
        sigemptyset(&newmask);
        sigprocmask(SIG_SETMASK, &newmask, NULL);
#endif
        signal(SIGCHLD, SIG_DFL);
        signal(SIGHUP, SIG_DFL);
        signal(SIGUSR1, SIG_DFL);
        signal(SIGUSR2, SIG_DFL);
        signal(SIGPIPE, SIG_DFL);
        signal(SIGTERM, SIG_DFL);
        signal(SIGQUIT, SIG_DFL);
        signal(SIGINT, SIG_DFL);
        execve(c->opt->exec_name, c->opt->exec_args, env);
        _exit(1); /* failed, but there is no way to report an error here */
    default: /* parent */
        closesocket(fd[1]);
        env_free(env);
        s_log(LOG_INFO, "Local mode child started (PID=%lu)", c->pid);
        return fd[0];
    }
}

char **env_alloc(CLI *c) {
    extern char **environ;
    char **env=NULL, **p;
    unsigned n=0; /* (n+2) keeps the list NULL-terminated */
    char *name, host[40], port[6];
    X509 *peer_cert;

    if(!getnameinfo(&c->peer_addr.sa, c->peer_addr_len,
            host, 40, port, 6, NI_NUMERICHOST|NI_NUMERICSERV)) {
        /* just don't set these variables if getnameinfo() fails */
        env=str_realloc(env, (n+2)*sizeof(char *));
        env[n++]=str_printf("REMOTE_HOST=%s", host);
        env=str_realloc(env, (n+2)*sizeof(char *));
        env[n++]=str_printf("REMOTE_PORT=%s", port);
        if(c->opt->option.transparent_src) {
#ifndef LIBDIR
#define LIBDIR "."
#endif
#ifdef MACH64
            env=str_realloc(env, (n+2)*sizeof(char *));
            env[n++]=str_dup("LD_PRELOAD_32=" LIBDIR "/libstunnel.so");
            env=str_realloc(env, (n+2)*sizeof(char *));
            env[n++]=str_dup("LD_PRELOAD_64=" LIBDIR "/" MACH64 "/libstunnel.so");
#elif defined(__osf) || defined(__osf__)
            /* for Tru64 _RLD_LIST is used instead */
            env=str_realloc(env, (n+2)*sizeof(char *));
            env[n++]=str_dup("_RLD_LIST=" LIBDIR "/libstunnel.so:DEFAULT");
#else
            env=str_realloc(env, (n+2)*sizeof(char *));
            env[n++]=str_dup("LD_PRELOAD=" LIBDIR "/libstunnel.so");
#endif
        }
    }

#ifdef MSSPISSL
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
#endif

#ifdef NO_OPENSSLOFF
    if(c->ssl) {
        peer_cert=SSL_get_peer_certificate(c->ssl);
        if(peer_cert) {
            name=X509_NAME2text(X509_get_subject_name(peer_cert));
            env=str_realloc(env, (n+2)*sizeof(char *));
            env[n++]=str_printf("SSL_CLIENT_DN=%s", name);
            str_free(name);
            name=X509_NAME2text(X509_get_issuer_name(peer_cert));
            env=str_realloc(env, (n+2)*sizeof(char *));
            env[n++]=str_printf("SSL_CLIENT_I_DN=%s", name);
            str_free(name);
            X509_free(peer_cert);
        }
    }
#endif /* NO_OPENSSLOFF */

    for(p=environ; *p; ++p) {
        env=str_realloc(env, (n+2)*sizeof(char *));
        env[n++]=str_dup(*p);
    }

    return env;
}

void env_free(char **env) {
    char **p;

    for(p=env; *p; ++p)
        str_free(*p);
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
        if(!connect_init(c, c->connect_addr.addr[c->idx].sa.sa_family) &&
                !s_connect(c, &c->connect_addr.addr[c->idx],
                    addr_len(&c->connect_addr.addr[c->idx]),
                    c->opt->timeout_connect)) {
#ifdef NO_OPENSSLOFF
            if(c->ssl) {
                SSL_SESSION *sess=SSL_get1_session(c->ssl);
                if(sess) {
                    idx_cache_save(sess, &c->connect_addr.addr[c->idx]);
                    SSL_SESSION_free(sess);
                }
            }
#endif /* NO_OPENSSLOFF */
            print_bound_address(c);
            fd=c->fd;
            c->fd=INVALID_SOCKET;
            return fd; /* success! */
        }
        if(c->fd!=INVALID_SOCKET) {
            closesocket(c->fd);
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
    len=addr_len(cur_addr);
    new_addr=str_alloc_detached((size_t)len);
    memcpy(new_addr, cur_addr, (size_t)len);

    addr_txt=s_ntop(cur_addr, len);
    s_log(LOG_INFO, "persistence: %s cached", addr_txt);
    str_free(addr_txt);

#ifdef NO_OPENSSLOFF
    CRYPTO_THREAD_write_lock(stunnel_locks[LOCK_ADDR]);
    old_addr=SSL_SESSION_get_ex_data(sess, index_session_connect_address);
    ok=SSL_SESSION_set_ex_data(sess, index_session_connect_address, new_addr);
    CRYPTO_THREAD_unlock(stunnel_locks[LOCK_ADDR]);
    if(ok) {
        str_free(old_addr); /* NULL pointers are ignored */
    } else { /* failed to store new_addr -> remove it */
        ssl_error(NULL, "SSL_SESSION_set_ex_data");
        str_free(new_addr); /* NULL pointers are ignored */
    }
#endif /* NO_OPENSSLOFF */
}

NOEXPORT unsigned idx_cache_retrieve(CLI *c) {
    unsigned i;
    SOCKADDR_UNION addr, *ptr;
    socklen_t len;
    char *addr_txt;

#ifdef NO_OPENSSLOFF
    if(c->ssl && SSL_session_reused(c->ssl)) {
        SSL_SESSION *sess=SSL_get1_session(c->ssl);
        if(sess) {
            CRYPTO_THREAD_read_lock(stunnel_locks[LOCK_ADDR]);
            ptr=SSL_SESSION_get_ex_data(sess, index_session_connect_address);
            if(ptr) {
                len=addr_len(ptr);
                memcpy(&addr, ptr, (size_t)len);
                CRYPTO_THREAD_unlock(stunnel_locks[LOCK_ADDR]);
                SSL_SESSION_free(sess);
                /* address was copied, ptr itself is no longer valid */
                for(i=0; i<c->connect_addr.num; ++i) {
                    if(addr_len(&c->connect_addr.addr[i])==len &&
                            !memcmp(&c->connect_addr.addr[i],
                                &addr, (size_t)len)) {
                        addr_txt=s_ntop(&addr, len);
                        s_log(LOG_INFO, "persistence: %s reused", addr_txt);
                        str_free(addr_txt);
                        return i;
                    }
                }
                addr_txt=s_ntop(&addr, len);
                s_log(LOG_INFO, "persistence: %s not available", addr_txt);
                str_free(addr_txt);
            } else {
                CRYPTO_THREAD_unlock(stunnel_locks[LOCK_ADDR]);
                SSL_SESSION_free(sess);
                s_log(LOG_NOTICE, "persistence: No cached address found");
            }
        }
    }
#endif /* NO_OPENSSLOFF */

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
        addrlist_dup(&c->connect_addr, &c->opt->redirect_addr);
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
    addrlist_dup(&c->connect_addr, &c->opt->connect_addr);
}

NOEXPORT int connect_init(CLI *c, int domain) {
    SOCKADDR_UNION bind_addr;

    if(c->bind_addr) {
        /* setup bind_addr based on c->bind_addr */
        memcpy(&bind_addr, c->bind_addr, (size_t)addr_len(c->bind_addr));
        /* perform the initial sanity checks before creating a socket */
        if(bind_addr.sa.sa_family!=domain) {
            s_log(LOG_DEBUG, "Cannot assign an AF=%d address an AF=%d socket",
                bind_addr.sa.sa_family, domain);
            return 1; /* failure */
        }
    } else {
        /* only needed to avoid a warning in MSVC */
        memset(&bind_addr, 0, sizeof bind_addr);
    }

    /* create a new socket */
    c->fd=s_socket(domain, SOCK_STREAM, 0, 1, "remote socket");
    if(c->fd==INVALID_SOCKET)
        return 1; /* failure */
    if(!c->bind_addr)
        return 0; /* success */

    /* enable non-local bind if needed (and supported) */
#ifndef USE_WIN32
    if(c->opt->option.transparent_src) {
#if defined(__linux__)
        /* non-local bind on Linux */
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
        /* non-local bind on FreeBSD */
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
    if(ntohs(bind_addr.in.sin_port)>=1024) { /* security check */
        /* this is currently only possible with transparent_src */
        if(!bind(c->fd, &bind_addr.sa, addr_len(&bind_addr))) {
            s_log(LOG_INFO, "bind succeeded on the original port");
            return 0; /* success */
        }
        if(get_last_socket_error()!=S_EADDRINUSE) {
            sockerror("bind (original port)");
            return 1; /* failure */
        }
    }
    bind_addr.in.sin_port=htons(0); /* retry with ephemeral port */
    if(!bind(c->fd, &bind_addr.sa, addr_len(&bind_addr))) {
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
#ifdef NO_OPENSSLOFF
    if(!c->ssl)
        return 1; /* TLS not established -> always redirect */
    sess=SSL_get1_session(c->ssl);
    if(!sess)
        return 1; /* no TLS session -> always redirect */
    ex_data=SSL_SESSION_get_ex_data(sess, index_session_authenticated);
    SSL_SESSION_free(sess);
    return ex_data == NULL;
#else /* NO_OPENSSLOFF */
    return 1;
#endif /* NO_OPENSSLOFF */
}

NOEXPORT void print_bound_address(CLI *c) {
    char *txt;
    SOCKADDR_UNION addr;
    socklen_t addrlen=sizeof addr;

    if(c->opt->log_level<LOG_NOTICE) /* performance optimization */
        return;
    memset(&addr, 0, (size_t)addrlen);
    if(getsockname(c->fd, (struct sockaddr *)&addr, &addrlen)) {
        sockerror("getsockname");
        return;
    }
    txt=s_ntop(&addr, addrlen);
    s_log(LOG_NOTICE,"Service [%s] connected remote server from %s",
        c->opt->servname, txt);
    str_free(txt);

#ifdef MSSPISSL
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
#endif
}

/* set lingering on a socket */
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
