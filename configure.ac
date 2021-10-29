# CPRO:
# If AC_CONFIG_HEADERS enabled, we dont want install autoconf-archive or pkg-config, but
# then autoconf say: "error: possibly undefined macro: AC_MSG_NOTICE".
# Workaround to fix this issuer:
# m4_pattern_allow([^AC_MSG_])
# m4_pattern_allow([^AC_DEFINE])

# Process this file with autoconf to produce a configure script.

AC_INIT([stunnel],[5.60])
AC_MSG_NOTICE([**************************************** initialization])
AC_CONFIG_AUX_DIR(auto)
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([src/config.h])
AC_CONFIG_SRCDIR([src/stunnel.c])
AM_INIT_AUTOMAKE([subdir-objects foreign])

AC_CANONICAL_HOST
AC_SUBST([host])
AC_DEFINE_UNQUOTED([HOST], ["$host"], [Host description])
define([esc], [`echo ]$1[ | tr abcdefghijklmnopqrstuvwxyz.- ABCDEFGHIJKLMNOPQRSTUVWXYZ__ | tr -dc ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_`])
AC_DEFINE_UNQUOTED(esc(CPU_$host_cpu))
AC_DEFINE_UNQUOTED(esc(VENDOR_$host_vendor))
AC_DEFINE_UNQUOTED(esc(OS_$host_os))

case "$host_os" in
*darwin*)
    # OSX does not declare ucontext without _XOPEN_SOURCE
    AC_DEFINE([_XOPEN_SOURCE], [500], [Use X/Open 5 with POSIX 1995])
    # OSX does not declare chroot() without _DARWIN_C_SOURCE
    AC_DEFINE([_DARWIN_C_SOURCE], [1], [Use Darwin source])
    ;;
*)
    AC_DEFINE([_GNU_SOURCE], [1], [Use GNU source])
    ;;
esac

# for AIX we need c99 option for compile 
AC_PROG_CC_C99
AC_PROG_CXX
AM_PROG_CC_C_O
AC_PROG_INSTALL
AC_PROG_MAKE_SET
AC_SUBST(CXXLD,$CXX)
AC_ARG_ENABLE(64, AS_HELP_STRING([--enable-64],[Enable compiling for 64-bit platforms]), stunnel_enable_64=$enableval)
AC_ARG_ENABLE(release, AS_HELP_STRING([--enable-release],[Enable optimization and stuff]), stunnel_enable_release=$enableval)
AC_ARG_ENABLE(ios, AS_HELP_STRING([--enable-ios],[Enable ios compile]), stunnel_enable_ios=$enableval)
AC_ARG_ENABLE(baikal, AS_HELP_STRING([--enable-baikal],[Enable baikal compile]), stunnel_enable_baikal=$enableval)
AC_ARG_ENABLE(uclibc, AS_HELP_STRING([--enable-uclibc],[Enable uclibc compile]), stunnel_enable_uclibc=$enableval)
AC_ARG_ENABLE(ios-emul, AS_HELP_STRING([--enable-ios-emul],[Enable ios emulator compile]), stunnel_enable_ios_emul=$enableval)
AC_ARG_ENABLE(arm, AS_HELP_STRING([--enable-arm],[Enable arm compile]), stunnel_enable_arm=$enableval)
AC_ARG_ENABLE(arm64, AS_HELP_STRING([--enable-arm64],[Enable arm64 compile]), stunnel_enable_arm64=$enableval)
AC_ARG_ENABLE(armel, AS_HELP_STRING([--enable-armel],[Enable armel compile]), stunnel_enable_armel=$enableval)
AC_ARG_ENABLE(cross-powerpcle, AS_HELP_STRING([--enable-cross-powerpcle],[Enable cross powerpcle compile]), stunnel_enable_cross_ppcle=$enableval)
AC_ARG_ENABLE(sailfish, AS_HELP_STRING([--enable-sailfish],[Enable sailfish os]), stunnel_enable_sailfish=$enableval)
AC_ARG_ENABLE(sailfish-emul, AS_HELP_STRING([--enable-sailfish-emul],[Enable sailfish os emulator]), stunnel_enable_sailfish_emul=$enableval)
AC_ARG_WITH(bindir64, AS_HELP_STRING([--with-bindir64],[Define directory for 64 bit binaries.]), [bindir64=$withval])

dnl -fsanitize=address|thread|undefined -- контроль корректности выполнения
dnl Проверку корректности задания флагов доверяю пользователю и компилятору
dnl документация есть в gcc, clang и google
AC_ARG_ENABLE(asan, AS_HELP_STRING([INTERNAL: --enable-asan], [configure build with or without -fsanitize=address. You must read comment in configure.ac]), stunnel_enable_asan=$enableval)
AC_ARG_ENABLE(tsan, AS_HELP_STRING([INTERNAL: --enable-tsan], [configure build with or without -fsanitize=thread. You must read comment in configure.ac]), stunnel_enable_tsan=$enableval)
AC_ARG_ENABLE(ubsan, AS_HELP_STRING([INTERNAL: --enable-ubsan], [configure build with or without -fsanitize=undefined. You must read comment in configure.ac]), stunnel_enable_ubsan=$enableval)

if test "$GCC" = "yes";
then
  CFLAGS="$CFLAGS -Wall -Wcast-align -Wpointer-arith"
  CFLAGS="$CFLAGS -Wformat -Wformat-security -Wconversion"
  CFLAGS="$CFLAGS -Wno-long-long -Wno-deprecated-declarations -fPIE"

  if test "x$stunnel_enable_asan" == "xyes"; then
    CFLAGS="$CFLAGS -fsanitize=address"
    CXXFLAGS="$CXXFLAGS -fsanitize=address"
  fi

  if test "x$stunnel_enable_tsan" == "xyes"; then
    CFLAGS="$CFLAGS -fsanitize=thread"
    CXXFLAGS="$CXXFLAGS -fsanitize=thread"
  fi

  if test "x$stunnel_enable_ubsan" == "xyes"; then
    CFLAGS="$CFLAGS -fsanitize=undefined"
    CXXFLAGS="$CXXFLAGS -fsanitize=undefined"
  fi

  AC_CACHE_CHECK([whether -fstack-protector-all is supported],
    [check_cv_fstack_protector],
    [check_save_CFLAGS="$CFLAGS"
    CFLAGS="$CFLAGS -fstack-protector-all"
    AC_COMPILE_IFELSE(
      [AC_LANG_PROGRAM([[]], [[]])],
      [check_cv_fstack_protector=yes],
      [check_cv_fstack_protector=no])
    CFLAGS="$check_save_CFLAGS"
    ])
  if test "$check_cv_fstack_protector" = yes; then
    CFLAGS="$CFLAGS -fstack-protector-all"
  fi
  AC_CACHE_CHECK([whether -Werror=format-security is supported],
    [check_cv_werror_format_security],
    [check_save_CFLAGS="$CFLAGS"
    CFLAGS="$CFLAGS -Werror=format-security"
    AC_COMPILE_IFELSE(
      [AC_LANG_PROGRAM([[]], [[]])],
      [check_cv_werror_format_security=yes],
      [check_cv_werror_format_security=no])
    CFLAGS="$check_save_CFLAGS"
    ])
  if test "$check_cv_werror_format_security" = yes; then
    CFLAGS="$CFLAGS -Werror=format-security"
  fi
  AC_CACHE_CHECK([whether -Wextra is supported],
    [check_cv_wextra],
    [check_save_CFLAGS="$CFLAGS"
    CFLAGS="$CFLAGS -Wextra"
    AC_COMPILE_IFELSE(
      [AC_LANG_PROGRAM([[]], [[]])],
      [check_cv_wextra=yes],
      [check_cv_wextra=no])
    CFLAGS="$check_save_CFLAGS"
    ])
  if test "$check_cv_wextra" = yes; then
    CFLAGS="$CFLAGS -Wextra"
  fi
  CXXFLAGS="$CFLAGS"
  CFLAGS_WERROR="-Werror"
  if test "x$stunnel_enable_arm" == xyes; then
    CFLAGS+=" -Wno-unused-result -DPROC_TYPE_ARM=6 -DPROCESSOR_TYPE=6"
  fi
  if test "$host_cpu" = "powerpc64" -o "$host_cpu" = "powerpc64le";then
    CFLAGS+=" -Wno-unused-result -DPROC_TYPE_PPC64=5 -DPROCESSOR_TYPE=5"
  fi
  if test "$host_cpu" = "aarch64";then
    CFLAGS+=" -Wno-unused-result -DPROC_TYPE_ARM64=7 -DPROCESSOR_TYPE=7"
  fi  
  if test "$host_cpu" = "mipsel"; then
    proc_mips=yes
    CFLAGS+=" -Wno-unused-result -DPROC_TYPE_MIPS32=8 -DPROCESSOR_TYPE=8"
  fi
  if test "$host_cpu" = "e2k";then
        if test "$stunnel_enable_64" = "yes"; then
            CFLAGS+=" -Wno-unused-result -DPROC_TYPE_E2K64=10 -DPROCESSOR_TYPE=10"
        else  
            CFLAGS+=" -Wno-unused-result -DPROC_TYPE_E2K32=9 -DPROCESSOR_TYPE=9"
        fi    
  fi      
fi
AM_CONDITIONAL(CSP_64, test x$stunnel_enable_64 = xyes)
AM_CONDITIONAL(PROC_MIPS,test -n "$proc_mips")
AM_CONDITIONAL(CROSS_PPCLE,test x$stunnel_enable_cross_ppcle = xyes)
AM_CONDITIONAL(SAILFISH,test x$stunnel_enable_sailfish = xyes || test x$stunnel_enable_sailfish_emul = xyes)
AM_CONDITIONAL(ARM64, test x$stunnel_enable_arm64 = xyes)
AM_CONDITIONAL(ARMEL, test x$stunnel_enable_armel = xyes)
AM_CONDITIONAL(E2K, test x$host_cpu = xe2k)
if test "x$stunnel_enable_release" = "xyes";then
    case "$host_os" in
    solaris*)
        CFLAGS="$CFLAGS -xO3"
        CXXFLAGS="$CXXFLAGS -xO3";;
    *)
        CFLAGS="$CFLAGS -O3"
        CXXFLAGS="$CXXFLAGS -O3";;
    esac
else 
    case "$host_os" in
    solaris*)
        CFLAGS="$CFLAGS -g -xO0"
        CXXFLAGS="$CXXFLAGS -g -xO0";;
    *)
        CFLAGS="$CFLAGS -g -O0"
        CXXFLAGS="$CXXFLAGS -g -O0"
    if test x$stunnel_enable_ios = xyes || 
       test x$stunnel_enable_ios_emul = xyes
    then
        CFLAGS="$CFLAGS -gdwarf-2"
        CXXFLAGS="$CXXFLAGS -gdwarf-2"
    fi;;    
    esac
fi
PTHREAD_LIBS="-lpthread"
case "$host_os" in
linux*)
  AC_DEFINE(UNIX,1,[UNIX])
  if test "x$stunnel_enable_uclibc" != "xyes"
  then
      AC_DEFINE(LINUX,1,[LINUX])
      AM_CONDITIONAL(LINUX,true)
      AM_CONDITIONAL(UCLIBC,false)
  else
      AC_DEFINE(UCLIBC,1,[UCLIBC])
      AM_CONDITIONAL(LINUX,false)
      AM_CONDITIONAL(UCLIBC,true)
  fi
  AM_CONDITIONAL(FREEBSD,false)
  AM_CONDITIONAL(SOLARIS,false)
  AM_CONDITIONAL(DARWIN,false)
  AM_CONDITIONAL(AIX,false)
  AM_CONDITIONAL(IOS,false)
  LDFLAGS="${LDFLAGS} -fPIE -pie -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack"
  CXX_LDFLAGS="${CXX_LDFLAGS} -fPIE -pie -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack"
  if ! test "x$stunnel_enable_64" = "xyes"; then
      ld_minor_ver=`ls /lib/ld-2*.so|cut -d. -f2`
  else
      ld_minor_ver=`ls /lib64/ld-2*.so|cut -d. -f2`
  fi
  case $ld_minor_ver in
      5) LDFLAGS="${LDFLAGS} -Wl,--hash-style=sysv"
         CXX_LDFLAGS="${CXX_LDFLAGS} -Wl,--hash-style=sysv";;
  esac
  ;;
solaris*)
    AC_DEFINE(UNIX,1,[UNIX])
    AC_DEFINE(SOLARIS,1,[Solaris])
    AM_CONDITIONAL(LINUX,false)
    AM_CONDITIONAL(UCLIBC,false)
    AM_CONDITIONAL(FREEBSD,false)
    AM_CONDITIONAL(SOLARIS,true)
    AM_CONDITIONAL(DARWIN,false)
    AM_CONDITIONAL(AIX,false)
    AM_CONDITIONAL(IOS,false)

    PTHREAD_LIBS="-lpthread -lrt"
    cc_version=`$CC -V 2>&1|head -1|awk '{print $4}'`
    if test `uname -p` != i386; then
      if test "x$stunnel_enable_64" = "xyes"; then
	case $cc_version in
	5.9)	CXXFLAGS="$CXXFLAGS -m64 -xarch=sparc"
		CFLAGS="$CFLAGS -m64 -xarch=sparc"
		CPPFLAGS="$CPPFLAGS -m64 -xarch=sparc";;
        *)	CXXFLAGS="$CXXFLAGS -m64 -xarch=sparc"
		CFLAGS="$CFLAGS -m64 -xarch=sparc"
		CPPFLAGS="$CPPFLAGS -m64 -xarch=sparc";;
	esac
        AC_SUBST(CXXLD, "$CXX -XCClinker -m64 -xarch=sparc")
	LIBM=/lib/sparcv9/libm.so.1
      else
	case $cc_version in
	5.9)	CXXFLAGS="$CXXFLAGS -m32 -xarch=sparc"
		CFLAGS="$CFLAGS -m32 -xarch=sparc"
		CPPFLAGS="$CPPFLAGS -m32 -xarch=sparc";;
	esac
	LIBM=/lib/libm.so.1
      fi
    else
      if test "x$stunnel_enable_64" = "xyes";then
       	case $cc_version in
	5.9)	CXXFLAGS="$CXXFLAGS -m64 -xarch=generic"
		CFLAGS="$CFLAGS -m64 -xarch=generic"
		CPPFLAGS="$CPPFLAGS -m64 -xarch=generic"
		AC_SUBST(CXXLD, "$CXX -XCClinker -m64") ;;
        *)	CXXFLAGS="$CXXFLAGS -m64 -xarch=generic"
		CPPFLAGS="$CPPFLAGS -m64 -xarch=generic"
		CFLAGS="$CFLAGS -m64 -xarch=generic" 
		AC_SUBST(CXXLD, "$CXX -XCClinker -m64 -xarch=generic") ;;
	esac

	 LIBM=/lib/amd64/libm.so.1
      else
	 LIBM=/lib/libm.so.1
      fi
  fi
  AC_SUBST(LIBM);;
freebsd*)
  AC_DEFINE(UNIX,1,[UNIX])
  AM_CONDITIONAL(LINUX,false)
  AM_CONDITIONAL(UCLIBC,false)
  AM_CONDITIONAL(FREEBSD,true)
  AM_CONDITIONAL(SOLARIS,false)
  AM_CONDITIONAL(AIX,false)
  AM_CONDITIONAL(DARWIN,false)
  AM_CONDITIONAL(IOS,false)
  AC_DEFINE(FREEBSD,1,[Вещи, уникальные для FreBSD]);;
darwin*)
  AC_DEFINE(UNIX,1,[UNIX])
  AM_CONDITIONAL(LINUX,false)
  AM_CONDITIONAL(UCLIBC,false)
  AM_CONDITIONAL(FREEBSD,false)
  AM_CONDITIONAL(SOLARIS,false)
  AM_CONDITIONAL(AIX,false)
  CFLAGS="$CFLAGS -Wno-deprecated-declarations"
  if      test "x$stunnel_enable_ios" != "xyes" && \
     test "x$stunnel_enable_ios_emul" != "xyes"
  then 
    CXXFLAGS="$CXXFLAGS -arch x86_64 -arch i386 -mmacosx-version-min=10.8"
    CFLAGS="$CFLAGS -arch x86_64 -arch i386 -mmacosx-version-min=10.8"
    AM_CONDITIONAL(DARWIN,true)
    AM_CONDITIONAL(IOS,false)
    AC_DEFINE(DARWIN,1,[Вещи, уникальные для DARWIN])
  else
    AM_CONDITIONAL(DARWIN,false)
    AM_CONDITIONAL(IOS,true)
    AC_DEFINE(IOS,1,[Вещи, уникальные для IOS])
    if test "x$stunnel_enable_ios_emul" = "xyes"
    then
	AC_DEFINE(IOS_EMUL,1, [Мы используем эмулятор IOS])
    fi
  fi ;;
aix*)
    AC_DEFINE(UNIX,1,[UNIX])
    AC_DEFINE(AIX,1,[AIX])
    AM_CONDITIONAL(LINUX,false)
    AM_CONDITIONAL(UCLIBC,false)
    AM_CONDITIONAL(FREEBSD,false)
    AM_CONDITIONAL(SOLARIS,false)
    AM_CONDITIONAL(AIX,true)
    AM_CONDITIONAL(DARWIN,false)
    AM_CONDITIONAL(IOS,false)
    LDFLAGS="-Wl,-brtl";;
esac
CFLAGS="$CFLAGS -D_FORTIFY_SOURCE=2"

AM_CONDITIONAL(IOS_EMUL, test x$stunnel_enable_ios_emul = xyes)


# silent build by default
ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AC_MSG_NOTICE([**************************************** thread model])
# thread detection should be done first, as it may change the CC variable

AC_ARG_WITH(threads,
[  --with-threads=model    select threading model (ucontext/pthread/fork)],
[
    case "$withval" in
        ucontext)
            AC_MSG_NOTICE([UCONTEXT mode selected])
            AC_DEFINE([USE_UCONTEXT], [1], [Define to 1 to select UCONTEXT mode])
            ;;
        pthread)
            AC_MSG_NOTICE([PTHREAD mode selected])
            LIBS="$PTHREAD_LIBS $LIBS"
            CFLAGS="$CFLAGS $PTHREAD_CFLAGS"
            AC_DEFINE([USE_PTHREAD], [1], [Define to 1 to select PTHREAD mode])
            ;;
        fork)
            AC_MSG_NOTICE([FORK mode selected])
            AC_DEFINE([USE_FORK], [1], [Define to 1 to select FORK mode])
            ;;
        *)
            AC_MSG_ERROR([Unknown thread model \"${withval}\"])
            ;;
    esac
], [
        AC_MSG_NOTICE([PTHREAD thread model selected (default)])
        LIBS="$PTHREAD_LIBS $LIBS"
        CFLAGS="$CFLAGS $PTHREAD_CFLAGS"
        AC_DEFINE([USE_PTHREAD], [1], [Define to 1 to select PTHREAD mode])
    ]
)

AC_MSG_NOTICE([**************************************** libtool])
AC_DISABLE_STATIC
AC_PROG_LIBTOOL
AC_SUBST([LIBTOOL_DEPS])

AC_MSG_NOTICE([**************************************** types])
AC_TYPE_INT8_T
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UID_T
AC_MSG_CHECKING([for socklen_t])
AC_EGREP_HEADER(socklen_t, sys/socket.h,
    AC_MSG_RESULT([yes]),
    AC_MSG_RESULT([no (defined as int)])
    AC_DEFINE([socklen_t], [int], [Type of socklen_t]))
AC_CHECK_TYPES([struct sockaddr_un], [], [], [#include <sys/un.h>])
AC_CHECK_TYPES([struct addrinfo], [], [], [#include <netdb.h>])
AC_CHECK_SIZEOF(void *)

AC_MSG_NOTICE([**************************************** PTY device files])
if test "x$cross_compiling" = "xno"; then
    AC_CHECK_FILE("/dev/ptmx", AC_DEFINE([HAVE_DEV_PTMX], [1],
        [Define to 1 if you have '/dev/ptmx' device.]))
    AC_CHECK_FILE("/dev/ptc", AC_DEFINE([HAVE_DEV_PTS_AND_PTC], [1],
        [Define to 1 if you have '/dev/ptc' device.]))
else
    AC_MSG_WARN([cross-compilation: assuming /dev/ptmx and /dev/ptc are not available])
fi

AC_MSG_NOTICE([**************************************** entropy sources])

if test "x$cross_compiling" = "xno"; then
    AC_ARG_WITH(egd-socket,
        [  --with-egd-socket=FILE  Entropy Gathering Daemon socket path],
        [EGD_SOCKET="$withval"]
    )
    if test -n "$EGD_SOCKET"; then
        AC_DEFINE_UNQUOTED([EGD_SOCKET], ["$EGD_SOCKET"],
            [Entropy Gathering Daemon socket path])
    fi

    # Check for user-specified random device
    AC_ARG_WITH(random,
    [  --with-random=FILE      read randomness from file (default=/dev/urandom)],
        [RANDOM_FILE="$withval"],
        [
            # Check for random device
            if test "x$stunnel_enable_ios" != xyes && \
                test "x$stunnel_enable_ios_emul" != xyes && \
                test "x$stunnel_enable_uclibc" != xyes && \
                test "x$stunnel_enable_baikal" != xyes && \
                test "x$stunnel_enable_arm64" != xyes && \
                test "x$stunnel_enable_armel" != xyes && \
                ( test $host_cpu != "powerpcle" -a $host_cpu != "powerpc64le" ||\
                test $build_cpu == "powerpc64le" )
            then    
                AC_CHECK_FILE("/dev/urandom", RANDOM_FILE="/dev/urandom")
            fi
        ]
    )
    if test -n "$RANDOM_FILE"; then
        AC_SUBST([RANDOM_FILE])
        AC_DEFINE_UNQUOTED([RANDOM_FILE], ["$RANDOM_FILE"], [Random file path])
    fi
else
    AC_MSG_WARN([cross-compilation: assuming entropy sources are not available])
fi

AC_MSG_NOTICE([**************************************** default group])
DEFAULT_GROUP=nobody
if test "x$cross_compiling" = "xno"; then
    grep '^nogroup:' /etc/group >/dev/null && DEFAULT_GROUP=nogroup
else
    AC_MSG_WARN([cross-compilation: assuming nogroup is not available])
fi
AC_MSG_CHECKING([for default group])
AC_MSG_RESULT([$DEFAULT_GROUP])
AC_SUBST([DEFAULT_GROUP])

AC_SYS_LARGEFILE

AC_MSG_NOTICE([**************************************** header files])
# AC_HEADER_DIRENT
# AC_HEADER_STDC
# AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([stdint.h inttypes.h malloc.h ucontext.h pthread.h poll.h \
    tcpd.h stropts.h grp.h unistd.h util.h libutil.h pty.h limits.h])
AC_CHECK_HEADERS([sys/types.h sys/select.h sys/poll.h sys/socket.h sys/un.h \
    sys/ioctl.h sys/filio.h sys/resource.h sys/uio.h sys/syscall.h \
    sys/param.h])
AC_CHECK_HEADERS([sched.h])
AC_CHECK_MEMBERS([struct msghdr.msg_control],
    [AC_DEFINE([HAVE_MSGHDR_MSG_CONTROL], [1],
    [Define to 1 if you have 'msghdr.msg_control' structure.])], [], [
AC_INCLUDES_DEFAULT
#include <sys/socket.h>
    ])
AC_CHECK_HEADERS([linux/netfilter_ipv4.h], , ,
    [
#include <limits.h>
#include <linux/types.h>
#include <sys/socket.h>
#include <netdb.h>
    ])

AC_MSG_NOTICE([**************************************** libraries])
# Checks for standard libraries
AC_SEARCH_LIBS([socket], [socket])
AC_SEARCH_LIBS([openpty], [util])
# Checks for dynamic loader needed by OpenSSL
AC_SEARCH_LIBS([dlopen], [dl])
AC_SEARCH_LIBS([shl_load], [dld])

# Add BeOS libraries
if test "x$host_os" = "xbeos"; then
    LIBS="$LIBS -lbe -lroot -lbind"
fi

AC_MSG_NOTICE([**************************************** library functions])
# safe string operations
AC_CHECK_FUNCS(snprintf vsnprintf)
# pseudoterminal
AC_CHECK_FUNCS(openpty _getpty)
# Unix
AC_CHECK_FUNCS(daemon waitpid wait4 setsid setgroups chroot realpath)
# limits
AC_CHECK_FUNCS(sysconf getrlimit)
# threads/reentrant functions
AC_CHECK_FUNCS(pthread_sigmask localtime_r)
# threads
AC_CHECK_FUNCS(getcontext __makecontext_v2)
# sockets
AC_CHECK_FUNCS(poll gethostbyname2 endhostent getnameinfo)
AC_MSG_CHECKING([for getaddrinfo])
case "$host_os" in
*androideabi*)
    # http://stackoverflow.com/questions/7818246/segmentation-fault-in-getaddrinfo
    AC_MSG_RESULT([no (buggy Android implementation)])
    ;;
*)
    # Tru64 UNIX has getaddrinfo() but has it renamed in libc as
    # something else so we must include <netdb.h> to get the
    # redefinition.
    AC_LINK_IFELSE(
        [AC_LANG_PROGRAM(
            [
AC_INCLUDES_DEFAULT
#include <sys/socket.h>
#include <netdb.h>
            ],
            [
getaddrinfo(NULL, NULL, NULL, NULL);
            ],)],
        [AC_MSG_RESULT([yes]); AC_DEFINE([HAVE_GETADDRINFO], [1], [Define to 1 if you have 'getaddrinfo' function.])],
        [AC_MSG_RESULT([no])])
    ;;
esac
# poll() is not recommended on Mac OS X <= 10.3 and broken on Mac OS X 10.4
AC_MSG_CHECKING([for broken poll() implementation])
case "$host_os" in
darwin[0-8].*)
    AC_MSG_RESULT([yes (poll() disabled)])
    AC_DEFINE([BROKEN_POLL], [1], [Define to 1 if you have a broken 'poll' implementation.])
    ;;
*)
    AC_MSG_RESULT([no])
    ;;
esac
# GNU extensions
AC_CHECK_FUNCS(pipe2 accept4)

AC_MSG_NOTICE([**************************************** optional features])
# Use IPv6?
AC_MSG_CHECKING([whether to enable IPv6 support])
AC_ARG_ENABLE(ipv6,
[  --disable-ipv6          disable IPv6 support],
    [
        case "$enableval" in
            yes) AC_MSG_RESULT([yes])
                 AC_DEFINE([USE_IPv6], [1],
                    [Define to 1 to enable IPv6 support])
                 ;;
            no)  AC_MSG_RESULT([no])
                 ;;
            *)   AC_MSG_RESULT([error])
                 AC_MSG_ERROR([bad value \"${enableval}\"])
                 ;;
        esac
    ], [
        AC_MSG_RESULT([yes (default)])
        AC_DEFINE([USE_IPv6], [1], [Define to 1 to enable IPv6 support])
    ], [
        AC_MSG_RESULT([no])
    ]
)

# Use msspi?
AC_MSG_CHECKING([whether to enable msspi support])
AC_ARG_ENABLE(msspi,
[  --enable-msspi          enable msspi support],
    [
        case "$enableval" in
            yes) AC_MSG_RESULT([yes])
                 AM_CONDITIONAL(MSSPI, true)
                 AC_DEFINE([USE_MSSPI], [1],
                    [Define to 1 to enable MSSPI support])
                 ;;
            no)  AC_MSG_RESULT([no])
                 ;;
            *)   AC_MSG_RESULT([error])
                 AC_MSG_ERROR([bad value \"${enableval}\"])
                 ;;
        esac
    ], [
        AC_MSG_RESULT([yes (default)])
        AM_CONDITIONAL(MSSPI, true)
        AC_DEFINE([USE_MSSPI], [1],
            [Define to 1 to enable MSSPI support])
    ]
)

# FIPS Mode
AC_MSG_CHECKING([whether to enable FIPS support])
AC_ARG_ENABLE(fips,
[  --disable-fips          disable OpenSSL FIPS support],
    [
        case "$enableval" in
            yes) AC_MSG_RESULT([no])
                 use_fips="yes"
                 AC_DEFINE([USE_FIPS], [1],
                    [Define to 1 to enable OpenSSL FIPS support])
                 ;;
            no)  AC_MSG_RESULT([no])
                 use_fips="no"
                 ;;
            *)   AC_MSG_RESULT([error])
                 AC_MSG_ERROR([bad value \"${enableval}\"])
                 ;;
        esac
    ],
    [
        use_fips="auto"
        AC_MSG_RESULT([autodetecting])
    ]
)

# Disable systemd socket activation support
AC_MSG_CHECKING([whether to enable systemd socket activation support])
AC_ARG_ENABLE(systemd,
[  --disable-systemd       disable systemd socket activation support],
    [
        case "$enableval" in
            yes) AC_MSG_RESULT([yes])
                 AC_SEARCH_LIBS([sd_listen_fds], [systemd systemd-daemon])
                 AC_DEFINE([USE_SYSTEMD], [1],
                     [Define to 1 to enable systemd socket activation])
                 ;;
            no)  AC_MSG_RESULT([no])
                 ;;
            *)   AC_MSG_RESULT([error])
                 AC_MSG_ERROR([Bad value \"${enableval}\"])
                 ;;
        esac
    ],
    [
        AC_MSG_RESULT([autodetecting])
        # the library name has changed to -lsystemd in systemd 209
        AC_SEARCH_LIBS([sd_listen_fds], [systemd systemd-daemon],
            [ AC_CHECK_HEADERS([systemd/sd-daemon.h], [
                AC_DEFINE([USE_SYSTEMD], [1],
                    [Define to 1 to enable systemd socket activation])
                AC_MSG_NOTICE([systemd support enabled])
            ], [
                AC_MSG_NOTICE([systemd header not found])
            ]) ], [
                AC_MSG_NOTICE([systemd library not found])
            ])
    ]
)

# Disable use of libwrap (TCP wrappers)
# it should be the last check!
AC_MSG_CHECKING([whether to enable TCP wrappers support])
AC_ARG_ENABLE(libwrap,
[  --disable-libwrap       disable TCP wrappers support],
    [
        case "$enableval" in
            yes) AC_MSG_RESULT([yes])
                 AC_SEARCH_LIBS([gethostbyname], [nsl])
                 AC_SEARCH_LIBS([yp_get_default_domain], [nsl])
                 AC_DEFINE([USE_LIBWRAP], [1],
                     [Define to 1 to enable TCP wrappers support])
                 LIBS="$LIBS -lwrap"
                 ;;
            no)  AC_MSG_RESULT([no])
                 ;;
            *)   AC_MSG_RESULT([error])
                 AC_MSG_ERROR([Bad value \"${enableval}\"])
                 ;;
        esac
    ],
    [
        AC_MSG_RESULT([autodetecting])
        AC_MSG_CHECKING([for hosts_access in -lwrap])
        valid_LIBS="$LIBS"
        LIBS="$valid_LIBS -lwrap"
        AC_LINK_IFELSE(
            [
                AC_LANG_PROGRAM(
                    [int hosts_access(); int allow_severity, deny_severity;],
                    [hosts_access()])
            ], [
                AC_SEARCH_LIBS([gethostbyname], [nsl])
                AC_SEARCH_LIBS([yp_get_default_domain], [nsl])
                AC_MSG_RESULT([yes]);
                AC_DEFINE([USE_LIBWRAP], [1],
                    [Define to 1 to enable TCP wrappers support])
                AC_MSG_NOTICE([libwrap support enabled])
            ], [
                AC_MSG_RESULT([no])
                LIBS="$valid_LIBS"
                AC_MSG_NOTICE([libwrap library not found])
            ]
        )
    ]
)

# Boost support
AC_MSG_CHECKING([whether to enable Boost support for msspi (instead c++11 standard)])
AC_ARG_ENABLE(boostmsspi,
[  --disable-boostmsspi       disable Boost support (for msspi only)],
    [
        case "$enableval" in
            yes) AC_MSG_RESULT([yes])
                 AM_CONDITIONAL(USE_BOOST, true)
                 AC_DEFINE(USE_BOOST, 1, [Enable boost instead c++11 standard (for msspi only)])
                 ;;
            no)  AC_MSG_RESULT([no])
                 ;;
            *)   AC_MSG_RESULT([error])
                 AC_MSG_ERROR([Bad value \"${enableval}\"])
                 ;;
        esac
    ],
    [
        AC_MSG_RESULT([yes (default)])
        AM_CONDITIONAL(USE_BOOST, true)
        AC_DEFINE(USE_BOOST, 1, [Enable boost instead c++11 standard (for msspi only)])
    ]
)

AC_MSG_NOTICE([**************************************** TLS])

check_ssl_dir() { :
    test -n "$1" -a -f "$1/include/openssl/ssl.h" && SSLDIR="$1"
}

iterate_ssl_dir() { :
    # OpenSSL directory search order:
    # - the user-specified prefix
    # - common locations for packages built from sources
    # - common locations for non-OS-default package managers
    # - common locations for OS-default package managers
    # - empty prefix
    for main_dir in "/usr/local" "/opt" "/opt/local" "/usr/local/opt" "/opt/csw" "/usr/pkg" "/usr/lib" "/usr/sfw" "/usr" ""; do
        for sub_dir in "/ssl" "/openssl" "/ossl" ""; do
            check_ssl_dir "$1$main_dir$sub_dir" && return 0
        done
    done
    return 1
}

find_ssl_dir() { :
    # try Android *first*
    case "$host_os" in
    *androideabi*)
        iterate_ssl_dir "$ANDROID_NDK/sysroot" && return
        ;;
    esac

    # try Xcode *last*
    if test -x "/usr/bin/xcrun"; then
        sdk_path=`/usr/bin/xcrun --sdk macosx --show-sdk-path`
        check_ssl_dir "$sdk_path/usr" && return
    fi

    test -d "$lt_sysroot" && iterate_ssl_dir "$lt_sysroot" && return
    test "$prefix" != "NONE" && iterate_ssl_dir "$prefix" && return
    test -d "$ac_default_prefix" && iterate_ssl_dir "$ac_default_prefix" && return
    iterate_ssl_dir "" && return

    check_ssl_dir "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/swift-migrator/sdk/MacOSX.sdk/usr"
}

SSLDIR=""
AC_MSG_CHECKING([for TLS directory])
AC_ARG_WITH(ssl,
[  --with-ssl=DIR          location of installed TLS libraries/include files],
    [check_ssl_dir "$withval"],
    [find_ssl_dir]
)
if test -z "$SSLDIR"; then
    AC_MSG_RESULT([System ssl not found, cp-openssl will be used.])
else
    AC_MSG_RESULT([System ssl was found.])
    AC_MSG_RESULT([$SSLDIR])
    AC_DEFINE_UNQUOTED([SSLDIR], ["$SSLDIR"], [TLS directory])
fi
AC_SUBST([SSLDIR])
AM_CONDITIONAL([SSLDIR_SET], [test -n "$SSLDIR"])

valid_CPPFLAGS="$CPPFLAGS"; # CPPFLAGS="$CPPFLAGS -I$SSLDIR/include"
valid_LIBS="$LIBS"; # LIBS="$LIBS -L$SSLDIR/lib64 -L$SSLDIR/lib -lssl -lcrypto"

AC_CHECK_FUNCS(FIPS_mode_set OSSL_PROVIDER_available)
if test "x$use_fips" = "xauto"; then
    if test "x$ac_cv_func_FIPS_mode_set" = "xyes" -o "x$ac_cv_func_OSSL_PROVIDER_available" = "xyes"; then
        AC_DEFINE([USE_FIPS], [1], [Define to 1 to enable OpenSSL FIPS support])
        AC_MSG_NOTICE([FIPS support enabled])
    else
        AC_MSG_NOTICE([FIPS support not found])
    fi
fi

AC_MSG_CHECKING([whether DH parameters need to be updated])
# only build src/dhparam.c if sources are located in the current directory
if test -f src/stunnel.c && ! grep -q " built for $PACKAGE_STRING " src/dhparam.c; then
    AC_MSG_RESULT([yes])
    (
        echo '/* dhparam.c: initial DH parameters for stunnel */'
        echo '#include "common.h"'
        echo '#ifndef OPENSSL_NO_DH'
        echo '#define DN_new DH_new'
        openssl dhparam -noout -C 2048 | sed 's/static DH/DH/'
        echo '#endif /* OPENSSL_NO_DH */'
        echo "/* built for $PACKAGE_STRING */"
    ) > src/dhparam.c
else
    AC_MSG_RESULT([no])
fi

SYSROOT="$lt_sysroot"
CPPFLAGS="$valid_CPPFLAGS"
LIBS="$valid_LIBS"

AC_MSG_NOTICE([**************************************** write the results])
AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT

AC_MSG_NOTICE([**************************************** success])
# vim:ft=automake
# End of configure.ac
