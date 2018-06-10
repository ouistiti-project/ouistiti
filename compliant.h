#ifndef _MAKEMORE_FEATURES_
#define _MAKEMORE_FEATURES_

#ifdef _POSIX_C_SOURCE
# define HAVE_GETNAMEINFO
# define HAVE_PWD
# if _POSIX_C_SOURCE >= 199309L
#  define HAVE_SIGACTION
# endif
#endif

#ifdef _XOPEN_SOURCE
# define HAVE_GETOPTS
# if _XOPEN_SOURCE >= 500
#  define HAVE_LOCKF
#  define HAVE_SYMLINK
#  define HAVE_STRDUP
# endif
#endif

#ifndef NI_MAXHOST
# define NI_MAXHOST      1025
# define NI_MAXSERV      32
#endif

#endif
