#ifndef _MAKEMORE_FEATURES_
#define _MAKEMORE_FEATURES_

#include <unistd.h>

#ifdef _POSIX_VERSION
# define _POSIX_C_SOURCE _POSIX_VERSION
#endif

#ifdef _POSIX_C_SOURCE
# define HAVE_GETNAMEINFO
# define HAVE_PWD
# if _POSIX_C_SOURCE >= 200112L
#  define HAVE_SYMLINK
# endif
# if _POSIX_C_SOURCE >= 199309L
#  define HAVE_SIGACTION
# endif
# if _POSIX_C_SOURCE >= 200809L
#  define HAVE_STRDUP
# endif
# if _POSIX_C_SOURCE >= 2
#  define HAVE_GETOPT
# endif
#endif

#ifdef _XOPEN_SOURCE
# define HAVE_GETOPT
# if _XOPEN_SOURCE >= 500
#  define HAVE_LOCKF
#  define HAVE_SYMLINK
#  define HAVE_STRDUP
# endif
#endif

#ifdef _BSD_SOURCE
# define HAVE_LOCKF
# define HAVE_SYMLINK
# define HAVE_STRDUP
#endif

#ifndef NI_MAXHOST
# define NI_MAXHOST      1025
# define NI_MAXSERV      32
#endif

#endif
