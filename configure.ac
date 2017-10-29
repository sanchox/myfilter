#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([myfilter], [0.1], [alexandergusarov@gmail.com])
AC_CONFIG_SRCDIR([myfilter.c])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE

# Checks for programs.
AC_PROG_CC
AC_PROG_CC_STDC
AC_PROG_CPP

# Use the C language and compiler for the following checks
AC_LANG([C])

# Checks for libraries.
AC_SEARCH_LIBS([pthread_create, pthread_sigmask, pthread_cancel, pthread_join], [pthread])
AC_SEARCH_LIBS([blob_buf_init, blobmsg_add_field], [ubox])
AC_SEARCH_LIBS([ubus_connect_ctx, ubus_send_event], [ubus])

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h netinet/in.h stdint.h stdlib.h string.h sys/socket.h unistd.h stdio.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([socket])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
