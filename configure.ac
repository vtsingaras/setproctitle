#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT(setproctitle, 1.0, vtsingaras@codersunleashed.com)
AM_INIT_AUTOMAKE(setproctitle, 1.0)
AC_OUTPUT(Makefile src/Makefile man/Makefile)
AC_CONFIG_SRCDIR([src/setproctitle.c])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([stdlib.h string.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([strchr strdup strtoul])

AC_OUTPUT
