ACLOCAL_AMFLAGS = -I m4 --install

AM_CFLAGS = --std=c99 -g3

bin_PROGRAMS = encryptor
encryptor_SOURCES = src/main.c
encryptor_LDADD = $(OPENSSL_LIBS)
encryptor_CFLAGS = --std=c99 $(OPENSSL_CFLAGS) -g3

EXTRA_DIST = m4/NOTES
