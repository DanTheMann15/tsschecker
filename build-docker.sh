#!/bin/sh
mkdir -p /app

apk add --no-cache git libtool automake autoconf gcc make g++ libzip-dev patch file bash

apk add --no-cache curl-dev readline-dev libusb-dev

git -C /app clone --depth=1 --recursive https://github.com/libimobiledevice/libplist
cd /app/libplist
./autogen.sh --enable-debug --without-cython
make install

git -C /app clone --depth=1 --recursive https://github.com/libimobiledevice/libimobiledevice-glue
cd /app/libimobiledevice-glue
./autogen.sh
make install

git -C /app clone --depth=1 --recursive https://github.com/libimobiledevice/libirecovery
cd /app/libirecovery
./autogen.sh
make install

git -C /app clone --depth=1 --recursive https://github.com/tihmstar/libgeneral
cd /app/libgeneral
./autogen.sh
make install

git -C /app clone --depth=1 --recursive https://github.com/tihmstar/libfragmentzip
cd /app/libfragmentzip
cat <<EOF | patch
--- configure.ac
+++ configure.ac
@@ -37,7 +37,7 @@
 LIBCURL_REQUIRES_STR="libcurl >= 1.0"
 LIBZIP_REQUIRES_STR="libzip >= 1.0"
 LIBZ_REQUIRES_STR="zlib >= 1.0"
-LIBGENERAL_REQUIRES_STR="libgeneral >= 48"
+LIBGENERAL_REQUIRES_STR="libgeneral >= 1"
 
EOF
./autogen.sh
make install

git -C /app clone --depth=1 --recursive https://github.com/DanTheMann15/tsschecker
cd /app/tsschecker

cd tsschecker
cat <<EOF | patch --ignore-whitespace
--- tss.c
+++ tss.c
@@ -51,7 +51,7 @@
         tsserror("ERROR: Invalid ECID passed.\n");
         return NULL;
     }
-    snprintf(ecid_string, ECID_STRSIZE, FMT_qu, ecid);
+    snprintf(ecid_string, ECID_STRSIZE, "%llu", (long long unsigned int)ecid);
     return ecid_string;
 }
EOF

cd ..
cat <<EOF | patch
--- configure.ac
+++ configure.ac
@@ -44,7 +44,7 @@
 
 PKG_CHECK_MODULES(libplist, libplist >= 2.2.0)
 PKG_CHECK_MODULES(libcurl, libcurl >= 1.0)
-PKG_CHECK_MODULES(libfragmentzip, libfragmentzip >= 48)
+PKG_CHECK_MODULES(libfragmentzip, libfragmentzip >= 1)
 AS_IF([test "x\$with_libcrypto" != xno],
     [PKG_CHECK_MODULES(libcrypto, libcrypto >= 1.0)]
 )
EOF

./autogen.sh
bash ./configure
make install

apk del git libtool automake autoconf gcc make g++ libzip-dev patch file readline-dev
rm -rf /app/tsschecker /app/libgeneral /app/libfragmentzip
