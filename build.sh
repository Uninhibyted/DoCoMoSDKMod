#!/bin/sh
# Builds sdkmod as build/libEGL.dll (32-bit Windows) with MinGW-w64.
#   macOS:  brew install mingw-w64      Debian/Ubuntu:  apt install gcc-mingw-w64-i686
#
# libEGL.def forwards every export of the SDK's stock libEGL.dll to libEGL_stock.dll
# (regenerate it with ./gen-def.sh <stock libEGL.dll> > libEGL.def). The version comes from VERSION.
#
# The build is reproducible: a fixed preferred load address (the linker otherwise derives one
# from the output path) and no timestamp, so the same sources always give the same bytes. The
# DLL is still relocatable (DYNAMIC_BASE, .reloc kept), so ASLR applies as usual.
set -e
cd "$(dirname "$0")"
version=$(tr -d ' \r\n' < VERSION)
mkdir -p build
${CC:-i686-w64-mingw32-gcc} -O2 -Wall -shared -s -o build/libEGL.dll sdkmod.c libEGL.def \
  -DSDKMOD_VERSION="\"$version\"" \
  -Wl,--enable-stdcall-fixup,--image-base,0x6a000000,--no-insert-timestamp -static-libgcc -lgdi32
echo "built sdkmod $version: $(pwd)/build/libEGL.dll ($(wc -c < build/libEGL.dll | tr -d ' ') bytes)"
