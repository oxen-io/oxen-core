#!/bin/bash
#
#  -D BOOST_ROOT=/opt/android/boost_1_58_0

set -e

orig_path=$PATH
base_dir=`pwd`

build_type=release # or debug

archs=(arm arm64 x86 x86_64)

for arch in ${archs[@]}; do
	ldflags=""
    case ${arch} in
        "arm")
			target_host=arm-linux-androideabi
			ldflags="-march=armv7-a -Wl,--fix-cortex-a8"
			xarch=armv7-a
			sixtyfour=OFF
			;;
        "arm64")
			target_host=aarch64-linux-android
			xarch="armv8-a"
			sixtyfour=ON
            ;;
        "x86")
			target_host=i686-linux-android
			xarch="i686"
            ;;
        "x86_64")
			target_host=x86_64-linux-android
			xarch="x86-64"
			sixtyfour=ON
            ;;
        *)
			exit 16
            ;;
    esac

	OUTPUT_DIR=$base_dir/build/$build_type.$arch

	mkdir -p $OUTPUT_DIR
	cd $OUTPUT_DIR

	PATH=/opt/android/tool/$arch/$target_host/bin:/opt/android/tool/$arch/bin:$PATH CC=clang CXX=clang++ cmake -D BUILD_GUI_DEPS=1 -D BUILD_TESTS=OFF -D ARCH="$xarch" -D STATIC=ON -D BUILD_64=$sixtyfour -D CMAKE_BUILD_TYPE=$build_type -D ANDROID=true -D BUILD_TAG="android" -D BOOST_ROOT=/opt/android/build/boost/$arch -D BOOST_LIBRARYDIR=/opt/android/build/boost/$arch/lib -D OPENSSL_ROOT_DIR=/opt/android/build/openssl/$arch -D OPENSSL_CRYPTO_LIBRARY=/opt/android/build/openssl/$arch/lib/libcrypto.so -D OPENSSL_SSL_LIBRARY=/opt/android/build/openssl/$arch/lib/libssl.so -D CMAKE_POSITION_INDEPENDENT_CODE:BOOL=true ../..
	make -j4 wallet_api
	find . -path ./lib -prune -o -name '*.a' -exec cp '{}' lib \;

    TARGET_LIB_DIR=/opt/android/build/monero/$arch/lib
    rm -rf $TARGET_LIB_DIR
    mkdir -p $TARGET_LIB_DIR
    cp $OUTPUT_DIR/lib/*.a $TARGET_LIB_DIR

    TARGET_INC_DIR=/opt/android/build/monero/include
    rm -rf $TARGET_INC_DIR
    mkdir -p $TARGET_INC_DIR
	cp -a ../../src/wallet/api/wallet2_api.h $TARGET_INC_DIR

	cd $base_dir
done
exit 0

