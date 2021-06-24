#!/bin/sh

set -ex

export PKG_CONFIG_ALLOW_CROSS=1
export CARGO_INCREMENTAL=1
export RUST_LOG=indy=trace
export RUST_TEST_THREADS=1

# OpenSSL path changes with version number, so export OPENSSL_DIR=/usr/local/Cellar/openssl/1.0.2n would not work correctly
OPENSSL_PATH=/usr/local/Cellar/openssl@1.1
for i in $(ls -t $OPENSSL_PATH); do
    export OPENSSL_VERSION=$i
    export OPENSSL_DIR=$OPENSSL_PATH/$OPENSSL_VERSION
    break
done

#efb72154dab94498861c43f9ac5208174e9b702c (HEAD -> master, origin/master, origin/HEAD) Merge pull request #2402 from hyperledger/update/update-rusqlite
#9fbbb7939440b67e92f2698e868f14c2432cce72 Merge pull request #2397 from ianco/postgres_updates
#794ad8a599f57e0f8e085e116251b96edbae0e40 Merge pull request #2392 from Nova-Scotia-Digital-Service/master
#e80e7092e4f3232b3ddf6841cd56619487e79eb0 Merge pull request #2389 from TimoGlastra/update-nodejs-wrapper
#503e8bc11302c35b8903f6296b372a32c690dd05 Merge branch 'master' into update-nodejs-wrapper
#8993d0b3f5cfe10c75d5d70d22b49e42ab4ee7c4 Merge pull request #2390 from ianco/rc
#4e4a7a29480ae4dbe27f6170a64d94ff6b02f4dd Merge branch 'master' into rc
#cb17e1bf4d534a22bfc9fc9d1e2219c15734e639 Merge branch 'master' into update-nodejs-wrapper
#1ea73bb92ad5682ab3e1f4422fa68c40d59197ea Merge branch 'master' into rc
#cc52f08778e279d400ac60f031e761a6536fe3e7 Merge pull request #2354 from mirgee/ga-workflow
#32e30b6ca307c201c3d16341887af2887c6d9562 Merge pull request #2366 from toshirin33/postgres_plugin_default_db   1628, 32e30b6ca
#12f1831efa8203b541bdc5d1645670ae48790538 (origin/rc) Merge branch 'master' into rc
#32c5d087c149878366c50fdb8e161d34657c22fd Merge branch 'master' into postgres_plugin_default_db
#8fa3c2ce9cb4978e4dc1f9bd57980437578b081a Merge pull request #2372 from baegjae/multi-wallet-md5
#dbd89cf94a73e7a62611c4150a874c38b810ff8d Merge pull request #2368 from toshirin33/percent_encoding
#212ab8844de3fffa195bed86276d0fc04e94a442 Merge pull request #2362 from ianco/rc
#8c669cff434f5d87e7a2e2e192423c67a9df0b33 Merge pull request #2356 from adenishchenko/frozen_ledgers
#03f5482198311670a63095363ddb032c71fa4eff Merge pull request #2257 from Artemkaaas/bugfix/proof-request-restriction
#645299886f9282769fdcddbb742135e94a5691ac Merge branch 'master' into bugfix/proof-request-restriction
#88bbb9646418f269db1c3d29c4bb2b7ea52e1660 (mirgee/master) Merge pull request #2338 from adenishchenko/bucket_metrics
#506254c2c0afe87ed6834bfaff8f46800e78bcde Merge branch 'master' into bucket_metrics
#c2a36d369fe7a16a241c5711b5c49b945816d009 Merge pull request #2341 from AxelNennker/sha-version-0.9
#7349f5684bff5eb84bc370f1c6c8fc7e8c054613 Merge pull request #2318 from adenishchenko/metrics_prometheus
#b4b330ef326958d593ab42e25679c2dcd655494c (tag: v1.16.0) Merge pull request #2335 from ianco/rc


INDY_VERSION="efb7215" # release indy-1.16.0-post-59 ##  this is "v1.16.0" + rusql update fix + (number of other commits on master branch)
#INDY_VERSION="v1.16.0"
#INDY_VERSION="b4b330ef3" # this is "v1.16.0" tag
#INDY_VERSION="32e30b6ca" # between efb7215, b4b330ef3, indy-sys = "1.15.0-dev-1628" indy = "1.15.0-dev-1628"
REPO_DIR=$PWD
SCRIPT_DIR="$( cd "$(dirname "$0")" ; pwd -P )"
OUTPUT_DIR=/tmp/artifacts
INDY_SDK_DIR=$OUTPUT_DIR/indy-sdk

setup() {
    echo "Setup rustup"
    rustup default 1.45.2
    rustup component add rls-preview rust-analysis rust-src

    echo "Setup rustup target platforms"
    rustup target add aarch64-apple-ios x86_64-apple-ios

    RUST_TARGETS=$(rustc --print target-list | grep -i ios)
    if [ "$RUST_TARGETS" = "" ]; then
        echo "Error: Rust targets for iOS has not been set! Try to run 'xcode-select -s /Applications/Xcode.app'"
        exit 1
    fi

    echo "Install Rust Xcode tools"
    cargo install cargo-lipo
    cargo install cargo-xcode

    echo "Check Homebrew"
    BREW_VERSION=$(brew --version)
    if ! [[ $BREW_VERSION =~ ^'Homebrew ' ]]; then
        echo "Error: Missing Homebrew, package manager for macOS to install native dependencies."
        exit 1
    fi

    echo "Install required native libraries and utilities"
    which pkg-config &>/dev/null || brew install pkg-config
    # Libsodium version<1.0.15 is required
    # brew install https://raw.githubusercontent.com/Homebrew/homebrew-core/65effd2b617bade68a8a2c5b39e1c3089cc0e945/Formula/libsodium.rb
    which automake &>/dev/null || brew install automake
    which autoconf &>/dev/null || brew install autoconf
    which cmake &>/dev/null || brew install cmake
    which wget &>/dev/null || brew install wget
    which truncate &>/dev/null || brew install truncate
    brew list openssl &>/dev/null || brew install openssl
    brew list zmq &>/dev/null || brew install zmq
    brew list libzip &>/dev/null || brew install libzip

    mkdir -p $OUTPUT_DIR

    # Figure out which OPENSSL we have available
    export OPENSSL_BASE_DIR=$(brew --cellar openssl)
    for f in $(ls -t "$OPENSSL_BASE_DIR"); do
      local ABSOLUTE_FILE_PATH="${OPENSSL_BASE_DIR}/${f}"
      if [ -d "$ABSOLUTE_FILE_PATH" ] && [ -d "$ABSOLUTE_FILE_PATH/lib" ]; then
        export OPENSSL_VERSION=$f
        export OPENSSL_DIR=$ABSOLUTE_FILE_PATH # Used later by cyclone
        break
      fi
    done
    if [ -z "$OPENSSL_VERSION" ]; then
      echo >&2 "Error: Failed to find an OpenSSL installation in $OPENSSL_BASE_DIR"
      exit 1
    else
      echo "Found OpenSSL version $OPENSSL_VERSION"
    fi
}

# NOTE: Each built archive must be a fat file, i.e support all required architectures
# Can be checked via e.g. `lipo -info $OUTPUT_DIR/OpenSSL-for-iPhone/lib/libssl.a`
build_crypto() {
    if [ ! -d $OUTPUT_DIR/OpenSSL-for-iPhone ]; then
        git clone https://github.com/x2on/OpenSSL-for-iPhone.git $OUTPUT_DIR/OpenSSL-for-iPhone
    fi

    pushd $OUTPUT_DIR/OpenSSL-for-iPhone
        ./build-libssl.sh --version=$OPENSSL_VERSION
    popd
}

build_libsodium() {
    if [ ! -d $OUTPUT_DIR/libsodium-ios ]; then
        git clone https://github.com/evernym/libsodium-ios.git $OUTPUT_DIR/libsodium-ios
    fi

    pushd $OUTPUT_DIR/libsodium-ios
        ./libsodium.rb
    popd
}

build_libzmq() {
    if [ ! -d $OUTPUT_DIR/libzmq-ios ]; then
        git clone https://github.com/evernym/libzmq-ios.git $OUTPUT_DIR/libzmq-ios
    fi

    pushd $OUTPUT_DIR/libzmq-ios
        git apply $SCRIPT_DIR/patches/libzmq.rb.patch
        ./libzmq.rb
    popd
}

# NOTE: $OUTPUT_DIR/libs/{arm64,x86_64}/$LIB_NAME.a should be a non-fat file with arm64 / x86_64 architecture
extract_architectures() {
    ARCHS="arm64 x86_64"
    FILE_PATH=$1
    LIB_FILE_NAME=$2
    LIB_NAME=$3

    echo FILE_PATH=$FILE_PATH
    echo LIB_FILE_NAME=$LIB_FILE_NAME

    mkdir -p $OUTPUT_DIR/libs
    pushd $OUTPUT_DIR/libs
        echo "Extracting architectures for $LIB_FILE_NAME..."
        for ARCH in ${ARCHS[*]}; do
            DESTINATION=${LIB_NAME}/${ARCH}

            echo "Destination $DESTINATION"

            mkdir -p $DESTINATION
            lipo -extract ${ARCH} $FILE_PATH -o $DESTINATION/$LIB_FILE_NAME-fat.a
            lipo $DESTINATION/$LIB_FILE_NAME-fat.a -thin $ARCH -output $DESTINATION/$LIB_FILE_NAME.a
            rm $DESTINATION/$LIB_FILE_NAME-fat.a
        done
    popd
}

checkout_indy_sdk() {
    if [ ! -d $INDY_SDK_DIR ]; then
        git clone https://github.com/hyperledger/indy-sdk $INDY_SDK_DIR
    fi

    pushd $INDY_SDK_DIR
        git fetch --all
        git checkout $INDY_VERSION
    popd
}

# NOTE: $INDY_SDK_DIR/libindy/target/$TRIPLET/release/libindy.a should be a non-fat file
build_libindy() {
    # OpenSSL-for-iPhone currently provides libs only for aarch64-apple-ios and x86_64-apple-ios, so we select only them.
    TRIPLETS="aarch64-apple-ios,x86_64-apple-ios"

    pushd $INDY_SDK_DIR/libindy
        cargo lipo --release --targets="${TRIPLETS}"
    popd
}

copy_libindy_architectures() {
    ARCHS="arm64 x86_64"
    LIB_NAME="indy"

    echo "Copying architectures for $LIB_NAME..."
    for ARCH in ${ARCHS[*]}; do
        generate_flags $ARCH

        echo ARCH=$ARCH
        echo TRIPLET=$TRIPLET

        mkdir -p $OUTPUT_DIR/libs/$LIB_NAME/$ARCH
        cp -v $INDY_SDK_DIR/libindy/target/$TRIPLET/release/libindy.a $OUTPUT_DIR/libs/$LIB_NAME/$ARCH/libindy.a
    done
}

# NOTE: $INDY_SDK_DIR/vcx/libvcx/target/$TRIPLET/release/libindy.a should be a non-fat file
build_libvcx() {
    WORK_DIR=$(abspath "$OUTPUT_DIR")
    ARCHS="arm64 x86_64"

    echo WORK_DIR=$WORK_DIR

    pushd $REPO_DIR/libvcx
        for ARCH in ${ARCHS[*]}; do
            generate_flags $ARCH

            echo ARCH=$ARCH
            echo TRIPLET=$TRIPLET

            export OPENSSL_LIB_DIR=$WORK_DIR/libs/openssl/${ARCH}
            export IOS_SODIUM_LIB=$WORK_DIR/libs/sodium/${ARCH}
            export IOS_ZMQ_LIB=$WORK_DIR/libs/zmq/${ARCH}
            export LIBINDY_DIR=$WORK_DIR/libs/indy/${ARCH}

            cargo build --target "${TRIPLET}" --release --no-default-features --features "ci"
        done
    popd
}

copy_libvcx_architectures() {
    ARCHS="arm64 x86_64"
    LIB_NAME="vcx"

    mkdir -p $OUTPUT_DIR/libs

    echo "Copying architectures for $LIB_NAME..."
    for ARCH in ${ARCHS[*]}; do
        generate_flags $ARCH

        echo ARCH=$ARCH
        echo TRIPLET=$TRIPLET

        mkdir -p $OUTPUT_DIR/libs/$LIB_NAME/$ARCH

        cp -v $REPO_DIR/target/$TRIPLET/release/libvcx.a $OUTPUT_DIR/libs/$LIB_NAME/$ARCH/libvcx.a
    done
}

copy_libs_to_combine() {
    mkdir -p $OUTPUT_DIR/cache/arch_libs

    copy_lib_tocombine openssl libssl
    copy_lib_tocombine openssl libcrypto
    copy_lib_tocombine sodium libsodium
    copy_lib_tocombine zmq libzmq
    copy_lib_tocombine indy libindy
    copy_lib_tocombine vcx libvcx
}

copy_lib_tocombine() {
    LIB_NAME=$1
    LIB_FILE_NAME=$2

    ARCHS="arm64 x86_64"

    for ARCH in ${ARCHS[*]}; do
        cp -v $OUTPUT_DIR/libs/$LIB_NAME/$ARCH/$LIB_FILE_NAME.a $OUTPUT_DIR/cache/arch_libs/${LIB_FILE_NAME}_$ARCH.a
    done
}

combine_libs() {
    COMBINED_LIB=$1

    BUILD_CACHE=$(abspath "$OUTPUT_DIR/cache")
    libtool="/usr/bin/libtool"

    ARCHS="arm64 x86_64"

    # Combine results of the same architecture into a library for that architecture
    source_combined=""
    for arch in ${ARCHS[*]}; do
        libraries="libssl libcrypto libsodium libzmq libindy libvcx"

        echo libraries
        echo $libraries

        source_libraries=""

        for library in ${libraries[*]}; do
            echo "Stripping library"
            echo $library
            if [ "$DEBUG_SYMBOLS" = "nodebug" ]; then
                if [ "${library}" = "libvcx.a.tocombine" ]; then
                    rm -rf ${BUILD_CACHE}/arch_libs/${library}-$arch-stripped.a
                    strip -S -x -o ${BUILD_CACHE}/arch_libs/${library}-$arch-stripped.a -r ${BUILD_CACHE}/arch_libs/${library}_${arch}.a
                elif [ ! -f ${BUILD_CACHE}/arch_libs/${library}-$arch-stripped.a ]; then
                    strip -S -x -o ${BUILD_CACHE}/arch_libs/${library}-$arch-stripped.a -r ${BUILD_CACHE}/arch_libs/${library}_${arch}.a
                fi
                source_libraries="${source_libraries} ${BUILD_CACHE}/arch_libs/${library}-$arch-stripped.a"
            else
                source_libraries="${source_libraries} ${BUILD_CACHE}/arch_libs/${library}_${arch}.a"
            fi
        done

        echo "Using source_libraries: ${source_libraries} to create ${BUILD_CACHE}/arch_libs/${COMBINED_LIB}_${arch}.a"
        rm -rf "${BUILD_CACHE}/arch_libs/${COMBINED_LIB}_${arch}.a"
        $libtool -static ${source_libraries} -o "${BUILD_CACHE}/arch_libs/${COMBINED_LIB}_${arch}.a"
        source_combined="${source_combined} ${BUILD_CACHE}/arch_libs/${COMBINED_LIB}_${arch}.a"

        lipo -info ${BUILD_CACHE}/arch_libs/${COMBINED_LIB}_${arch}.a

        # TEMPORARY HACK (build libvcx without duplicate .o object files):
        # There are duplicate .o object files inside the libvcx.a file and these
        # lines of logic remove those duplicate .o object files
        rm -rf ${BUILD_CACHE}/arch_libs/tmpobjs
        mkdir ${BUILD_CACHE}/arch_libs/tmpobjs
        pushd ${BUILD_CACHE}/arch_libs/tmpobjs
        ar -x ../${COMBINED_LIB}_${arch}.a
        ls >../objfiles
        xargs ar cr ../${COMBINED_LIB}_${arch}.a.new <../objfiles
        if [ "$DEBUG_SYMBOLS" = "nodebug" ]; then
            strip -S -x -o ../${COMBINED_LIB}_${arch}.a.stripped -r ../${COMBINED_LIB}_${arch}.a.new
            mv ../${COMBINED_LIB}_${arch}.a.stripped ../${COMBINED_LIB}_${arch}.a
        else
            mv ../${COMBINED_LIB}_${arch}.a.new ../${COMBINED_LIB}_${arch}.a
        fi
        popd
    done

    echo "Using source_combined: ${source_combined} to create ${COMBINED_LIB}.a"
    # Merge the combined library for each architecture into a single fat binary
    lipo -create $source_combined -o $OUTPUT_DIR/${COMBINED_LIB}.a

    # Delete intermediate files
    rm -rf ${source_combined}

    # Show info on the output library as confirmation
    echo "Combination complete."
    lipo -info $OUTPUT_DIR/${COMBINED_LIB}.a
}

build_vcx_framework() {
    COMBINED_LIB=$1
    ARCHS="arm64 x86_64"

    cp -v $OUTPUT_DIR/${COMBINED_LIB}.a $REPO_DIR/wrappers/ios/vcx/lib/libvcx.a

    pushd $REPO_DIR/wrappers/ios/vcx
        rm -rf vcx.framework.previousbuild

        for ARCH in ${ARCHS[*]}; do
            echo "Building vcx framework for $ARCH architecture"

            rm -rf vcx.framework
            if [ "${ARCH}" = "i386" ] || [ "${ARCH}" = "x86_64" ]; then
                # This sdk supports i386 and x86_64
                IPHONE_SDK=iphonesimulator
            elif [ "${ARCH}" = "armv7" ] || [ "${ARCH}" = "armv7s" ] || [ "${ARCH}" = "arm64" ]; then
                # This sdk supports armv7, armv7s, and arm64
                IPHONE_SDK=iphoneos
            else
                echo "Missing IPHONE_SDK value!"
                exit 1
            fi

            xcodebuild -project vcx.xcodeproj -scheme vcx -configuration Release -arch ${ARCH} -sdk ${IPHONE_SDK} CONFIGURATION_BUILD_DIR=. build

            if [ -d "./vcx.framework.previousbuild" ]; then
                lipo -create -output combined.ios.vcx vcx.framework/vcx vcx.framework.previousbuild/vcx
                mv combined.ios.vcx vcx.framework/vcx
                rm -rf vcx.framework.previousbuild
            fi
            cp -rp vcx.framework vcx.framework.previousbuild
        done

        rm lib/libvcx.a
        rm -rf vcx.framework.previousbuild
        mkdir -p vcx.framework/Headers
        cp -v ConnectMeVcx.h vcx.framework/Headers
        cp -v include/libvcx.h vcx.framework/Headers
        cp -v vcx/vcx.h vcx.framework/Headers
        cp -v utils/*.h vcx.framework/Headers
        if [ -d tmp ]; then
            rm -rf tmp
        fi

        UNIVERSAL_BUILD_PATH=$OUTPUT_DIR/universal/vcx
        mkdir -p $UNIVERSAL_BUILD_PATH
        cp -rvp vcx.framework $UNIVERSAL_BUILD_PATH
        pushd $UNIVERSAL_BUILD_PATH
            zip -r $OUTPUT_DIR/libvcx-ios-${LIBVCX_VERSION}-universal.zip ./*
        popd

        DEVICE_BUILD_PATH=$OUTPUT_DIR/device/vcx
        mkdir -p $DEVICE_BUILD_PATH
        cp -rvp vcx.framework $DEVICE_BUILD_PATH
        lipo -extract arm64 $DEVICE_BUILD_PATH/vcx.framework/vcx -o $DEVICE_BUILD_PATH/vcx.framework/vcx
        pushd $DEVICE_BUILD_PATH
            zip -r $OUTPUT_DIR/libvcx-ios-${LIBVCX_VERSION}-device.zip ./*
        popd

    popd
}

generate_flags() {
    if [ -z $1 ]; then
        echo "please provide the arch e.g. arm64 or x86_64"
        exit 1
    fi

    if [ $1 == "arm64" ]; then
        export TRIPLET="aarch64-apple-ios"
    elif [ $1 == "x86_64" ]; then
        export TRIPLET="x86_64-apple-ios"
    fi
}

abspath() {
    # generate absolute path from relative path
    # $1     : relative filename
    # return : absolute path
    if [ -d "$1" ]; then
        # dir
        (
            cd "$1"
            pwd
        )
    elif [ -f "$1" ]; then
        # file
        if [[ $1 = /* ]]; then
            echo "$1"
        elif [[ $1 == */* ]]; then
            echo "$(
                cd "${1%/*}"
                pwd
            )/${1##*/}"
        else
            echo "$(pwd)/$1"
        fi
    fi
}

# Setup environment
setup
 
# Build 3rd party libraries
build_crypto
build_libsodium
build_libzmq

# Extract architectures from fat files into non-fat files
extract_architectures $OUTPUT_DIR/libsodium-ios/dist/ios/lib/libsodium.a libsodium sodium
extract_architectures $OUTPUT_DIR/libzmq-ios/dist/ios/lib/libzmq.a libzmq zmq
extract_architectures $OUTPUT_DIR/OpenSSL-for-iPhone/lib/libssl.a libssl openssl
extract_architectures $OUTPUT_DIR/OpenSSL-for-iPhone/lib/libcrypto.a libcrypto openssl

# Build libindy
checkout_indy_sdk
build_libindy
copy_libindy_architectures

# Build vcx
build_libvcx
copy_libvcx_architectures

# Copy libraries to combine
copy_libs_to_combine

# Combine libs by arch and merge libs to single fat binary
combine_libs libvcx_all

# Build vcx.framework
build_vcx_framework libvcx_all
