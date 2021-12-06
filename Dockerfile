# Multistage docker build, requires docker 17.05

# TO RUN
# docker build -t oxen-daemon-image .

# TO COLLECT BINARIES
# ./util/build_scripts/collect_from_docker_container.sh

# builder stage
FROM ubuntu:16.04 as builder

RUN set -ex && \
    apt-get update && \
    apt-get install -y curl apt-transport-https eatmydata && \
    echo 'deb https://apt.kitware.com/ubuntu/ xenial main' >/etc/apt/sources.list.d/kitware-cmake.list && \
    curl https://apt.kitware.com/keys/kitware-archive-latest.asc | apt-key add - && \
    apt-get update && \
    eatmydata apt-get --no-install-recommends --yes install \
        ca-certificates \
        cmake \
        g++ \
        make \
        pkg-config \
        graphviz \
        doxygen \
        git \
        libtool-bin \
        autoconf \
        automake \
        bzip2 \
        xsltproc \
        gperf

WORKDIR /usr/local/src

ARG OPENSSL_VERSION=1.1.1g
ARG OPENSSL_HASH=ddb04774f1e32f0c49751e21b67216ac87852ceb056b75209af2443400636d46
RUN set -ex \
    && curl -s -O https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz \
    && echo "${OPENSSL_HASH}  openssl-${OPENSSL_VERSION}.tar.gz" | sha256sum -c \
    && tar xf openssl-${OPENSSL_VERSION}.tar.gz \
    && cd openssl-${OPENSSL_VERSION} \
    && ./Configure --prefix=/usr linux-x86_64 no-shared --static \
    && make -j$(nproc) \
    && make install_sw -j$(nproc)

ARG BOOST_VERSION=1_72_0
ARG BOOST_VERSION_DOT=1.72.0
ARG BOOST_HASH=59c9b274bc451cf91a9ba1dd2c7fdcaf5d60b1b3aa83f2c9fa143417cc660722
RUN set -ex \
    && curl -s -L -O  https://boostorg.jfrog.io/artifactory/main/release/${BOOST_VERSION_DOT}/source/boost_${BOOST_VERSION}.tar.bz2 \
    && tar xf boost_${BOOST_VERSION}.tar.bz2 \
    && cd boost_${BOOST_VERSION} \
    && ./bootstrap.sh \
    && ./b2 --prefix=/usr --build-type=minimal link=static runtime-link=static \
        --with-atomic --with-chrono --with-date_time --with-filesystem --with-program_options \
        --with-regex --with-serialization --with-system --with-thread --with-locale \
        threading=multi threadapi=pthread cxxflags=-fPIC \
        -j$(nproc) install

ARG SODIUM_VERSION=1.0.18-RELEASE
ARG SODIUM_HASH=940ef42797baa0278df6b7fd9e67c7590f87744b
RUN set -ex \
    && git clone https://github.com/jedisct1/libsodium.git -b ${SODIUM_VERSION} --depth=1 \
    && cd libsodium \
    && test `git rev-parse HEAD` = ${SODIUM_HASH} || exit 1 \
    && ./autogen.sh \
    && ./configure --enable-static --disable-shared --prefix=/usr \
    && make -j$(nproc) \
    && make check \
    && make install

# Readline
# ARG READLINE_VERSION=8.0
# ARG READLINE_HASH=e339f51971478d369f8a053a330a190781acb9864cf4c541060f12078948e461
# RUN set -ex \
#     && curl -s -O https://ftp.gnu.org/gnu/readline/readline-${READLINE_VERSION}.tar.gz \
#     && echo "${READLINE_HASH}  readline-${READLINE_VERSION}.tar.gz" | sha256sum -c \
#     && tar xf readline-${READLINE_VERSION}.tar.gz \
#     && cd readline-${READLINE_VERSION} \
#     && ./configure --prefix=/usr --disable-shared \
#     && make -j$(nproc) \
#     && make install

# Sqlite3
ARG SQLITE_VERSION=3310100
ARG SQLITE_HASH=62284efebc05a76f909c580ffa5c008a7d22a1287285d68b7825a2b6b51949ae
RUN set -ex \
    && curl -s -O https://sqlite.org/2020/sqlite-autoconf-${SQLITE_VERSION}.tar.gz \
    && echo "${SQLITE_HASH}  sqlite-autoconf-${SQLITE_VERSION}.tar.gz" | sha256sum -c \
    && tar xf sqlite-autoconf-${SQLITE_VERSION}.tar.gz \
    && cd sqlite-autoconf-${SQLITE_VERSION} \
    && ./configure --disable-shared --prefix=/usr --with-pic \
    && make -j$(nproc) \
    && make install

RUN set -ex \
    && apt install wget -y \
    && wget https://github.com/libexpat/libexpat/releases/download/R_2_3_0/expat-2.3.0.tar.gz \
    && tar xf expat-2.3.0.tar.gz \
    && cd expat-2.3.0 \
    && ./configure --enable-static --prefix=/usr && make && make install

RUN set -ex \
    && wget https://curl.se/download/curl-7.76.1.tar.gz \
    && tar xf curl-7.76.1.tar.gz \
    && cd curl-7.76.1 \
    && ./configure --with-openssl --enable-static --prefix=/usr && make && make install

RUN set -ex \
    && apt-get update -y \
    && apt install software-properties-common -y \
    && add-apt-repository ppa:ubuntu-toolchain-r/test \
    && apt-get update -y \
    && apt install gcc-7 g++-7 gcc-8 g++-8 gcc-9 g++-9 -y \
    && update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-9 90 --slave /usr/bin/g++ g++ /usr/bin/g++-9 --slave /usr/bin/gcov gcov /usr/bin/gcov-9 \
    && update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-8 80 --slave /usr/bin/g++ g++ /usr/bin/g++-8 --slave /usr/bin/gcov gcov /usr/bin/gcov-8 \
    && update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-7 70 --slave /usr/bin/g++ g++ /usr/bin/g++-7 --slave /usr/bin/gcov gcov /usr/bin/gcov-7 \
    && gcc --version

RUN set -ex \
    && apt install libevent-dev -y \
    && wget https://nlnetlabs.nl/downloads/unbound/unbound-1.13.1.tar.gz \
    && tar xf unbound-1.13.1.tar.gz \
    && cd unbound-1.13.1 \
     && ./configure --enable-static --disable-flto --prefix=/usr CFLAGS=-fPIC && make && make install

WORKDIR /src
COPY . .

RUN set -ex && \
    git submodule update --init --recursive && \
    rm -rf build/release && mkdir -p build/release && cd build/release && \
    cmake -DSTATIC=ON -DARCH=x86-64 -DCMAKE_BUILD_TYPE=Release ../.. && \
    make -j$(nproc) VERBOSE=1

RUN set -ex && \
    ldd /src/build/release/bin/oxend

# runtime stage
FROM ubuntu:16.04

RUN set -ex && \
    apt-get update && \
    apt-get --no-install-recommends --yes install ca-certificates && \
    apt-get clean && \
    rm -rf /var/lib/apt
COPY --from=builder /src/build/release/bin /usr/local/bin/

# Create oxen user
RUN adduser --system --group --disabled-password oxen && \
	mkdir -p /wallet /home/oxen/.oxen && \
	chown -R oxen:oxen /home/oxen/.oxen && \
	chown -R oxen:oxen /wallet

# Contains the blockchain
VOLUME /home/oxen/.oxen

# Generate your wallet via accessing the container and run:
# cd /wallet
# oxen-wallet-cli
VOLUME /wallet

EXPOSE 22022
EXPOSE 22023

# switch to user oxen
USER oxen

ENTRYPOINT ["oxend", "--p2p-bind-ip=0.0.0.0", "--p2p-bind-port=22022", "--rpc-bind-ip=0.0.0.0", "--rpc-bind-port=22023", "--non-interactive", "--confirm-external-bind"]
