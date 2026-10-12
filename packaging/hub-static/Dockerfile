# 배포판과 무관하게 실행되는 douve-hub 정적 바이너리 (musl, 의존 라이브러리 전부 포함).
#   docker build -f packaging/hub-static/Dockerfile -o dist .
# 결과: dist/douve-hub-linux-<arch>
FROM alpine:3.22 AS deps
RUN apk add --no-cache build-base cmake ninja git pkgconf linux-headers perl \
        openssl-dev openssl-libs-static zlib-dev zlib-static sqlite-dev sqlite-static \
        util-linux-dev util-linux-static
ARG PREFIX=/opt/deps
ENV CMAKE_PREFIX_PATH=${PREFIX} PKG_CONFIG_PATH=${PREFIX}/lib/pkgconfig
WORKDIR /src

# jsoncpp
RUN git clone --depth 1 --branch 1.9.6 https://github.com/open-source-parsers/jsoncpp.git && \
    cmake -S jsoncpp -B jsoncpp/b -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=${PREFIX} \
      -DBUILD_SHARED_LIBS=OFF -DBUILD_STATIC_LIBS=ON -DBUILD_OBJECT_LIBS=OFF \
      -DJSONCPP_WITH_TESTS=OFF -DJSONCPP_WITH_POST_BUILD_UNITTEST=OFF && \
    cmake --build jsoncpp/b && cmake --install jsoncpp/b

# libcbor
RUN git clone --depth 1 --branch v0.12.0 https://github.com/PJK/libcbor.git && \
    cmake -S libcbor -B libcbor/b -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=${PREFIX} \
      -DBUILD_SHARED_LIBS=OFF -DWITH_EXAMPLES=OFF && \
    cmake --build libcbor/b && cmake --install libcbor/b

# curl: OpenSSL만 쓰는 최소 구성 (Google·텔레그램 HTTPS 요청용)
RUN git clone --depth 1 --branch curl-8_15_0 https://github.com/curl/curl.git && \
    cmake -S curl -B curl/b -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=${PREFIX} \
      -DBUILD_SHARED_LIBS=OFF -DBUILD_STATIC_LIBS=ON -DBUILD_CURL_EXE=OFF -DBUILD_TESTING=OFF \
      -DCURL_USE_OPENSSL=ON -DCURL_USE_LIBPSL=OFF -DCURL_USE_LIBSSH2=OFF -DCURL_BROTLI=OFF -DCURL_ZSTD=OFF \
      -DUSE_NGHTTP2=OFF -DUSE_LIBIDN2=OFF -DCURL_DISABLE_LDAP=ON -DENABLE_ARES=OFF -DCURL_CA_FALLBACK=ON && \
    cmake --build curl/b && cmake --install curl/b

# Drogon (+trantor): 서버 기능만. ORM·DB 드라이버·Redis·brotli·c-ares 없음
RUN git clone --depth 1 --branch v1.9.11 --recurse-submodules --shallow-submodules https://github.com/drogonframework/drogon.git && \
    cmake -S drogon -B drogon/b -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=${PREFIX} \
      -DBUILD_SHARED_LIBS=OFF -DBUILD_CTL=OFF -DBUILD_EXAMPLES=OFF -DBUILD_ORM=OFF -DBUILD_TESTING=OFF \
      -DBUILD_POSTGRESQL=OFF -DBUILD_MYSQL=OFF -DBUILD_SQLITE=OFF -DBUILD_REDIS=OFF -DBUILD_BROTLI=OFF \
      -DBUILD_YAML_CONFIG=OFF -DUSE_SUBMODULE=ON && \
    cmake --build drogon/b && cmake --install drogon/b

FROM deps AS build
ARG VERSION=0.0.0-dev
COPY hub /src/douve/hub
COPY web /src/douve/web
RUN cmake -S /src/douve/hub -B /src/douve/b -G Ninja -DCMAKE_BUILD_TYPE=Release -DDOUVE_STATIC=ON \
      -DDOUVE_BUILD_TESTS=OFF -DDOUVE_VERSION=${VERSION} && \
    cmake --build /src/douve/b --target douve-hub && \
    strip /src/douve/b/douve-hub && \
    file /src/douve/b/douve-hub && /src/douve/b/douve-hub --version && \
    mkdir /out && cp /src/douve/b/douve-hub /out/douve-hub-linux-$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')

# 정적 바이너리에 함께 들어간 라이브러리의 라이선스 고지 (릴리스에 같이 배포)
RUN apk add --no-cache curl musl-dev && cd /src && { \
      echo "Third-party software statically linked into douve-hub"; echo; \
      for c in "jsoncpp 1.9.6|MIT / Public Domain|jsoncpp/LICENSE" \
               "libcbor 0.12.0|MIT|libcbor/LICENSE.md" \
               "curl 8.15.0|curl (MIT-style)|curl/COPYING" \
               "Drogon 1.9.11|MIT|drogon/LICENSE" \
               "trantor (Drogon submodule)|BSD-3-Clause|drogon/trantor/License"; do \
        n=${c%%|*}; r=${c#*|}; l=${r%%|*}; f=${r#*|}; \
        echo "================================================================"; echo "$n — $l"; echo; cat "$f"; echo; \
      done; \
      echo "================================================================"; echo "OpenSSL ($(apk list -I openssl-libs-static 2>/dev/null | awk '{print $1}')) — Apache-2.0"; echo; \
      curl -fsSL https://www.apache.org/licenses/LICENSE-2.0.txt; echo; \
      echo "================================================================"; echo "zlib — zlib License"; echo; \
      sed -n '/^  Copyright/,/^\*\//p' /usr/include/zlib.h; echo; \
      echo "================================================================"; echo "SQLite — Public Domain"; echo; \
      echo "The author disclaims copyright to this source code. In place of a legal notice, here is a blessing: May you do good and not evil."; echo; \
      echo "================================================================"; echo "libuuid (util-linux) — BSD-3-Clause"; echo; \
      curl -fsSL https://raw.githubusercontent.com/util-linux/util-linux/master/Documentation/licenses/COPYING.BSD-3-Clause; echo; \
      echo "================================================================"; echo "musl libc — MIT"; echo; \
      curl -fsSL "https://git.musl-libc.org/cgit/musl/plain/COPYRIGHT"; echo; \
      echo "================================================================"; echo "Web UI components (embedded)"; echo; \
      cat /src/douve/web/THIRD_PARTY_LICENSES.md; \
    } > /out/THIRD_PARTY_LICENSES-hub.txt && test -s /out/THIRD_PARTY_LICENSES-hub.txt

FROM scratch
COPY --from=build /out/ /
