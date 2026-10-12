cmake_minimum_required(VERSION 3.25)
project(douve-hub VERSION 0.0.1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif()

option(DOUVE_STATIC "배포용 정적 바이너리 (packaging/hub-static, Alpine/musl)" OFF)
option(DOUVE_BUILD_TESTS "단위 테스트 빌드" ON)
if(DOUVE_STATIC)
    # 모든 의존 라이브러리를 .a로 찾고 완전 정적 링크
    set(CMAKE_FIND_LIBRARY_SUFFIXES .a)
    set(OPENSSL_USE_STATIC_LIBS TRUE)
    add_link_options(-static)
endif()

find_package(Drogon CONFIG REQUIRED)

set(DOUVE_VERSION "${PROJECT_VERSION}" CACHE STRING "빌드 버전 (make가 git describe로 넣음)")
configure_file(src/version.h.in ${CMAKE_CURRENT_BINARY_DIR}/generated/version.h @ONLY)

find_package(OpenSSL REQUIRED)

find_package(PkgConfig REQUIRED)
pkg_check_modules(CBOR REQUIRED IMPORTED_TARGET libcbor)
pkg_check_modules(SQLITE REQUIRED IMPORTED_TARGET sqlite3)
pkg_check_modules(CURL REQUIRED IMPORTED_TARGET libcurl)

# 웹 UI 내장
set(DOUVE_WEB_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../web)
set(DOUVE_WEB_FILES home.html login.html account.html privacy.html invite.html dashboard.html node.html services.html settings.html security.html terminal.html app.js i18n.js i18n-en.json icons.js dashboard.js terminal.js xterm.js addon-fit.js xterm.css style.css join.sh favicon.svg favicon.ico apple-touch-icon.png icon-192.png icon-512.png icon-maskable-512.png manifest.webmanifest)
list(TRANSFORM DOUVE_WEB_FILES PREPEND ${DOUVE_WEB_DIR}/ OUTPUT_VARIABLE DOUVE_WEB_DEPS)
add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/generated/assets.cc
    COMMAND ${CMAKE_COMMAND} -DOUT=${CMAKE_CURRENT_BINARY_DIR}/generated/assets.cc -DBASE=${DOUVE_WEB_DIR}
            "-DFILES=${DOUVE_WEB_FILES}" -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/embed.cmake
    DEPENDS ${DOUVE_WEB_DEPS} ${CMAKE_CURRENT_SOURCE_DIR}/cmake/embed.cmake
    COMMENT "웹 UI 내장"
    VERBATIM)

add_library(douve_core STATIC
    ${CMAKE_CURRENT_BINARY_DIR}/generated/assets.cc
    src/options.cc
    src/config.cc
    src/util/encoding.cc
    src/util/crypto.cc
    src/store/db.cc
    src/store/repo.cc
    src/store/passkeys.cc
    src/auth/session.cc
    src/auth/redirect.cc
    src/auth/ratelimit.cc
    src/auth/jwt.cc
    src/auth/google.cc
    src/net/https_client.cc
    src/store/nodes.cc
    src/store/services.cc
    src/store/invites.cc
    src/store/recovery.cc
    src/store/backup.cc
    src/util/i18n.cc
    src/cluster/live.cc
    src/cluster/alerts.cc
    src/cluster/gateway.cc
    src/cluster/tasks.cc
    src/cluster/release.cc
    src/cluster/recording.cc
    src/cluster/terminal.cc
    src/cluster/security.cc
    src/routes_nodes.cc
    src/routes_services.cc
    src/routes_terminal.cc
    src/routes_settings.cc
    src/routes_security.cc
    src/routes_home.cc
    src/routes_expose.cc
    src/routes_portmap.cc
    src/routes_channels.cc
    src/cluster/channels.cc
    src/cluster/icons.cc
    src/cluster/apps.cc
    src/settings.cc
    src/cli_token.cc
    src/cli_service.cc
    src/cli_invite.cc
    src/cli_system.cc
    src/cli_recovery.cc
    src/webauthn/cose.cc
    src/webauthn/webauthn.cc
    src/init.cc
    src/app.cc
    src/routes_passkey.cc
    src/routes_account.cc
)
target_include_directories(douve_core PUBLIC src ${CMAKE_CURRENT_BINARY_DIR}/generated)
target_link_libraries(douve_core PUBLIC Drogon::Drogon OpenSSL::Crypto PkgConfig::SQLITE PkgConfig::CBOR PkgConfig::CURL)
if(DOUVE_STATIC)
    # 정적 libcurl의 의존성 (pkg-config Libs.private)
    find_package(ZLIB REQUIRED)
    target_link_libraries(douve_core PUBLIC OpenSSL::SSL OpenSSL::Crypto ZLIB::ZLIB pthread)
endif()
target_compile_options(douve_core PRIVATE -Wall -Wextra -Wpedantic)

add_executable(douve-hub src/main.cc)
target_link_libraries(douve-hub PRIVATE douve_core Drogon::Drogon)
target_compile_options(douve-hub PRIVATE -Wall -Wextra -Wpedantic)
install(TARGETS douve-hub RUNTIME DESTINATION bin)

if(NOT DOUVE_BUILD_TESTS)
    return()
endif()
enable_testing()
file(GLOB DOUVE_TEST_SOURCES CONFIGURE_DEPENDS tests/*_test.cc)
add_executable(douve_hub_tests tests/main.cc ${DOUVE_TEST_SOURCES})
target_include_directories(douve_hub_tests PRIVATE tests)
target_link_libraries(douve_hub_tests PRIVATE douve_core)
add_test(NAME unit COMMAND douve_hub_tests)
add_test(NAME cli_version COMMAND douve-hub --version)
set_tests_properties(cli_version PROPERTIES PASS_REGULAR_EXPRESSION "douve-hub ${DOUVE_VERSION}")
