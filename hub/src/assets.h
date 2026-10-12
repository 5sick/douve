#pragma once
// 바이너리에 내장된 웹 파일 (web/ 디렉터리, 빌드 시 cmake/embed.cmake가 생성)

#include <cstddef>
#include <string_view>

namespace douve::assets {

struct Asset {
    const char* name;
    const char* mime;
    const unsigned char* data;
    std::size_t size;
};

const Asset* find(std::string_view name);

} // namespace douve::assets
