#include "cluster/recording.h"
#include "testing.h"
#include "util/crypto.h"

#include <filesystem>
#include <fstream>
#include <sstream>

using namespace douve;

TEST(utf8_split_carries_partial_sequences) {
    std::string carry;
    const std::string han = "한"; // ED 95 9C
    CHECK_EQ(takeCompleteUtf8(carry, "ab" + han.substr(0, 1)), "ab");
    CHECK_EQ(carry.size(), std::size_t{1});
    CHECK_EQ(takeCompleteUtf8(carry, han.substr(1, 1)), "");
    CHECK_EQ(takeCompleteUtf8(carry, han.substr(2) + "c"), han + "c");
    CHECK(carry.empty());
    CHECK_EQ(takeCompleteUtf8(carry, "plain"), "plain");
    const std::string emoji = "😀"; // 4바이트
    CHECK_EQ(takeCompleteUtf8(carry, emoji.substr(0, 3)), "");
    CHECK_EQ(takeCompleteUtf8(carry, emoji.substr(3)), emoji);
}

TEST(recorder_writes_asciicast) {
    auto path = std::filesystem::temp_directory_path() / ("douve-rec-" + randomToken(6) + ".cast");
    {
        Recorder r(path.string(), 100, 30, 1700000000, "node2 ubuntu");
        CHECK(r.ok());
        r.output("hello \xED\x95", 0.5);
        r.output("\x9C\r\n", 0.75);
        r.resize(120, 40, 1.0);
    }
    std::ifstream in(path);
    std::string header, l1, l2;
    std::getline(in, header);
    std::getline(in, l1);
    std::getline(in, l2);
    CHECK(header.find("\"version\":2") != std::string::npos);
    CHECK(header.find("\"width\":100") != std::string::npos);
    CHECK(l1.find("hello ") != std::string::npos);
    CHECK(l2.find("한") != std::string::npos);
    std::filesystem::remove(path);
}
