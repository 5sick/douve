#include "cluster/files.h"
#include "testing.h"

using namespace douve;

TEST(files_paths_and_actions) {
    // agent/internal/files와 같은 규칙·문자열
    for (const char* bad : {"", "a\nb", "dir/", ".", "..", "a/..", "a/.", "~/x", "\x7f"})
        CHECK(!validTransferPath(bad));
    CHECK(!validTransferPath(std::string(5000, 'a')));
    for (const char* good : {"a.txt", "/tmp/x y", "../up.txt", "a~b", "한글.txt"})
        CHECK(validTransferPath(good));
    CHECK_EQ(filePutAction("ubuntu", 3, "ab", "/tmp/a:b"),
             std::string("file-put:ubuntu:3:ab:/tmp/a:b"));
    CHECK_EQ(fileGetAction("ubuntu", "x"), std::string("file-get:ubuntu:x"));
}
