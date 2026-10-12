#include "cluster/gateway.h"
#include "store/nodes.h"
#include "test_crypto.h"
#include "testing.h"
#include "util/crypto.h"

#include <openssl/evp.h>

using namespace douve;
using namespace douve::testing;

namespace {

Pkey genEd25519() {
    return Pkey(EVP_PKEY_Q_keygen(nullptr, nullptr, "ED25519"));
}

Bytes rawPub(EVP_PKEY* k) {
    Bytes out(32);
    std::size_t len = out.size();
    EVP_PKEY_get_raw_public_key(k, out.data(), &len);
    return out;
}

Bytes edSign(EVP_PKEY* k, const std::string& msg) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    Bytes sig(64);
    std::size_t len = sig.size();
    EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, k);
    EVP_DigestSign(ctx, sig.data(), &len, reinterpret_cast<const unsigned char*>(msg.data()),
                   msg.size());
    EVP_MD_CTX_free(ctx);
    return sig;
}

EnrollRequest req(const std::string& token, const Bytes& pub, const std::string& host = "web-1") {
    EnrollRequest r;
    r.token = token;
    r.pubkey = pub;
    r.hostname = host;
    r.os = "linux";
    r.arch = "arm64";
    r.ip = "10.0.0.5";
    return r;
}

} // namespace

TEST(ed25519_verify_accepts_valid_rejects_tampered) {
    auto k = genEd25519();
    const Bytes pub = rawPub(k.get());
    const std::string msg = agentAuthMessage("nonce123", 7);
    Bytes sig = edSign(k.get(), msg);
    CHECK(ed25519Verify(pub, msg, sig));
    CHECK(!ed25519Verify(pub, agentAuthMessage("nonce123", 8), sig)); // 다른 노드 ID
    CHECK(!ed25519Verify(pub, agentAuthMessage("nonce124", 7), sig)); // 다른 nonce
    sig[0] ^= 1;
    CHECK(!ed25519Verify(pub, msg, sig));
    CHECK(!ed25519Verify(Bytes(31), msg, sig)); // 길이 오류
    auto other = genEd25519();
    CHECK(!ed25519Verify(rawPub(other.get()), msg, edSign(k.get(), msg)));
}

TEST(join_token_single_use_and_expiry) {
    Database db(":memory:");
    auto t = createJoinToken(db, std::nullopt, "", 900, 1000);
    auto k1 = genEd25519();
    std::string err;
    auto n = enrollNode(db, req(t.token, rawPub(k1.get())), 1100, err);
    CHECK(n.has_value());
    CHECK_EQ(n->name, "web-1");
    // 재사용 거부
    auto k2 = genEd25519();
    CHECK(!enrollNode(db, req(t.token, rawPub(k2.get())), 1101, err).has_value());
    // 만료 거부
    auto t2 = createJoinToken(db, std::nullopt, "", 900, 1000);
    CHECK(!enrollNode(db, req(t2.token, rawPub(k2.get())), 1900, err).has_value());
    // 없는 토큰
    CHECK(!enrollNode(db, req("bogus", rawPub(k2.get())), 1100, err).has_value());
    // DB에는 평문 토큰이 없다
    Statement s(db, "SELECT count(*) FROM join_tokens WHERE token_hash = ?");
    s.bind(1, Bytes(t.token.begin(), t.token.end()));
    CHECK(s.step() && s.int64(0) == 0);
}

TEST(enroll_rejects_bad_or_duplicate_pubkey) {
    Database db(":memory:");
    std::string err;
    auto t = createJoinToken(db, std::nullopt, "", 900, 1000);
    CHECK(!enrollNode(db, req(t.token, Bytes(16)), 1001, err).has_value());
    auto k = genEd25519();
    CHECK(enrollNode(db, req(t.token, rawPub(k.get())), 1001, err).has_value());
    auto t2 = createJoinToken(db, std::nullopt, "", 900, 1000);
    CHECK(!enrollNode(db, req(t2.token, rawPub(k.get())), 1002, err).has_value());
    // 실패한 등록은 토큰을 소모하지 않는다
    auto k2 = genEd25519();
    CHECK(enrollNode(db, req(t2.token, rawPub(k2.get())), 1003, err).has_value());
}

TEST(enroll_names_from_token_or_hostname_dedupe) {
    Database db(":memory:");
    std::string err;
    auto t1 = createJoinToken(db, std::nullopt, "My Server", 900, 0);
    auto k1 = genEd25519();
    CHECK_EQ(enrollNode(db, req(t1.token, rawPub(k1.get())), 1, err)->name, "my-server");
    auto t2 = createJoinToken(db, std::nullopt, "", 900, 0);
    auto k2 = genEd25519();
    CHECK_EQ(enrollNode(db, req(t2.token, rawPub(k2.get()), "My_Server"), 1, err)->name,
             "my-server-2");
    CHECK_EQ(sanitizeNodeName("  --Node.01--  "), "node-01");
    CHECK_EQ(sanitizeNodeName("한글"), "");
    CHECK(renameNode(db, 1, "proxy"));
    CHECK(!renameNode(db, 2, "proxy")); // 중복
    CHECK(!renameNode(db, 2, "!!!"));
}

TEST(metrics_bucketed_query_and_purge) {
    Database db(":memory:");
    std::string err;
    auto t = createJoinToken(db, std::nullopt, "", 900, 0);
    auto k = genEd25519();
    auto n = enrollNode(db, req(t.token, rawPub(k.get())), 1, err);
    for (int i = 0; i < 10; ++i) {
        MetricRow m;
        m.ts = 6000 + i * 60;
        m.cpu = i * 10;
        m.memTotal = 100;
        m.memUsed = i;
        insertMetric(db, n->id, m);
    }
    auto rows = queryMetrics(db, n->id, 0, 300);
    CHECK_EQ(rows.size(), std::size_t{2});
    CHECK(rows[0].cpu > 19.9 && rows[0].cpu < 20.1); // (0+10+20+30+40)/5
    CHECK_EQ(queryMetrics(db, n->id, 6300, 60).size(), std::size_t{5});
    purgeMetrics(db, 6300);
    CHECK_EQ(queryMetrics(db, n->id, 0, 60).size(), std::size_t{5});
    // 노드 삭제 시 메트릭도 삭제
    CHECK(deleteNode(db, n->id));
    CHECK_EQ(queryMetrics(db, n->id, 0, 60).size(), std::size_t{0});
}

#include "cluster/release.h"

#include <filesystem>
#include <fstream>

TEST(agent_release_reads_version_and_sums) {
    auto dir = std::filesystem::temp_directory_path() / ("douve-rel-" + randomToken(6));
    std::filesystem::create_directories(dir);
    CHECK(!loadAgentRelease(dir.string()).has_value()); // 파일 없음
    std::ofstream(dir / "VERSION") << "v1.2.3\n";
    std::ofstream(dir / "SHA256SUMS") << std::string(64, 'a') << "  douve-agent-linux-amd64\n"
                                      << std::string(64, 'b') << "  douve-agent-linux-arm64\n"
                                      << "garbage line\n"
                                      << std::string(64, 'c') << "  ../../etc/passwd\n";
    auto r = loadAgentRelease(dir.string());
    CHECK(r.has_value());
    CHECK_EQ(r->version, "v1.2.3");
    CHECK_EQ(r->sha256.size(), std::size_t{2});
    CHECK_EQ(r->sha256["arm64"], std::string(64, 'b'));
    std::filesystem::remove_all(dir);
}
