#pragma once
// 테스트 전용 소프트웨어 인증기: 실제 패스키처럼 등록·인증 응답을 만든다.

#include "test_crypto.h"
#include "util/crypto.h"
#include "webauthn/webauthn.h"

#include <cbor.h>
#include <openssl/core_names.h>

#include <cstdlib>
#include <string>

namespace douve::testing {

inline cbor_item_t* cborInt(std::int64_t v) {
    if (v >= 0)
        return cbor_build_uint64(static_cast<std::uint64_t>(v));
    return cbor_build_negint64(static_cast<std::uint64_t>(-1 - v));
}

inline void put(cbor_item_t* map, cbor_item_t* k, cbor_item_t* v) {
    if (!cbor_map_add(map, cbor_pair{cbor_move(k), cbor_move(v)}))
        std::abort();
}

inline Bytes serialize(cbor_item_t* item) {
    unsigned char* buf = nullptr;
    std::size_t size = 0;
    std::size_t len = cbor_serialize_alloc(item, &buf, &size);
    Bytes out(buf, buf + len);
    std::free(buf);
    cbor_decref(&item);
    return out;
}

enum class KeyType { ES256, RS256, EdDSA };

struct SoftAuthenticator {
    KeyType type;
    Pkey key;
    Bytes credentialId = randomBytes(16);
    std::uint32_t counter = 0;
    bool countUp = true; // 동기화 패스키처럼 항상 0을 보내려면 false

    explicit SoftAuthenticator(KeyType t = KeyType::ES256) : type(t) {
        if (t == KeyType::ES256)
            key = genP256();
        else if (t == KeyType::RS256)
            key = genRsa();
        else
            key = Pkey(EVP_PKEY_Q_keygen(nullptr, nullptr, "ED25519"));
    }

    Bytes coseKey() const {
        cbor_item_t* m = cbor_new_definite_map(5);
        if (type == KeyType::ES256) {
            auto [x, y] = ecXY(key.get());
            put(m, cborInt(1), cborInt(2));
            put(m, cborInt(3), cborInt(-7));
            put(m, cborInt(-1), cborInt(1));
            put(m, cborInt(-2), cbor_build_bytestring(x.data(), x.size()));
            put(m, cborInt(-3), cbor_build_bytestring(y.data(), y.size()));
        } else if (type == KeyType::RS256) {
            auto n = bnParam(key.get(), OSSL_PKEY_PARAM_RSA_N),
                 e = bnParam(key.get(), OSSL_PKEY_PARAM_RSA_E);
            put(m, cborInt(1), cborInt(3));
            put(m, cborInt(3), cborInt(-257));
            put(m, cborInt(-1), cbor_build_bytestring(n.data(), n.size()));
            put(m, cborInt(-2), cbor_build_bytestring(e.data(), e.size()));
        } else {
            Bytes x(32);
            std::size_t len = 32;
            EVP_PKEY_get_raw_public_key(key.get(), x.data(), &len);
            put(m, cborInt(1), cborInt(1));
            put(m, cborInt(3), cborInt(-8));
            put(m, cborInt(-1), cborInt(6));
            put(m, cborInt(-2), cbor_build_bytestring(x.data(), x.size()));
        }
        return serialize(m);
    }

    static Bytes clientData(const std::string& type, const Bytes& challenge,
                            const std::string& origin, const std::string& extra = "") {
        return toBytes(R"({"type":")" + type + R"(","challenge":")" + base64UrlEncode(challenge) +
                       R"(","origin":")" + origin + R"(","crossOrigin":false)" + extra + "}");
    }

    Bytes authData(const std::string& rpId, std::uint8_t flags, bool withCredential) {
        Bytes ad = sha256(rpId);
        ad.push_back(flags);
        if (countUp)
            ++counter;
        for (int s = 24; s >= 0; s -= 8)
            ad.push_back(static_cast<std::uint8_t>(counter >> s));
        if (withCredential) {
            ad.insert(ad.end(), 16, 0); // aaguid
            ad.push_back(static_cast<std::uint8_t>(credentialId.size() >> 8));
            ad.push_back(static_cast<std::uint8_t>(credentialId.size()));
            ad.insert(ad.end(), credentialId.begin(), credentialId.end());
            auto ck = coseKey();
            ad.insert(ad.end(), ck.begin(), ck.end());
        }
        return ad;
    }

    struct Registration {
        Bytes clientDataJson, attestationObject;
    };
    Registration create(const Bytes& challenge, const std::string& origin, const std::string& rpId,
                        std::uint8_t flags = webauthn::kFlagUP | webauthn::kFlagUV |
                                             webauthn::kFlagAT) {
        auto ad = authData(rpId, flags, true);
        cbor_item_t* m = cbor_new_definite_map(3);
        put(m, cbor_build_string("fmt"), cbor_build_string("none"));
        put(m, cbor_build_string("attStmt"), cbor_new_definite_map(0));
        put(m, cbor_build_string("authData"), cbor_build_bytestring(ad.data(), ad.size()));
        return {clientData("webauthn.create", challenge, origin), serialize(m)};
    }

    struct Assertion {
        Bytes clientDataJson, authenticatorData, signature;
    };
    Assertion get(const Bytes& challenge, const std::string& origin, const std::string& rpId,
                  std::uint8_t flags = webauthn::kFlagUP | webauthn::kFlagUV) {
        Assertion a;
        a.clientDataJson = clientData("webauthn.get", challenge, origin);
        a.authenticatorData = authData(rpId, flags, false);
        Bytes msg = a.authenticatorData;
        auto h = sha256(a.clientDataJson);
        msg.insert(msg.end(), h.begin(), h.end());
        a.signature = signMessage(msg);
        return a;
    }

    Bytes signMessage(const Bytes& msg) const {
        if (type != KeyType::EdDSA)
            return sign(key.get(), msg);
        EVP_MD_CTX* md = EVP_MD_CTX_new();
        std::size_t len = 64;
        Bytes sig(len);
        EVP_DigestSignInit(md, nullptr, nullptr, nullptr, key.get());
        EVP_DigestSign(md, sig.data(), &len, msg.data(), msg.size());
        EVP_MD_CTX_free(md);
        sig.resize(len);
        return sig;
    }
};

} // namespace douve::testing
