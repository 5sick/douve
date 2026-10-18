#include "webauthn/cose.h"
#include "webauthn/cbor_guard.h"

#include "auth/jwt.h"

#include <cbor.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>

#include <memory>

namespace douve::webauthn {
namespace {

struct ItemDeleter {
    void operator()(cbor_item_t* p) const { cbor_decref(&p); }
};
using Item = std::unique_ptr<cbor_item_t, ItemDeleter>;

std::optional<std::int64_t> asInt(cbor_item_t* it) {
    if (cbor_isa_uint(it))
        return static_cast<std::int64_t>(cbor_get_int(it));
    if (cbor_isa_negint(it))
        return -1 - static_cast<std::int64_t>(cbor_get_int(it));
    return std::nullopt;
}

std::optional<Bytes> asBytes(cbor_item_t* it) {
    if (!cbor_isa_bytestring(it) || !cbor_bytestring_is_definite(it))
        return std::nullopt;
    auto* p = cbor_bytestring_handle(it);
    return Bytes(p, p + cbor_bytestring_length(it));
}

struct PkeyFree {
    void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); }
};
using Pkey = std::unique_ptr<EVP_PKEY, PkeyFree>;

Pkey p256PublicKey(const Bytes& x, const Bytes& y) {
    Bytes point{0x04};
    point.insert(point.end(), x.begin(), x.end());
    point.insert(point.end(), y.begin(), y.end());
    OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
    OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, "prime256v1", 0);
    OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, point.data(), point.size());
    OSSL_PARAM* params = OSSL_PARAM_BLD_to_param(bld);
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
    EVP_PKEY* key = nullptr;
    // fromdata는 점이 곡선 위에 있는지 검사한다 (잘못된 좌표면 실패)
    if (!params || !ctx || EVP_PKEY_fromdata_init(ctx) <= 0 ||
        EVP_PKEY_fromdata(ctx, &key, EVP_PKEY_PUBLIC_KEY, params) <= 0)
        key = nullptr;
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    return Pkey(key);
}

bool digestVerify(EVP_PKEY* key, const EVP_MD* md, const Bytes& msg, const Bytes& sig) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    bool ok = ctx && EVP_DigestVerifyInit(ctx, nullptr, md, nullptr, key) == 1 &&
              EVP_DigestVerify(ctx, sig.data(), sig.size(), msg.data(), msg.size()) == 1;
    EVP_MD_CTX_free(ctx);
    return ok;
}

} // namespace

std::optional<CoseKey> parseCoseKey(const std::uint8_t* data, std::size_t len,
                                    std::size_t* consumed, std::string& error) {
    if (!cborWithinBounds(data, len)) {
        error = "COSE 키 CBOR 오류";
        return std::nullopt;
    }
    cbor_load_result res{};
    Item root(cbor_load(data, len, &res));
    if (!root || res.error.code != CBOR_ERR_NONE || !cbor_isa_map(root.get()) ||
        !cbor_map_is_definite(root.get())) {
        error = "COSE 키 CBOR 오류";
        return std::nullopt;
    }
    if (consumed)
        *consumed = res.read;

    std::optional<std::int64_t> kty, alg, crv;
    std::optional<Bytes> m1, m2, m3; // -1, -2, -3 (키 종류에 따라 의미가 다름)
    auto* pairs = cbor_map_handle(root.get());
    for (std::size_t i = 0; i < cbor_map_size(root.get()); ++i) {
        auto k = asInt(pairs[i].key);
        if (!k)
            continue;
        switch (*k) {
        case 1:
            kty = asInt(pairs[i].value);
            break;
        case 3:
            alg = asInt(pairs[i].value);
            break;
        case -1:
            if (auto b = asBytes(pairs[i].value))
                m1 = b;
            else
                crv = asInt(pairs[i].value);
            break;
        case -2:
            m2 = asBytes(pairs[i].value);
            break;
        case -3:
            m3 = asBytes(pairs[i].value);
            break;
        default:
            break;
        }
    }
    CoseKey key;
    if (kty == 2 && alg == kAlgES256 && crv == 1 && m2 && m3 && m2->size() == 32 &&
        m3->size() == 32) {
        key.alg = kAlgES256;
        key.x = *m2;
        key.y = *m3;
    } else if (kty == 3 && alg == kAlgRS256 && m1 && m2 && m1->size() >= 256) {
        key.alg = kAlgRS256;
        key.n = *m1;
        key.e = *m2;
    } else if (kty == 1 && alg == kAlgEdDSA && crv == 6 && m2 && m2->size() == 32) {
        key.alg = kAlgEdDSA;
        key.x = *m2;
    } else {
        error = "지원하지 않는 공개키 형식";
        return std::nullopt;
    }
    return key;
}

bool verifySignature(const CoseKey& key, const Bytes& message, const Bytes& signature) {
    switch (key.alg) {
    case kAlgES256: {
        auto pk = p256PublicKey(key.x, key.y);
        return pk && digestVerify(pk.get(), EVP_sha256(), message, signature);
    }
    case kAlgRS256:
        return rsaSha256Verify(key.n, key.e, message.data(), message.size(), signature);
    case kAlgEdDSA: {
        Pkey pk(EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, key.x.data(), key.x.size()));
        return pk && digestVerify(pk.get(), nullptr, message, signature);
    }
    default:
        return false;
    }
}

} // namespace douve::webauthn
