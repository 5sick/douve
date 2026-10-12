#include "webauthn/webauthn.h"

#include "util/crypto.h"

#include <cbor.h>
#include <json/json.h>

#include <memory>
#include <sstream>

namespace douve::webauthn {
namespace {

struct ItemDeleter {
    void operator()(cbor_item_t* p) const { cbor_decref(&p); }
};
using Item = std::unique_ptr<cbor_item_t, ItemDeleter>;

// clientDataJSON 검증 (§7.1 단계 7~10, §7.2 단계 11~14)
bool checkClientData(const Bytes& raw, const char* expectedType, const Expectations& exp,
                     std::string& error) {
    Json::Value cd;
    Json::CharReaderBuilder b;
    std::string errs;
    std::istringstream in(toString(raw));
    if (raw.size() > 4096 || !Json::parseFromStream(b, in, &cd, &errs) || !cd.isObject()) {
        error = "clientDataJSON 형식 오류";
        return false;
    }
    if (cd.get("type", "").asString() != expectedType) {
        error = "clientData type 불일치";
        return false;
    }
    auto challenge = base64UrlDecode(cd.get("challenge", "").asString());
    if (!challenge || exp.challenge.empty() || !constantTimeEquals(*challenge, exp.challenge)) {
        error = "challenge 불일치";
        return false;
    }
    if (cd.get("origin", "").asString() != exp.origin) {
        error = "origin 불일치: " + cd.get("origin", "").asString();
        return false;
    }
    if (cd.get("crossOrigin", false).asBool()) {
        error = "crossOrigin 요청 거부";
        return false;
    }
    return true;
}

bool checkFlagsAndRp(const AuthData& ad, const Expectations& exp, std::string& error) {
    if (!constantTimeEquals(ad.rpIdHash, sha256(exp.rpId))) {
        error = "rpIdHash 불일치";
        return false;
    }
    if (!(ad.flags & kFlagUP)) {
        error = "사용자 존재(UP) 플래그 없음";
        return false;
    }
    if (exp.requireUserVerification && !(ad.flags & kFlagUV)) {
        error = "사용자 검증(UV) 플래그 없음";
        return false;
    }
    // BS(백업됨)는 BE(백업 가능) 없이 설정될 수 없다
    if ((ad.flags & kFlagBS) && !(ad.flags & kFlagBE)) {
        error = "잘못된 백업 플래그";
        return false;
    }
    return true;
}

} // namespace

std::optional<AuthData> parseAuthData(const Bytes& raw, std::string& error) {
    if (raw.size() < 37) {
        error = "authenticatorData가 너무 짧습니다";
        return std::nullopt;
    }
    AuthData ad;
    ad.rpIdHash.assign(raw.begin(), raw.begin() + 32);
    ad.flags = raw[32];
    ad.signCount = (std::uint32_t(raw[33]) << 24) | (std::uint32_t(raw[34]) << 16) |
                   (std::uint32_t(raw[35]) << 8) | raw[36];
    std::size_t pos = 37;
    if (ad.flags & kFlagAT) {
        if (raw.size() < pos + 18) {
            error = "attestedCredentialData가 잘렸습니다";
            return std::nullopt;
        }
        ad.aaguid.assign(raw.begin() + pos, raw.begin() + pos + 16);
        pos += 16;
        std::size_t idLen = (std::size_t(raw[pos]) << 8) | raw[pos + 1];
        pos += 2;
        if (idLen == 0 || idLen > 1023 || raw.size() < pos + idLen) {
            error = "credentialId 길이 오류";
            return std::nullopt;
        }
        ad.credentialId.assign(raw.begin() + pos, raw.begin() + pos + idLen);
        pos += idLen;
        std::size_t used = 0;
        ad.coseKey = parseCoseKey(raw.data() + pos, raw.size() - pos, &used, error);
        if (!ad.coseKey)
            return std::nullopt;
        ad.coseKeyBytes.assign(raw.begin() + pos, raw.begin() + pos + used);
        pos += used;
    }
    if (ad.flags & kFlagED) {
        cbor_load_result res{};
        Item ext(cbor_load(raw.data() + pos, raw.size() - pos, &res));
        if (!ext || res.error.code != CBOR_ERR_NONE || !cbor_isa_map(ext.get())) {
            error = "확장 데이터 CBOR 오류";
            return std::nullopt;
        }
        pos += res.read;
    }
    if (pos != raw.size()) {
        error = "authenticatorData 뒤에 남는 데이터";
        return std::nullopt;
    }
    return ad;
}

std::optional<NewCredential> verifyRegistration(const Bytes& clientDataJson,
                                                const Bytes& attestationObject,
                                                const Expectations& exp, std::string& error) {
    if (!checkClientData(clientDataJson, "webauthn.create", exp, error))
        return std::nullopt;

    cbor_load_result res{};
    Item root(cbor_load(attestationObject.data(), attestationObject.size(), &res));
    if (!root || res.error.code != CBOR_ERR_NONE || !cbor_isa_map(root.get())) {
        error = "attestationObject CBOR 오류";
        return std::nullopt;
    }
    std::optional<Bytes> authData;
    auto* pairs = cbor_map_handle(root.get());
    for (std::size_t i = 0; i < cbor_map_size(root.get()); ++i) {
        if (!cbor_isa_string(pairs[i].key) || !cbor_string_is_definite(pairs[i].key))
            continue;
        std::string key(reinterpret_cast<const char*>(cbor_string_handle(pairs[i].key)),
                        cbor_string_length(pairs[i].key));
        if (key == "authData" && cbor_isa_bytestring(pairs[i].value) &&
            cbor_bytestring_is_definite(pairs[i].value)) {
            auto* p = cbor_bytestring_handle(pairs[i].value);
            authData = Bytes(p, p + cbor_bytestring_length(pairs[i].value));
        }
    }
    if (!authData) {
        error = "authData 없음";
        return std::nullopt;
    }
    auto ad = parseAuthData(*authData, error);
    if (!ad)
        return std::nullopt;
    if (!checkFlagsAndRp(*ad, exp, error))
        return std::nullopt;
    if (!(ad->flags & kFlagAT) || !ad->coseKey) {
        error = "등록 응답에 공개키가 없습니다";
        return std::nullopt;
    }
    return NewCredential{ad->credentialId, ad->coseKeyBytes, ad->coseKey->alg, ad->signCount,
                         (ad->flags & kFlagBE) != 0};
}

std::optional<AssertionResult> verifyAssertion(const Bytes& clientDataJson,
                                               const Bytes& authenticatorData,
                                               const Bytes& signature, const Bytes& storedCoseKey,
                                               std::uint32_t storedSignCount,
                                               const Expectations& exp, std::string& error) {
    if (!checkClientData(clientDataJson, "webauthn.get", exp, error))
        return std::nullopt;
    auto ad = parseAuthData(authenticatorData, error);
    if (!ad)
        return std::nullopt;
    if (!checkFlagsAndRp(*ad, exp, error))
        return std::nullopt;
    if (ad->flags & kFlagAT) {
        error = "인증 응답에 예상치 않은 공개키";
        return std::nullopt;
    }
    auto key = parseCoseKey(storedCoseKey.data(), storedCoseKey.size(), nullptr, error);
    if (!key)
        return std::nullopt;

    Bytes signedData = authenticatorData;
    auto h = sha256(clientDataJson);
    signedData.insert(signedData.end(), h.begin(), h.end());
    if (!verifySignature(*key, signedData, signature)) {
        error = "서명 검증 실패";
        return std::nullopt;
    }
    if ((ad->signCount != 0 || storedSignCount != 0) && ad->signCount <= storedSignCount) {
        error = "서명 카운터가 증가하지 않음 (복제된 인증기 의심)";
        return std::nullopt;
    }
    return AssertionResult{ad->signCount};
}

} // namespace douve::webauthn
