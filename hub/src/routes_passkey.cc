// 패스키(WebAuthn) 로그인·등록·재인증 라우트.
// 흐름: options(챌린지 발급, pending에 저장) → 브라우저 navigator.credentials → verify(챌린지 1회
// 소모 후 검증)

#include "app.h"
#include "auth/redirect.h"
#include "http_util.h"
#include "store/invites.h"
#include "store/passkeys.h"
#include "store/repo.h"
#include "util/crypto.h"
#include "webauthn/webauthn.h"

#include <drogon/drogon.h>

namespace douve {

using drogon::HttpRequestPtr;
using drogon::HttpResponse;
using drogon::HttpResponsePtr;
using http::error;
using http::json;
using Callback = std::function<void(const HttpResponsePtr&)>;

namespace {

constexpr int kChallengeTtl = 300;
constexpr int kTimeoutMs = 120000;

// 사용자 핸들: 개인정보가 없는 고정 값 (userId에서 유도)
Bytes userHandle(std::int64_t userId) {
    auto h = sha256("douve-user:" + std::to_string(userId));
    return Bytes(h.begin(), h.begin() + 16);
}

std::optional<Bytes> b64(const Json::Value& v) {
    if (!v.isString())
        return std::nullopt;
    return base64UrlDecode(v.asString());
}

std::string newChallenge(Database& db, const std::string& purpose,
                         std::optional<std::int64_t> userId, const std::string& rd,
                         std::int64_t now, Bytes& challengeOut) {
    challengeOut = randomBytes(32);
    Json::Value p;
    p["challenge"] = base64UrlEncode(challengeOut);
    p["purpose"] = purpose;
    if (userId)
        p["user_id"] = Json::Int64(*userId);
    p["rd"] = rd;
    return putPending(db, "webauthn", p.toStyledString(), kChallengeTtl, now);
}

std::optional<Json::Value> takeChallenge(Database& db, const std::string& id,
                                         const std::string& purpose, std::int64_t now) {
    auto payload = takePending(db, id, "webauthn", now);
    if (!payload)
        return std::nullopt;
    Json::Value p;
    if (!Json::Reader().parse(*payload, p) || p["purpose"].asString() != purpose)
        return std::nullopt;
    return p;
}

Json::Value credentialDescriptors(const std::vector<Passkey>& keys) {
    Json::Value arr(Json::arrayValue);
    for (const auto& k : keys) {
        Json::Value d;
        d["type"] = "public-key";
        d["id"] = base64UrlEncode(k.credentialId);
        arr.append(d);
    }
    return arr;
}

// 등록용 publicKey 옵션 (로그인 사용자 등록·초대 수락 공통)
Json::Value registrationOptions(const HubConfig& cfg, std::int64_t userId, const std::string& email,
                                const Bytes& challenge, const std::vector<Passkey>& existing) {
    Json::Value pk;
    pk["challenge"] = base64UrlEncode(challenge);
    pk["rp"]["id"] = cfg.effectiveRpId();
    pk["rp"]["name"] = cfg.rpName;
    pk["user"]["id"] = base64UrlEncode(userHandle(userId));
    pk["user"]["name"] = email;
    pk["user"]["displayName"] = email;
    for (int alg : {webauthn::kAlgES256, webauthn::kAlgEdDSA, webauthn::kAlgRS256}) {
        Json::Value p;
        p["type"] = "public-key";
        p["alg"] = alg;
        pk["pubKeyCredParams"].append(p);
    }
    pk["timeout"] = kTimeoutMs;
    pk["attestation"] = "none";
    pk["authenticatorSelection"]["residentKey"] = "required";
    pk["authenticatorSelection"]["requireResidentKey"] = true;
    pk["authenticatorSelection"]["userVerification"] = "required";
    pk["excludeCredentials"] = credentialDescriptors(existing);
    return pk;
}

std::string transportsOf(const Json::Value& resp) {
    std::string transports;
    for (const auto& tr : resp["transports"]) {
        auto v = tr.asString();
        if (v.size() < 16 && v.find(',') == std::string::npos)
            transports += (transports.empty() ? "" : ",") + v;
    }
    return transports;
}

} // namespace

void HubApp::registerPasskeyRoutes() {
    auto& app = drogon::app();

    // ---- 로그인 (아이디 입력 없이 패스키만으로: discoverable credential) ----
    app.registerHandler(
        "/auth/passkey/login/options",
        [this](const HttpRequestPtr& req, Callback&& cb) {
            if (!loginAllowed(req))
                return cb(http::error(drogon::k429TooManyRequests,
                                      "요청이 너무 많습니다. 잠시 후 다시 시도하세요"));
            if (!sameOrigin(req))
                return cb(error(drogon::k403Forbidden, "잘못된 요청 출처"));
            const auto t = now();
            purgeExpiredPending(*db_, t);
            auto body = req->getJsonObject();
            const std::string rd =
                safeRedirect(body ? (*body).get("rd", "").asString() : "", cfg_, "/");
            Bytes ch;
            Json::Value v;
            v["pending"] = newChallenge(*db_, "login", std::nullopt, rd, t, ch);
            auto& pk = v["publicKey"];
            pk["challenge"] = base64UrlEncode(ch);
            pk["rpId"] = cfg_.effectiveRpId();
            pk["timeout"] = kTimeoutMs;
            pk["userVerification"] = "required";
            pk["allowCredentials"] = Json::Value(Json::arrayValue);
            cb(json(v));
        },
        {drogon::Post});

    app.registerHandler(
        "/auth/passkey/login/verify",
        [this](const HttpRequestPtr& req, Callback&& cb) {
            if (!loginAllowed(req))
                return cb(http::error(drogon::k429TooManyRequests,
                                      "요청이 너무 많습니다. 잠시 후 다시 시도하세요"));
            if (!sameOrigin(req))
                return cb(error(drogon::k403Forbidden, "잘못된 요청 출처"));
            const auto t = now();
            const std::string ip = clientIp(req);
            auto body = req->getJsonObject();
            if (!body)
                return cb(error(drogon::k400BadRequest, "잘못된 요청"));
            auto p = takeChallenge(*db_, (*body).get("pending", "").asString(), "login", t);
            if (!p)
                return cb(error(drogon::k400BadRequest,
                                "만료되었거나 이미 사용된 요청입니다. 다시 시도하세요"));
            const auto& cred = (*body)["credential"];
            const auto& resp = cred["response"];
            auto credId = b64(cred["id"]);
            auto clientData = b64(resp["clientDataJSON"]);
            auto authData = b64(resp["authenticatorData"]);
            auto sig = b64(resp["signature"]);
            if (!credId || !clientData || !authData || !sig)
                return cb(error(drogon::k400BadRequest, "잘못된 응답 형식"));

            auto key = findPasskeyByCredentialId(*db_, *credId);
            if (!key) {
                audit(*db_, std::nullopt, "login_failed", ip, "passkey: 등록되지 않은 패스키", t);
                return cb(error(drogon::k401Unauthorized, "등록되지 않은 패스키입니다"));
            }
            if (resp.isMember("userHandle") && !resp["userHandle"].isNull()) {
                auto uh = b64(resp["userHandle"]);
                if (!uh || !constantTimeEquals(*uh, userHandle(key->userId))) {
                    audit(*db_, key->userId, "login_failed", ip, "passkey: userHandle 불일치", t);
                    return cb(error(drogon::k401Unauthorized, "패스키 확인 실패"));
                }
            }
            webauthn::Expectations exp{*base64UrlDecode((*p)["challenge"].asString()),
                                       cfg_.origin(), cfg_.effectiveRpId(), true};
            std::string err;
            auto res = webauthn::verifyAssertion(*clientData, *authData, *sig, key->publicKeyCose,
                                                 key->signCount, exp, err);
            if (!res) {
                audit(*db_, key->userId, "login_failed", ip, "passkey: " + err, t);
                return cb(error(drogon::k401Unauthorized, "패스키 확인 실패"));
            }
            auto user = findUserById(*db_, key->userId);
            // 허용 목록에서 빠진 사용자는 패스키가 있어도 로그인 불가
            if (!user || !emailAllowed(user->email)) {
                audit(*db_, key->userId, "login_denied", ip, "passkey: 허용 목록에 없음", t);
                return cb(error(drogon::k403Forbidden, "로그인이 허용되지 않은 계정입니다"));
            }
            updatePasskeyUse(*db_, key->id, res->signCount, t);
            // fetch로 호출되므로 리다이렉트 대신 JSON으로 다음 주소를 알려준다
            Json::Value v;
            v["redirect"] = (*p)["rd"].asString();
            auto r = json(v);
            startSession(req, r, user->id, "passkey");
            cb(r);
        },
        {drogon::Post});

    // ---- 등록 (로그인한 상태에서만, 기존 패스키가 있으면 재인증 필요) ----
    app.registerHandler("/auth/passkey/register/options",
                        [this](const HttpRequestPtr& req, Callback&& cb) {
                            if (!sameOrigin(req))
                                return cb(error(drogon::k403Forbidden, "잘못된 요청 출처"));
                            const auto t = now();
                            auto s = currentSession(req, t);
                            if (!s)
                                return cb(error(drogon::k401Unauthorized, "로그인이 필요합니다"));
                            auto existing = listPasskeys(*db_, s->userId);
                            if (!existing.empty() && !sessions_->reauthFresh(*s, t))
                                return cb(error(drogon::k403Forbidden, "reauth_required"));
                            Bytes ch;
                            Json::Value v;
                            v["pending"] = newChallenge(*db_, "register", s->userId, "", t, ch);
                            auto& pk = v["publicKey"];
                            pk["challenge"] = base64UrlEncode(ch);
                            pk["rp"]["id"] = cfg_.effectiveRpId();
                            pk["rp"]["name"] = cfg_.rpName;
                            pk["user"]["id"] = base64UrlEncode(userHandle(s->userId));
                            pk["user"]["name"] = s->email;
                            pk["user"]["displayName"] = s->email;
                            for (int alg :
                                 {webauthn::kAlgES256, webauthn::kAlgEdDSA, webauthn::kAlgRS256}) {
                                Json::Value p;
                                p["type"] = "public-key";
                                p["alg"] = alg;
                                pk["pubKeyCredParams"].append(p);
                            }
                            pk["timeout"] = kTimeoutMs;
                            pk["attestation"] = "none";
                            pk["authenticatorSelection"]["residentKey"] = "required";
                            pk["authenticatorSelection"]["requireResidentKey"] = true;
                            pk["authenticatorSelection"]["userVerification"] = "required";
                            pk["excludeCredentials"] = credentialDescriptors(existing);
                            cb(json(v));
                        },
                        {drogon::Post});

    app.registerHandler(
        "/auth/passkey/register/verify",
        [this](const HttpRequestPtr& req, Callback&& cb) {
            if (!sameOrigin(req))
                return cb(error(drogon::k403Forbidden, "잘못된 요청 출처"));
            const auto t = now();
            auto s = currentSession(req, t);
            if (!s)
                return cb(error(drogon::k401Unauthorized, "로그인이 필요합니다"));
            auto body = req->getJsonObject();
            if (!body)
                return cb(error(drogon::k400BadRequest, "잘못된 요청"));
            auto p = takeChallenge(*db_, (*body).get("pending", "").asString(), "register", t);
            if (!p || (*p)["user_id"].asInt64() != s->userId)
                return cb(error(drogon::k400BadRequest,
                                "만료되었거나 이미 사용된 요청입니다. 다시 시도하세요"));
            const auto& resp = (*body)["credential"]["response"];
            auto clientData = b64(resp["clientDataJSON"]);
            auto attObj = b64(resp["attestationObject"]);
            if (!clientData || !attObj)
                return cb(error(drogon::k400BadRequest, "잘못된 응답 형식"));
            webauthn::Expectations exp{*base64UrlDecode((*p)["challenge"].asString()),
                                       cfg_.origin(), cfg_.effectiveRpId(), true};
            std::string err;
            auto cred = webauthn::verifyRegistration(*clientData, *attObj, exp, err);
            if (!cred) {
                audit(*db_, s->userId, "passkey_register_failed", clientIp(req), err, t);
                return cb(error(drogon::k400BadRequest, "패스키 등록 실패: " + err));
            }
            std::string transports;
            for (const auto& tr : resp["transports"]) {
                auto v = tr.asString();
                if (v.size() < 16 && v.find(',') == std::string::npos)
                    transports += (transports.empty() ? "" : ",") + v;
            }
            std::string name = (*body).get("name", "").asString().substr(0, 60);
            if (name.empty())
                name = "패스키 " + std::to_string(listPasskeys(*db_, s->userId).size() + 1);
            Passkey pk{0,
                       s->userId,
                       cred->credentialId,
                       cred->coseKeyBytes,
                       cred->signCount,
                       name,
                       transports,
                       t,
                       std::nullopt};
            if (!insertPasskey(*db_, pk))
                return cb(error(drogon::k409Conflict, "이미 등록된 패스키입니다"));
            if (auto tok = sessionToken(req))
                sessions_->markReauth(*tok, t);
            audit(*db_, s->userId, "passkey_registered", clientIp(req), name, t);
            Json::Value v;
            v["ok"] = true;
            v["name"] = name;
            cb(json(v));
        },
        {drogon::Post});

    // ---- 초대 수락 (로그인 없이, 1회용 초대 토큰으로 첫 패스키 등록 → 사용자 허용 + 로그인) ----
    app.registerHandler(
        "/auth/invite/options",
        [this](const HttpRequestPtr& req, Callback&& cb) {
            if (!sameOrigin(req))
                return cb(error(drogon::k403Forbidden, "잘못된 요청 출처"));
            if (!loginAllowed(req))
                return cb(error(drogon::k429TooManyRequests, "요청이 너무 많습니다"));
            const auto t = now();
            auto body = req->getJsonObject();
            const std::string token = body ? (*body).get("token", "").asString() : "";
            auto email = peekInvite(*db_, token, t);
            if (!email) {
                audit(*db_, std::nullopt, "invite_invalid", clientIp(req), "", t);
                return cb(error(drogon::k404NotFound,
                                "초대 링크가 없거나 만료되었거나 이미 사용되었습니다"));
            }
            auto user = findOrCreateUser(*db_, *email, t);
            Bytes ch;
            Json::Value v;
            v["pending"] = newChallenge(*db_, "invite", user.id, toHex(sha256(token)), t, ch);
            v["email"] = *email;
            v["publicKey"] =
                registrationOptions(cfg_, user.id, *email, ch, listPasskeys(*db_, user.id));
            cb(json(v));
        },
        {drogon::Post});

    app.registerHandler(
        "/auth/invite/verify",
        [this](const HttpRequestPtr& req, Callback&& cb) {
            if (!sameOrigin(req))
                return cb(error(drogon::k403Forbidden, "잘못된 요청 출처"));
            if (!loginAllowed(req))
                return cb(error(drogon::k429TooManyRequests, "요청이 너무 많습니다"));
            const auto t = now();
            auto body = req->getJsonObject();
            if (!body)
                return cb(error(drogon::k400BadRequest, "잘못된 요청"));
            const std::string token = (*body).get("token", "").asString();
            auto p = takeChallenge(*db_, (*body).get("pending", "").asString(), "invite", t);
            // 챌린지는 이 초대 토큰으로 발급된 것이어야 한다 (rd 칸에 토큰 해시를 저장)
            if (!p || (*p)["rd"].asString() != toHex(sha256(token)))
                return cb(error(drogon::k400BadRequest,
                                "만료되었거나 이미 사용된 요청입니다. 링크를 다시 여세요"));
            const std::int64_t userId = (*p)["user_id"].asInt64();
            auto user = findUserById(*db_, userId);
            const auto& resp = (*body)["credential"]["response"];
            auto clientData = b64(resp["clientDataJSON"]);
            auto attObj = b64(resp["attestationObject"]);
            if (!user || !clientData || !attObj)
                return cb(error(drogon::k400BadRequest, "잘못된 응답 형식"));
            webauthn::Expectations exp{*base64UrlDecode((*p)["challenge"].asString()),
                                       cfg_.origin(), cfg_.effectiveRpId(), true};
            std::string err;
            auto cred = webauthn::verifyRegistration(*clientData, *attObj, exp, err);
            if (!cred) {
                audit(*db_, userId, "passkey_register_failed", clientIp(req), "invite: " + err, t);
                return cb(error(drogon::k400BadRequest, "패스키 등록 실패: " + err));
            }
            if (!consumeInvite(*db_, token, t))
                return cb(
                    error(drogon::k409Conflict, "초대 링크가 이미 사용되었거나 만료되었습니다"));
            std::string name = (*body).get("name", "").asString().substr(0, 60);
            if (name.empty())
                name = "패스키 " + std::to_string(listPasskeys(*db_, userId).size() + 1);
            Passkey pk{0,
                       userId,
                       cred->credentialId,
                       cred->coseKeyBytes,
                       cred->signCount,
                       name,
                       transportsOf(resp),
                       t,
                       std::nullopt};
            if (!insertPasskey(*db_, pk))
                return cb(error(drogon::k409Conflict, "이미 등록된 패스키입니다"));
            setUserAllowed(*db_, userId, true);
            audit(*db_, userId, "invite_accepted", clientIp(req), user->email + " " + name, t);
            Json::Value v;
            v["ok"] = true;
            auto r = json(v);
            startSession(req, r, userId, "passkey");
            cb(r);
        },
        {drogon::Post});

    // ---- 재인증 (민감한 작업 전, 내 패스키 중 하나로) ----
    app.registerHandler("/auth/passkey/reauth/options",
                        [this](const HttpRequestPtr& req, Callback&& cb) {
                            if (!sameOrigin(req))
                                return cb(error(drogon::k403Forbidden, "잘못된 요청 출처"));
                            const auto t = now();
                            auto s = currentSession(req, t);
                            if (!s)
                                return cb(error(drogon::k401Unauthorized, "로그인이 필요합니다"));
                            auto keys = listPasskeys(*db_, s->userId);
                            if (keys.empty())
                                return cb(error(drogon::k409Conflict, "등록된 패스키가 없습니다"));
                            Bytes ch;
                            Json::Value v;
                            v["pending"] = newChallenge(*db_, "reauth", s->userId, "", t, ch);
                            auto& pk = v["publicKey"];
                            pk["challenge"] = base64UrlEncode(ch);
                            pk["rpId"] = cfg_.effectiveRpId();
                            pk["timeout"] = kTimeoutMs;
                            pk["userVerification"] = "required";
                            pk["allowCredentials"] = credentialDescriptors(keys);
                            cb(json(v));
                        },
                        {drogon::Post});

    app.registerHandler(
        "/auth/passkey/reauth/verify",
        [this](const HttpRequestPtr& req, Callback&& cb) {
            if (!loginAllowed(req))
                return cb(http::error(drogon::k429TooManyRequests,
                                      "요청이 너무 많습니다. 잠시 후 다시 시도하세요"));
            if (!sameOrigin(req))
                return cb(error(drogon::k403Forbidden, "잘못된 요청 출처"));
            const auto t = now();
            auto s = currentSession(req, t);
            if (!s)
                return cb(error(drogon::k401Unauthorized, "로그인이 필요합니다"));
            auto body = req->getJsonObject();
            if (!body)
                return cb(error(drogon::k400BadRequest, "잘못된 요청"));
            auto p = takeChallenge(*db_, (*body).get("pending", "").asString(), "reauth", t);
            if (!p || (*p)["user_id"].asInt64() != s->userId)
                return cb(error(drogon::k400BadRequest, "만료된 요청입니다"));
            const auto& cred = (*body)["credential"];
            const auto& resp = cred["response"];
            auto credId = b64(cred["id"]);
            auto clientData = b64(resp["clientDataJSON"]);
            auto authData = b64(resp["authenticatorData"]);
            auto sig = b64(resp["signature"]);
            if (!credId || !clientData || !authData || !sig)
                return cb(error(drogon::k400BadRequest, "잘못된 응답 형식"));
            auto key = findPasskeyByCredentialId(*db_, *credId);
            if (!key || key->userId != s->userId)
                return cb(error(drogon::k401Unauthorized, "내 패스키가 아닙니다"));
            webauthn::Expectations exp{*base64UrlDecode((*p)["challenge"].asString()),
                                       cfg_.origin(), cfg_.effectiveRpId(), true};
            std::string err;
            auto res = webauthn::verifyAssertion(*clientData, *authData, *sig, key->publicKeyCose,
                                                 key->signCount, exp, err);
            if (!res) {
                audit(*db_, s->userId, "reauth_failed", clientIp(req), err, t);
                return cb(error(drogon::k401Unauthorized, "패스키 확인 실패"));
            }
            updatePasskeyUse(*db_, key->id, res->signCount, t);
            sessions_->markReauth(*sessionToken(req), t);
            audit(*db_, s->userId, "reauth", clientIp(req), key->name, t);
            Json::Value v;
            v["ok"] = true;
            cb(json(v));
        },
        {drogon::Post});
}

} // namespace douve
