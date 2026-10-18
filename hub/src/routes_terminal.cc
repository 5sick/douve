// 웹 터미널: 패스키 서명 → 1회용 티켓 발급, 터미널 신뢰 목록 승인, 녹화 목록·내려받기.

#include "app.h"
#include "cluster/gateway.h"
#include "cluster/term_trust.h"
#include "cluster/terminal.h"
#include "http_util.h"
#include "store/nodes.h"
#include "store/passkeys.h"
#include "store/repo.h"
#include "util/crypto.h"
#include "util/encoding.h"
#include "util/json.h"
#include "webauthn/webauthn.h"

#include <drogon/drogon.h>

#include <algorithm>
#include <filesystem>
#include <regex>
#include <sstream>

namespace douve {

using drogon::HttpRequestPtr;
using drogon::HttpResponse;
using drogon::HttpResponsePtr;
using http::error;
using http::json;
using Callback = std::function<void(const HttpResponsePtr&)>;

namespace {
const std::regex kRecName(R"(^(\d{8})-(\d{6})-([a-z0-9-]+)-([a-z0-9-]+)-([A-Za-z0-9_-]+)\.cast$)");
} // namespace

void HubApp::registerTerminalRoutes() {
    auto& app = drogon::app();
    terminal_ = std::make_shared<TerminalGateway>(*this);
    app.registerController(terminal_);

    // 1) 터미널 열기 요청: 서명할 문장(서버, 계정, 시각, 1회용 값)을 challenge로 돌려준다.
    //    Agent가 이 서명을 신뢰 목록으로 직접 확인하므로, 이 서버가 믿는 내 패스키만 고르게 한다.
    app.registerHandler(
        "/api/terminal/options",
        [this](const HttpRequestPtr& req, Callback&& cb) {
            if (!sameOrigin(req))
                return cb(error(drogon::k403Forbidden, "잘못된 요청 출처"));
            const auto t = now();
            auto s = currentSession(req, t);
            if (!s)
                return cb(error(drogon::k401Unauthorized, "로그인이 필요합니다"));
            if (!settings_.features().terminal)
                return cb(error(drogon::k403Forbidden, "웹 터미널이 꺼져 있습니다 (설정 → 기능)"));
            auto body = req->getJsonObject();
            if (!body)
                return cb(error(drogon::k400BadRequest, "JSON 본문이 필요합니다"));
            const std::int64_t nodeId = jsonInt(*body, "node_id");
            auto n = access(*s).node(nodeId) ? findNode(*db_, nodeId) : std::nullopt;
            if (!n)
                return cb(error(drogon::k404NotFound, "노드를 찾을 수 없습니다"));
            if (!live_.connected(n->id))
                return cb(error(drogon::k409Conflict, "서버가 Douve에 접속해 있지 않습니다"));
            const std::string user = (*body).get("user", "").asString();
            auto inv = live_.inventory(n->id);
            bool allowed = false;
            if (inv)
                for (const auto& u : (*inv)["terminal_users"])
                    allowed = allowed || u.asString() == user;
            if (!allowed)
                return cb(
                    error(drogon::k403Forbidden, "이 서버에서 터미널을 열 수 없는 계정입니다"));
            const auto trusted = trustKeyIds(trustState().snapshot, false, n->id);
            const auto mine = listPasskeys(*db_, s->userId);
            // Tailscale·Google로만 로그인한 사람: 터미널은 서버가 확인할 패스키 서명이 필요하다
            if (mine.empty())
                return cb(error(drogon::k409Conflict, "passkey_required"));
            Json::Value creds(Json::arrayValue);
            for (const auto& k : mine) {
                const auto id = base64UrlEncode(k.credentialId);
                if (!trusted.contains(id))
                    continue;
                Json::Value d;
                d["type"] = "public-key";
                d["id"] = id;
                creds.append(d);
            }
            if (creds.empty())
                return cb(error(drogon::k409Conflict, "term_trust_missing"));
            Json::Value p;
            p["node_id"] = Json::Int64(n->id);
            p["node_name"] = n->name;
            p["user"] = user;
            p["user_id"] = Json::Int64(s->userId);
            p["cols"] = std::clamp((*body).get("cols", 80).asInt(), 10, 1000);
            p["rows"] = std::clamp((*body).get("rows", 24).asInt(), 3, 500);
            p["ts"] = Json::Int64(t);
            p["nonce"] = randomToken(18);
            Json::StreamWriterBuilder w;
            w["indentation"] = "";
            Json::Value v;
            v["pending"] = putPending(*db_, "termauth", Json::writeString(w, p), 120, t);
            auto& pk = v["publicKey"];
            pk["challenge"] =
                base64UrlEncode(termOpenChallenge(n->id, user, t, p["nonce"].asString()));
            pk["rpId"] = cfg_.effectiveRpId();
            pk["timeout"] = 60000;
            pk["userVerification"] = "required";
            pk["allowCredentials"] = creds;
            cb(json(v));
        },
        {drogon::Post});

    // 2) 패스키 서명 확인 → 1회용 티켓. 서명은 티켓에 담겨 Agent에 그대로 전달된다.
    app.registerHandler(
        "/api/terminal/ticket",
        [this](const HttpRequestPtr& req, Callback&& cb) {
            if (!loginAllowed(req))
                return cb(error(drogon::k429TooManyRequests,
                                "요청이 너무 많습니다. 잠시 후 다시 시도하세요"));
            if (!sameOrigin(req))
                return cb(error(drogon::k403Forbidden, "잘못된 요청 출처"));
            const auto t = now();
            auto s = currentSession(req, t);
            if (!s)
                return cb(error(drogon::k401Unauthorized, "로그인이 필요합니다"));
            auto body = req->getJsonObject();
            if (!body)
                return cb(error(drogon::k400BadRequest, "JSON 본문이 필요합니다"));
            if (!settings_.features().terminal)
                return cb(error(drogon::k403Forbidden, "웹 터미널이 꺼져 있습니다 (설정 → 기능)"));
            auto payload = takePending(*db_, (*body).get("pending", "").asString(), "termauth", t);
            Json::Value p;
            if (!payload || !parseJson(*payload, p) || jsonInt(p, "user_id") != s->userId)
                return cb(error(drogon::k400BadRequest, "만료된 요청입니다. 다시 여세요"));
            if (!access(*s).node(jsonInt(p, "node_id")))
                return cb(error(drogon::k404NotFound, "노드를 찾을 수 없습니다"));
            const auto& cred = (*body)["credential"];
            const auto& resp = cred["response"];
            auto dec = [](const Json::Value& v) {
                return v.isString() ? base64UrlDecode(v.asString()) : std::nullopt;
            };
            auto credId = dec(cred["id"]);
            auto clientData = dec(resp["clientDataJSON"]);
            auto authData = dec(resp["authenticatorData"]);
            auto sig = dec(resp["signature"]);
            if (!credId || !clientData || !authData || !sig)
                return cb(error(drogon::k400BadRequest, "잘못된 응답 형식"));
            auto key = findPasskeyByCredentialId(*db_, *credId);
            if (!key || key->userId != s->userId)
                return cb(error(drogon::k401Unauthorized, "내 패스키가 아닙니다"));
            const std::int64_t nodeId = jsonInt(p, "node_id");
            const std::string nonce = jsonStr(p, "nonce");
            webauthn::Expectations exp{
                termOpenChallenge(nodeId, jsonStr(p, "user"), jsonInt(p, "ts"), nonce),
                cfg_.origin(), cfg_.effectiveRpId(), true};
            std::string err;
            auto res = webauthn::verifyAssertion(*clientData, *authData, *sig, key->publicKeyCose,
                                                 key->signCount, exp, err);
            if (!res) {
                audit(*db_, s->userId, "reauth_failed", clientIp(req), "terminal: " + err, t);
                return cb(error(drogon::k401Unauthorized, "패스키 확인 실패"));
            }
            updatePasskeyUse(*db_, key->id, res->signCount, t);
            if (auto tok = sessionToken(req))
                sessions_->markReauth(*tok, t);
            Json::Value& a = p["auth"];
            a["ts"] = p["ts"];
            a["nonce"] = nonce;
            a["id"] = base64UrlEncode(*credId);
            a["client_data"] = base64UrlEncode(*clientData);
            a["auth_data"] = base64UrlEncode(*authData);
            a["sig"] = base64UrlEncode(*sig);
            Json::StreamWriterBuilder w;
            w["indentation"] = "";
            Json::Value v;
            v["ticket"] = putPending(*db_, "term", Json::writeString(w, p), 60, t);
            cb(json(v));
        },
        {drogon::Post});

    // 신뢰 목록 상태 (관리자): 승인 대기 변경, 서버별 반영 버전
    app.registerHandler("/api/terminal/trust",
                        [this](const HttpRequestPtr& req, Callback&& cb) {
                            if (!currentSession(req, now()))
                                return cb(error(drogon::k401Unauthorized, "로그인이 필요합니다"));
                            cb(json(trustStatusJson()));
                        },
                        {drogon::Get});

    // 신뢰 목록 변경 승인 1) 서명할 새 판 (관리자 패스키 중 서버들이 이미 믿는 것만)
    app.registerHandler(
        "/api/terminal/trust/options",
        [this](const HttpRequestPtr& req, Callback&& cb) {
            if (!sameOrigin(req))
                return cb(error(drogon::k403Forbidden, "잘못된 요청 출처"));
            const auto t = now();
            auto s = currentSession(req, t);
            if (!s)
                return cb(error(drogon::k401Unauthorized, "로그인이 필요합니다"));
            auto st = trustState();
            if (!st.pending)
                return cb(error(drogon::k409Conflict, "승인할 변경이 없습니다"));
            std::int64_t next = st.version;
            {
                std::lock_guard lk(trustMu_);
                for (const auto& [id, nt] : nodeTrust_)
                    next = std::max(next, nt.version);
            }
            ++next;
            const auto admins = trustKeyIds(st.snapshot, true);
            Json::Value creds(Json::arrayValue);
            for (const auto& k : listPasskeys(*db_, s->userId)) {
                const auto id = base64UrlEncode(k.credentialId);
                if (!admins.contains(id))
                    continue;
                Json::Value d;
                d["type"] = "public-key";
                d["id"] = id;
                creds.append(d);
            }
            if (creds.empty())
                return cb(error(drogon::k409Conflict,
                                "서버들이 믿는 관리자 패스키가 이 계정에 없습니다. 기존 "
                                "관리자 패스키가 있는 계정·기기에서 승인하세요"));
            Json::Value p;
            p["user_id"] = Json::Int64(s->userId);
            p["base"] = Json::Int64(st.version);
            p["snapshot"] = desiredTrust(next);
            Json::StreamWriterBuilder w;
            w["indentation"] = "";
            Json::Value v;
            v["pending"] = putPending(*db_, "termtrust", Json::writeString(w, p), 300, t);
            auto& pk = v["publicKey"];
            pk["challenge"] = base64UrlEncode(termTrustChallenge(p["snapshot"].asString()));
            pk["rpId"] = cfg_.effectiveRpId();
            pk["timeout"] = 120000;
            pk["userVerification"] = "required";
            pk["allowCredentials"] = creds;
            cb(json(v));
        },
        {drogon::Post});

    // 신뢰 목록 변경 승인 2) 서명 확인 → 저장 → 모든 Agent에 전송
    app.registerHandler(
        "/api/terminal/trust/sign",
        [this](const HttpRequestPtr& req, Callback&& cb) {
            if (!loginAllowed(req))
                return cb(error(drogon::k429TooManyRequests,
                                "요청이 너무 많습니다. 잠시 후 다시 시도하세요"));
            if (!sameOrigin(req))
                return cb(error(drogon::k403Forbidden, "잘못된 요청 출처"));
            const auto t = now();
            auto s = currentSession(req, t);
            if (!s)
                return cb(error(drogon::k401Unauthorized, "로그인이 필요합니다"));
            auto body = req->getJsonObject();
            if (!body)
                return cb(error(drogon::k400BadRequest, "JSON 본문이 필요합니다"));
            auto payload = takePending(*db_, (*body).get("pending", "").asString(), "termtrust", t);
            Json::Value p;
            if (!payload || !parseJson(*payload, p) || jsonInt(p, "user_id") != s->userId)
                return cb(error(drogon::k400BadRequest, "만료된 요청입니다. 다시 시도하세요"));
            auto st = trustState();
            if (jsonInt(p, "base") != st.version)
                return cb(error(drogon::k409Conflict, "그사이 신뢰 목록이 바뀌었습니다. 다시 "
                                                      "시도하세요"));
            const std::string snapshot = jsonStr(p, "snapshot");
            const auto& cred = (*body)["credential"];
            const auto& resp = cred["response"];
            auto dec = [](const Json::Value& v) {
                return v.isString() ? base64UrlDecode(v.asString()) : std::nullopt;
            };
            auto credId = dec(cred["id"]);
            auto clientData = dec(resp["clientDataJSON"]);
            auto authData = dec(resp["authenticatorData"]);
            auto sig = dec(resp["signature"]);
            if (!credId || !clientData || !authData || !sig)
                return cb(error(drogon::k400BadRequest, "잘못된 응답 형식"));
            auto key = findPasskeyByCredentialId(*db_, *credId);
            if (!key || key->userId != s->userId ||
                !trustKeyIds(st.snapshot, true).contains(base64UrlEncode(*credId)))
                return cb(error(drogon::k401Unauthorized, "서버들이 믿는 관리자 패스키가 "
                                                          "아닙니다"));
            webauthn::Expectations exp{termTrustChallenge(snapshot), cfg_.origin(),
                                       cfg_.effectiveRpId(), true};
            std::string err;
            auto res = webauthn::verifyAssertion(*clientData, *authData, *sig, key->publicKeyCose,
                                                 key->signCount, exp, err);
            if (!res) {
                audit(*db_, s->userId, "reauth_failed", clientIp(req), "terminal trust: " + err, t);
                return cb(error(drogon::k401Unauthorized, "패스키 확인 실패"));
            }
            updatePasskeyUse(*db_, key->id, res->signCount, t);
            Json::Value parsed;
            parseJson(snapshot, parsed);
            Json::Value sj;
            sj["id"] = base64UrlEncode(*credId);
            sj["client_data"] = base64UrlEncode(*clientData);
            sj["auth_data"] = base64UrlEncode(*authData);
            sj["sig"] = base64UrlEncode(*sig);
            Json::StreamWriterBuilder w;
            w["indentation"] = "";
            TrustRecord r{parsed["version"].asInt64(), snapshot, Json::writeString(w, sj),
                          s->userId, t};
            if (!insertTrust(*db_, r))
                return cb(error(drogon::k409Conflict, "그사이 신뢰 목록이 바뀌었습니다. 다시 "
                                                      "시도하세요"));
            audit(*db_, s->userId, "terminal_trust_signed", clientIp(req),
                  "v" + std::to_string(r.version) + " 키 " + std::to_string(parsed["keys"].size()) +
                      "개 (" + key->name + ")",
                  t);
            pushTrust();
            cb(json(trustStatusJson()));
        },
        {drogon::Post});

    app.registerHandler("/api/terminal/recordings",
                        [this](const HttpRequestPtr& req, Callback&& cb) {
                            if (!currentSession(req, now()))
                                return cb(error(drogon::k401Unauthorized, "로그인이 필요합니다"));
                            std::vector<std::pair<std::string, std::uintmax_t>> files;
                            std::error_code ec;
                            for (const auto& e : std::filesystem::directory_iterator(
                                     terminal_->recordingsDir(), ec)) {
                                const std::string name = e.path().filename().string();
                                if (std::regex_match(name, kRecName))
                                    files.emplace_back(name, e.file_size(ec));
                            }
                            std::sort(files.begin(), files.end(), std::greater<>());
                            Json::Value arr(Json::arrayValue);
                            for (std::size_t i = 0; i < files.size() && i < 200; ++i) {
                                std::smatch m;
                                std::regex_match(files[i].first, m, kRecName);
                                Json::Value v;
                                v["name"] = files[i].first;
                                v["date"] = m[1].str();
                                v["time"] = m[2].str();
                                v["node"] = m[3].str();
                                v["user"] = m[4].str();
                                v["size"] = Json::UInt64(files[i].second);
                                arr.append(v);
                            }
                            Json::Value out;
                            out["recordings"] = arr;
                            out["active"] = Json::UInt64(terminal_->activeCount());
                            cb(json(out));
                        },
                        {drogon::Get});

    // 녹화 삭제 (패스키 재확인). 지운 사실은 감사 로그에 남는다.
    app.registerHandler(
        "/api/terminal/recordings/delete",
        [this](const HttpRequestPtr& req, Callback&& cb) {
            if (!sameOrigin(req))
                return cb(error(drogon::k403Forbidden, "잘못된 요청 출처"));
            const auto t = now();
            auto s = currentSession(req, t);
            if (!s)
                return cb(error(drogon::k401Unauthorized, "로그인이 필요합니다"));
            if (!sessions_->reauthFresh(*s, t))
                return cb(error(drogon::k403Forbidden, "reauth_required"));
            auto body = req->getJsonObject();
            std::vector<std::string> names;
            if (body && (*body)["names"].isArray())
                for (const auto& n : (*body)["names"])
                    names.push_back(n.asString());
            if (names.empty() || names.size() > 500)
                return cb(error(drogon::k400BadRequest, "지울 녹화를 고르세요"));
            int removed = 0;
            for (const auto& name : names) {
                if (!std::regex_match(name, kRecName))
                    continue;
                std::error_code ec;
                if (std::filesystem::remove(
                        std::filesystem::path(terminal_->recordingsDir()) / name, ec)) {
                    ++removed;
                    audit(*db_, s->userId, "recording_deleted", clientIp(req), name, t);
                }
            }
            Json::Value v;
            v["removed"] = removed;
            cb(json(v));
        },
        {drogon::Post});

    // 녹화에는 화면에 출력된 비밀값이 있을 수 있어 패스키 재확인 후에만 내려준다
    app.registerHandler(
        "/api/terminal/recordings/{name}",
        [this](const HttpRequestPtr& req, Callback&& cb, const std::string& name) {
            const auto t = now();
            auto s = currentSession(req, t);
            if (!s)
                return cb(error(drogon::k401Unauthorized, "로그인이 필요합니다"));
            if (!sessions_->reauthFresh(*s, t))
                return cb(error(drogon::k403Forbidden, "reauth_required"));
            if (!std::regex_match(name, kRecName))
                return cb(error(drogon::k404NotFound, "녹화를 찾을 수 없습니다"));
            const auto path = std::filesystem::path(terminal_->recordingsDir()) / name;
            std::error_code ec;
            if (!std::filesystem::is_regular_file(path, ec))
                return cb(error(drogon::k404NotFound, "녹화를 찾을 수 없습니다"));
            audit(*db_, s->userId, "recording_viewed", clientIp(req), name, t);
            auto r = HttpResponse::newFileResponse(path.string(), "", drogon::CT_TEXT_PLAIN);
            r->addHeader("Cache-Control", "no-store");
            cb(r);
        },
        {drogon::Get});
}

std::string HubApp::desiredTrust(std::int64_t version) {
    return buildTrustSnapshot(*db_, cfg_.origin(), cfg_.effectiveRpId(), cfg_.allowedEmails,
                              version);
}

HubApp::TrustState HubApp::trustState() {
    TrustState st;
    bool created = false;
    {
        auto guard = db_->lock();
        auto latest = latestTrust(*db_);
        // 첫 판, 또는 관리자 패스키가 아직 없는 동안(아무도 서명할 수 없음)은 서명 없이 새 판을
        // 만든다. Agent도 이 경우에만 서명 없는 판을 받는다.
        if (!latest || trustKeyIds(latest->snapshot, true).empty()) {
            const std::int64_t v = latest ? latest->version : 0;
            if (!latest || !sameTrustContent(latest->snapshot, desiredTrust(v))) {
                TrustRecord r{v + 1, desiredTrust(v + 1), "", std::nullopt, now()};
                created = insertTrust(*db_, r);
                latest = r;
            }
        }
        st.version = latest->version;
        st.snapshot = latest->snapshot;
        st.pending = !sameTrustContent(latest->snapshot, desiredTrust(latest->version));
    }
    if (created && gateway_)
        sendTrust(0);
    return st;
}

void HubApp::pushTrust(std::int64_t nodeId) {
    trustState(); // 첫 판 준비 (새로 만들었으면 이미 모두에게 보냄)
    sendTrust(nodeId);
}

void HubApp::sendTrust(std::int64_t nodeId) {
    const auto msg = trustMessage(trustRecords(*db_));
    if (nodeId) {
        gateway_->send(nodeId, msg);
        return;
    }
    for (const auto& n : listNodes(*db_))
        gateway_->send(n.id, msg);
}

void HubApp::ingestTrustStatus(std::int64_t nodeId, const Json::Value& msg) {
    NodeTrust nt{jsonInt(msg, "version"), jsonStr(msg, "error").substr(0, 300), now()};
    std::lock_guard lk(trustMu_);
    nodeTrust_[nodeId] = nt;
}

Json::Value HubApp::trustStatusJson() {
    auto st = trustState();
    Json::Value v;
    v["version"] = Json::Int64(st.version);
    v["pending"] = st.pending;
    auto keys = [](const std::string& snap) {
        Json::Value t, out(Json::arrayValue);
        parseJson(snap, t);
        for (const auto& k : t["keys"]) {
            Json::Value e;
            e["id"] = k["id"];
            e["user"] = k["user"];
            e["admin"] = k.get("admin", false).asBool();
            e["nodes"] = k.isMember("nodes") ? k["nodes"] : Json::Value(Json::arrayValue);
            out.append(e);
        }
        return out;
    };
    v["keys"] = keys(st.snapshot);
    if (st.pending)
        v["desired"] = keys(desiredTrust(st.version));
    // 패스키 이름 (화면 표시용)
    Json::Value names(Json::objectValue);
    for (const auto& u : listUsers(*db_))
        for (const auto& k : listPasskeys(*db_, u.id))
            names[base64UrlEncode(k.credentialId)] = k.name;
    v["key_names"] = names;
    Json::Value nodes(Json::arrayValue);
    std::lock_guard lk(trustMu_);
    for (const auto& n : listNodes(*db_)) {
        Json::Value e;
        e["id"] = Json::Int64(n.id);
        e["name"] = n.name;
        e["connected"] = live_.connected(n.id);
        if (auto it = nodeTrust_.find(n.id); it != nodeTrust_.end()) {
            e["version"] = Json::Int64(it->second.version);
            if (!it->second.error.empty())
                e["error"] = it->second.error;
        }
        nodes.append(e);
    }
    v["nodes"] = nodes;
    return v;
}

} // namespace douve
