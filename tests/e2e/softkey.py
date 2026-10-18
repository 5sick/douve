#!/usr/bin/env python3
# 시험용 소프트웨어 패스키 (ES256). 브라우저 없이 WebAuthn 인증 응답을 만든다.
#   softkey.py new <키 파일>                     → 키를 만들고 "credential_id_hex cose_hex"를 출력
#   softkey.py sign <키 파일> <origin> <rpId>    → 표준 입력의 options JSON({"publicKey":{...}})에 대한
#                                                   credential JSON을 출력 (navigator.credentials.get 결과처럼)
import base64, hashlib, json, os, struct, sys
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

b64u = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
def unb64u(s): return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

cmd, path = sys.argv[1], sys.argv[2]
if cmd == "new":
    key = ec.generate_private_key(ec.SECP256R1())
    cid = os.urandom(16)
    nums = key.public_key().public_numbers()
    x, y = nums.x.to_bytes(32, "big"), nums.y.to_bytes(32, "big")
    # COSE_Key {1: 2 (EC2), 3: -7 (ES256), -1: 1 (P-256), -2: x, -3: y}
    cose = bytes([0xA5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]) + x + bytes([0x22, 0x58, 0x20]) + y
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    json.dump({"cid": cid.hex(), "pem": pem.decode(), "count": 0}, open(path, "w"))
    print(cid.hex(), cose.hex())
elif cmd == "sign":
    origin, rp = sys.argv[3], sys.argv[4]
    st = json.load(open(path))
    key = serialization.load_pem_private_key(st["pem"].encode(), None)
    opts = json.load(sys.stdin)["publicKey"]
    st["count"] += 1
    json.dump(st, open(path, "w"))
    cd = json.dumps({"type": "webauthn.get", "challenge": opts["challenge"], "origin": origin, "crossOrigin": False}).encode()
    ad = hashlib.sha256(rp.encode()).digest() + bytes([0x05]) + struct.pack(">I", st["count"])
    sig = key.sign(ad + hashlib.sha256(cd).digest(), ec.ECDSA(hashes.SHA256()))
    cid = bytes.fromhex(st["cid"])
    print(json.dumps({"id": b64u(cid), "rawId": b64u(cid), "type": "public-key",
                      "response": {"clientDataJSON": b64u(cd), "authenticatorData": b64u(ad), "signature": b64u(sig), "userHandle": None}}))
