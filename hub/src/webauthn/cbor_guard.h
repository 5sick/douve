#pragma once
// libcbor에 넘기기 전 CBOR 사전 검사.
// libcbor는 배열·맵의 "선언된 개수"만큼 미리 메모리를 잡는다. 외부 입력(로그인 요청의 인증기 데이터
// 등)이 "원소 7억 개짜리 배열"이라고 선언하면 실제 데이터가 몇 바이트여도 수 GB를 할당하려 한다
// (퍼징으로 발견). 그래서 할당 없이 구조만 훑어, 선언된 길이·개수가 남은 바이트로 불가능하면
// 거부한다.

#include <cstddef>
#include <cstdint>

namespace douve::webauthn {

// data에서 시작하는 CBOR 항목 하나가 len 안에 들어갈 수 있으면 true (뒤에 남는 바이트는 허용).
// 중첩 깊이는 maxDepth까지.
bool cborWithinBounds(const std::uint8_t* data, std::size_t len, int maxDepth = 16);

} // namespace douve::webauthn
