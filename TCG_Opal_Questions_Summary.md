# TCG Opal Test Cases - 질문 정리

## ETC (Error Test Cases)

### ETC-04: Invalid SessionID
- **문서의 expected response가 잘못된 것 아니야?**
  - Steps #1-3 SUCCEED가 기대값인데, Step 2에서 status code가 출력이 안 되는데 어떻게 SUCCEED가 되지?
  - → IF-SEND가 NVMe 레벨에서 성공한 것이 SUCCEED의 의미. TPer가 패킷을 drop했으므로 TCG 응답 없음 → 파싱 결과 0,0,0은 기본값
  - **IF-RECV가 아무 회신이 없어**
  - → OutstandingData=0, MinTransfer=0, Length=0 = "All Response(s) returned - no further data" 가 맞음
  - **1번 회신(All Response returned - no further data)은 어떻게 오는 거야? 문자로 오나?**
  - → ComPacket header 필드값으로 옴. OutstandingData=0, MinTransfer=0, Length=0

### ETC-04 reference
- **error reference source는 어디에 있는 거야?**
  - → Test Cases 문서 1.3 Document References: [1]=Core Spec v2.01, [2]=SIIS v1.08 등

### ETC-05: Unexpected Token Outside Method
- **2에서 status code가 출력이 안 되는데 어떻게 SUCCEED가 되지** (재질문)
- **Session이 살아있는 것은 문제가 있는 거 아닌가?**
  - → Firmware bug. 스펙은 session abort를 요구하나 드라이브가 abort하지 않음

### ETC-06: Unexpected Token in Method Header
- **close session하고 status 1이네**
  - → NOT_AUTHORIZED + CloseSession = 스펙 기대값 그대로. **ETC-06 PASS**

---

## Properties

- **Properties에서 host setting에 따른 회신은 뭐지?**
  - → HostProperties는 Host가 받을 수 있는 능력을 TPer에게 알려주는 것. TPer가 Host에게 보낼 때 이 한계를 지켜야 함
- **Host properties 해석이 잘못된 거 아니야?**
  - → 맞음. HostProperties = "TPer가 Host에게 보낼 때 지켜야 할 Host의 수신 능력"

---

## Authority / Table 구조

- **Locking range 설정할 때 User1 auth가 왜 들어가지? Range1 UID가 들어가야 하는 거 아니야?**
  - → User1 Authority object에 Set/Get을 하는 것. ETC-05에서 User1 Enabled 컬럼을 설정하는 것

- **저기 위에서 왜 Enabled가 컬럼 6이지?**
  - → Authority table (Table 178): Enabled = 0x05, Secure = 0x06. 내가 잘못 작성한 것

- **Invoking은 User1 authority인데 왜 authority table description을 참조해?**
  - → User1은 Authority table의 한 row. InvokingUID가 해당 row를 직접 가리키므로 Authority table 컬럼 구조를 참조하는 것이 맞음

- **User1 authority는 어디서 찾았어?**
  - → Opal SSC 스펙 Table 40 (Locking SP Authority Table Preconfiguration)에서 확인

- **Authority table과 Locking SP Authority table 차이는 뭐야?** (Table 240 관련)
  - → Table 구조(컬럼 번호)는 동일. Core Spec Table 178이 공통 구조 정의. 차이는 내용(row): Admin SP에는 SID, Locking SP에는 User1~N 등

- **Table method와 object method 방식에 대하여 spec에서 설명한 부분이 있어?**
  - → Core Spec 5.3.3.6: `TableUID.Get` vs `ObjectUID.Get` 명시. Object method는 Where 파라미터 생략, Table method는 Where=UID 지정 필요

- **Invoking은 User1 authority table uid로 했어, 그런데 어떻게 authority table descriptor object를 읽는지 TPer이 어떻게 알지?**
  - → UID 앞 4바이트 `00 00 00 09`가 Authority table 식별자. TPer는 이를 보고 Authority table의 컬럼 구조 적용

- **그럼 invoking uid의 row를 직접 읽으려면 어떻게 해야 해?**
  - → 지금까지 해온 방식이 Object method. InvokingUID = object UID → 해당 row 직접 접근, CellBlock에 컬럼 번호만 지정

---

## 3.2.2.4.2 Unexpected Tokens

- **Core spec 3.2.2.4.2에 unexpected tokens를 읽고 정리해봐**
  - → 5가지 케이스: (1)일반-session abort, (2)Method 밖-session abort, (3)Method header-NOT_AUTHORIZED, (4)Parameter list-INVALID_PARAMETER, (5)Status list-session abort
  - Control session은 모두 "나머지 패킷 무시"

- **Abort는 session을 종료한다는 의미인가?**
  - → 맞음. 하지만 정상 종료(CloseSession)와 다름: 미완료 트랜잭션 롤백 + 실행 중 method 즉시 중단 + CloseSession MAY 전송

- **왜 English로 답해** (한국말이 의미를 더 모호하게 만든다는 지적)

---

## ACE / Locking Range 접근 제어

- **동작 원리를 모르겠네 User마다 접근 Range가 다르게 하는 건가?**
  - → Authority는 인증 주체. 어떤 Range에 접근하는지는 ACE가 결정. Admin1 설정으로 User1에게 특정 Range의 ReadLocked/WriteLocked 변경 권한 부여 가능

---

## Session

- **Session abort는 session을 종료한다는 의미인가?**
  - → 강제 종료. 미완료 트랜잭션 롤백, 실행 중 method 실패, CloseSession MAY 전송 (의무 아님)

---

## SPF-11: Stack Reset

- **Stack Reset에 대하여 알려줘**
  - → HANDLE_COMID_REQUEST (Protocol=0x02), Request Code=0x00000002. 특정 ComID의 protocol stack 초기화, 모든 세션 abort, 트랜잭션 rollback, Properties 기본값 reset

---

## TPer Reset

- **TPer Reset은 어떤 효과가 있어?**
  - → 모든 ComID의 모든 세션 abort, 모든 트랜잭션 rollback, LockOnReset 설정에 따라 Locking Range lock 가능, 모든 ComID Properties 초기화

- **TPer Reset 구현은?**
  - → SSC 스펙에서 별도 Method 정의. Programmatic TPer Reset은 ThisSP.TPerReset[] method

- **TPer Reset은 ComID 4로 하는 거 아니야?**
  - → 맞음. Reserved ComID 0x0004. IF-SEND Protocol=0x02, ComID=0x0004, payload=empty/zeros

---

## LockOnReset

- **LockOnReset setting하면 INVALID_PARAMETER 나오는데 정리좀 해줘**
  - → Set_Type이므로 F0...F1 list 안에 값을 넣어야 함. 단순 integer로 보내면 INVALID_PARAMETER
  - PowerCycle(0) 설정: `F2 0A F0 00 F1 F3`
  - Empty set (null): `F2 0A F0 F1 F3`
  - 값 0을 직접 `F2 0A 00 F3`으로 보내면 안 됨

- **아니 0도 setting이 안 돼 setting하는 법을 정리해봐** (재질문)
  - → reset_types는 Set_Type (Table 127). Set Value: 0=PowerCycle, 1=Hardware, 2=HotPlug

---

## ETC-18: RevertSP GlobalRange Locked

- **ETC-18 FAIL 이유는?**
  - → ReadLocked=TRUE, WriteLocked=TRUE 상태에서 KeepGlobalRangeKey=TRUE로 RevertSP → FAIL. locked 상태의 키를 보존하면서 revert는 보안상 허용 안 됨

- **그럼 Locked FALSE로 하면?**
  - → LockEnabled=TRUE, Locked=FALSE로 설정 시 SUCCEED. 드라이브는 Locked 상태를 기준으로 판단

- **그럼 여기서 Range1을 설정하면?**
  - → Range1 LockEnabled=TRUE이면 → RevertSP KeepGlobalRangeKey=TRUE FAIL. LockEnabled=FALSE이면 SUCCEED

- **GlobalRange만 설정하고 Enable은 TRUE, Locked는 FALSE 하면 pass 되네**
  - → 드라이브 판단 기준이 ReadLocked/WriteLocked 상태임을 확인. ETC-18 PASS

---

## ETC-19: ATA Security Interaction

- **Prerequisite 2번은 어떻게 구현해? 그리고 SID PIN 값이 써져 있는데(1번) 어떻게 3번 조건이 되지?**
  - → 2번: ATA Security 명령(SATA 전용). NVMe에서는 불가. 3번: Admin SP와 Locking SP는 독립적. SID PIN 설정(Admin SP)과 Locking SP Manufactured-Inactive는 공존 가능
  - NVMe SSD에서는 **ETC-19 NA**

- **왜 이게 Opal 문서에 있지?**
  - → Opal 초기 설계가 SATA 드라이브 대상. ATA Security와 TCG Opal 충돌 상황 테스트가 필요했음. NVMe에는 ATA Security Feature Set 없음

---

## SPF-12: TPer Reset

- **SPF-12 Case 2에서 MBR에 write하라는데 그럼 유저 등록해야 하나?**
  - → 불필요. Admin1 세션으로 MBR Table Set 가능

- **Programmatic 지원된다니까. 내가 테이블을 TPerInfo table을 잘못 적어서 생긴 문제야. 그래서 Case 1 통과 되었어**
  - → LockOnReset을 잘못된 table에 Set했던 것이 원인. 올바른 Locking table에 Set하니 SUCCEED

- **다 됐는데 동작 원리좀 알려줘** (SPF-12 Case 2)
  - → Done=TRUE: MBR Shadow 해제 → 실제 LBA 접근 가능
  - → TPER_RESET: DoneOnReset에 Programmatic 포함 → Done=FALSE로 자동 리셋
  - → Done=FALSE: MBR Shadow 활성화 → Write는 Data Protection Error, Read는 MBR Table 내용 반환

---

## 기타

- **와 정말 어렵다** (TCG 구조 복잡성)
  - → Table 구조(컬럼)는 동일, SP마다 내용(row)만 다름. UID prefix로 테이블 식별

- **그냥 English로 답해** (의미가 더 명확해진다는 이유)

- **이제 이 Test Case 문서는 완료했네** → 다음 문서 시작 전 질문 정리 요청
