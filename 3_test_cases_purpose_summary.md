TCG Storage Opal Family Test Cases Specification 문서에는 드라이브가 TCG 보안 국제 표준을 정확히 따르는지 평가하기 위한 다양한 테스트 시나리오가 3가지 카테고리(UCT, SPF, ETC)로 나뉘어 기재되어 있습니다. 각 카테고리의 모든 테스트에 대한 "목적(무엇을 검증하기 위한 테스트인지)" 설명입니다.

## 1. UCT (Use Case Test Cases)
이 섹션은 TCG 규격을 지원하는 스토리지가 **"정상적인 일반 사용 시나리오"**에서 올바르게 동작하는지를 확인하기 위한 목적입니다.

* **[UCT-01: Level 0 Discovery]**
  - 목적: 호스트(OS)가 스토리지에 처음 질의(Query)할 때, 디바이스가 자신이 단일 TCG 모듈(Opal, Pyrite 등) 및 어떤 기본 보안 기능을 지원하는지 규격에 맞춰 정보 목록을 정확히 응답해 주는지 검증.
* **[UCT-02: Properties]**
  - 목적: 호스트와 드라이브 상호 간에 통신할 세션의 최대 패킷 속성 파라미터 협상이 정상적으로 이루어지는지 목적.
* **[UCT-03: Taking Ownership of an SD]**
  - 목적: 공장 상태의 드라이브에 대해 초기 관리자 권한(MSID)으로 로그인한 뒤, 관리자 암호(SID)를 변경하여 호스트 시스템이 정상적으로 드라이브 제어 **소유권을 획득**할 수 있는지 확인.
* **[UCT-04: Activate Locking SP when in Manufactured-Inactive State]**
  - 목적: 공장 초기 상태에서 아직 잠들어있는(비활성 상태) 데이터 보안 잠금 관리자(Locking SP)를 활성화(Activate)시켜 이용 가능한 상태로 만들 수 있는지 기능 테스트.
* **[UCT-05: Configuring Authorities]**
  - 목적: 다수의 관리자 및 일반 사용자 계정(User1, Admin1 등)에 대해 설정 및 권한 활성화, 고유한 패스워드 설정 기능이 제대로 동작하는지 테스트.
* **[UCT-06: Configuring Locking Objects (Locking Ranges)]**
  - 목적: 공간을 분할해 논리적인 잠금 영역(Range) 개체를 만들고, 읽기/쓰기 잠금 권한과 시작/끝 범위를 정상적으로 구성(Setting) 가능한지 검증.
* **[UCT-07: Unlocking Ranges]**
  - 목적: 접근 권한을 획득한 올바른 사용자가 잠겨져 있는 파티션(Range)의 락(Lock) 상태를 해제하여 데이터 읽기/쓰기를 재개할 수 있는지 검증.
* **[UCT-08: Erasing Ranges]**
  - 목적: 암호화 영역의 데이터 복호화 키(ActiveKey) 자체를 파기 후 재생성(GenKey)하여 해당 영역 데이터를 어떠한 수단으로도 복원할 수 없게 일거에 완벽 삭제(Crypto Erase)하는 기능.
* **[UCT-09: Using the DataStore Table]**
  - 목적: 시스템 관리에 필요한 부수적인 데이터를 기기 내 비휘발성 저장공간(DataStore 테이블) 영역에 읽고 쓸 수 있는 접근 제한 권한이 제대로 작동하는지 목적.
* **[UCT-10: Enable MBR Shadowing]**
  - 목적: 컴퓨터 부팅 시 운영체제보다 먼저 인증 화면을 띄워주는 기능(Pre-Boot Authentication)을 위해 가상 MBR 파티션 공간(섀도잉) 기능이 올바르게 켜지는지 확인.
* **[UCT-11: MBR Done]**
  - 목적: MBR 부팅 인증을 성공적으로 마치고, 이 가상 MBR 공간을 감춘 뒤 실제 사용자의 OS 영역 파티션을 부팅 라인으로 정상적으로 복귀시키는(Done 상태 마킹) 여부 확인.
* **[UCT-12/13/14/15: Revert Admin/Locking SP using various states & IDs]**
  - 목적 (UCT 12~15): 각 권한자(SID, Admin1)가 현재 드라이브의 상황별 제약하에서도 특정 구역(관리자 SP 또는 데이터 잠금 SP)만을 선택적으로 공장 부팅 상태 수준으로 리셋(초기화)할 수 있는지 기능 유효성 점검.
* **[UCT-16: Revert Admin SP using PSID...]**
  - 목적: 완전한 계정 상실/비상 상황 시 스토리지 겉면의 물리적 비밀 키(PSID)를 사용해, 무조건적으로 드라이브를 강제 공장 초기화 상태로 복구해 재사용할 수 있게 하는 핵심 기능 시연.

## 2. SPF (Specific Functionality Test Cases)
이 섹션은 TCG 아키텍처 내 **"특수한 메서드들과 세부 규칙(속성 설정, 트랜잭션 등)"**을 집중적으로 시험하는 목적입니다.

* **[SPF-01: Transaction]**
  - 목적: 여러 개의 정보 갱신 명령들을 하나의 묶음 '트랜잭션'으로 전송할 때, 하나라도 실패 시 전부 롤백시키고 성공 시 한 번에 반영하는 원자성 데이터 업데이트 기능 검증.
* **[SPF-02: IF-RECV Behavior Tests]**
  - 목적: 정보를 꺼내오는 호출(RECV)을 보낼 때, 수신 버퍼 크기를 지나치게 적게 보내거나 응답 데이터가 더 많을 때 끊어서 가져갈 수 있는 통신 연결 관리 검증.
* **[SPF-03/04/05: TryLimit, Tries Reset, Tries Reset on Power Cycle]**
  - 목적 (SPF 3~5): 비밀번호 연속 시도 횟수 제한(TryLimit)이 정확히 초과 시 잠기는지, 올바른 인증이나 전원 재부팅 조건에서는 해당 오류 카운트(Tries)가 0으로 정상 리셋되는지 검증해 무차별 대입 공격(Brute Force)을 막는 목적.
* **[SPF-06: Next]**
  - 목적: 테이블의 객체 리스트나 컬렉션 목록을 스캔할 때, 규격화된 방식으로 요소들을 하나씩 순회 조회(Next)해 나갈 수 있는지 확인.
* **[SPF-07: Host Session Number (HSN)]**
  - 목적: 다중 접속 시 혼란을 피하기 위해 쏘아 보낸 고유한 세션 번호(HSN)와 응답 세션 번호가 일관되게 연동되는지 체크.
* **[SPF-08: RevertSP]**
  - 목적: 국지적 서비스 모듈 초기화 명령어인 RevertSP를 호출하면 연관된 글로벌 키와 암호화 구조가 제대로 종속 소멸하는지 연관성 테스트.
* **[SPF-09: Range Alignment Verification]**
  - 목적: 논리 구역의 시작 주소와 크기가 기기 내부의 물리적인 포맷 정렬 요구 조건(Alignment Granularity)의 크기 배수에 정확히 맞게 떨어져서 생성되는지 유효성 검증.
* **[SPF-10: Byte Table Access Granularity]**
  - 목적: 바이트(Byte) 조각 단위 형태로 처리하는 테이블 저장 영역 처리에서 지정된 바이트 접근 제한 규격대로 분할 처리 가능한지 체킹.
* **[SPF-11/12: Stack Reset, TPer Reset]**
  - 목적: TCG 규격에 부합하는 통신 리셋(Stack Reset) 및 스토리지 물리적 보안 전체 리셋(TPer Reset) 시, 열려있던 모든 암호 세션 등이 올바르게 즉시 소멸하는지 점검.
* **[SPF-13: Authenticate]**
  - 목적: 인증 메서드로 올바른 권한 아이디 및 증명 키를 전달했을 때 정상 토큰을 반환해 주는지 인증 처리 동작 점검.
* **[SPF-14: Session Abort (Deprecated)]**
  - 목적: 오류가 파악되어 즉각 특정 통신 세션을 취소, 패기처리(Abort)하는 명령의 정상 작동 확인(과거 하위호환).
* **[SPF-15: Random]**
  - 목적: 난수 발생기 요구 시 단순한 임의 바이트열을 제대로 뱉어내는지 응답성 테스트(보안 강도 테스트 아님).
* **[SPF-16: CommonName]**
  - 목적: 사용자가 원하는 식별형 별칭 문자열 필드 값(CommonName)을 추가로 테이블에 기입하고 수정/조회 가능한지 테스트.
* **[SPF-17: Additional DataStore Tables]**
  - 목적: 기본적으로 제공되는 부가 저장 기능 이외에 다수의 확장 스토리지 추가 영역 테이블이 있는 하드웨어에서, 모든 추가 영역이 통신 가능 규정에 맞는지 검증.
* **[SPF-18: Range Crossing Behavior]**
  - 목적: 호스트가 보낸 I/O 읽기/쓰기가 잠금 속성이 서로 다른 구역(예: 1GB는 잠김, 1GB는 열림) 2가지 영역에 교묘하게 반반 걸쳐서 수행될 때 거부하거나 올바른 규약으로 실패 처리 하는지 검증.
* **[SPF-19: Block SID Authentication]**
  - 목적: 다른 악성 도구가 초기 설정을 탈취하지 못하게 TCG SID 인증을 일시적으로 동결, 차단(Block SID)시키는 명령을 보냈을 때 정말로 SID 접근이 차단되는지 방어 여부 테스트.
* **[SPF-20: Data Removal Mechanism]**
  - 목적: 단순히 암호화 키를 부수는 것 외에 블록 전체를 Zero로 지워버리는 등의 장비별 '데이터 오버라이트 / 물리적 영구 삭제 매커니즘'의 지원 유무와 작동성을 올바르게 인지 테스트.

## 3. ETC (Error Test Cases)
이 섹션은 비정상 규격 주입, 무단의 데이터 오용 및 **"해킹 공격이나 잘못된 프로토콜에 대해 방어(에러 응답 거부)"**를 제대로 하는지 검증하는 것이 목적입니다.

* **[ETC-01: Native Protocol Read/Write Locked Error Responses]**
  - 목적: 호스트 운영체제(네이티브 구문)가 무단으로 잠겨진 영역으로 Read/Write 패킷을 보낼 때, 정확한 형태의 통신 에러 코드를 내려보내서 데이터 노출을 완벽하게 차단하는지 검사.
* **[ETC-02: General – IF-SEND/IF-RECV Synchronous Protocol]**
  - 목적: SEND 명령을 하지 않은채 RECV 응답 데이터를 받으려 하는 허용되지 않은 비동기적 통신 요청에 대해 에러 대응 무결성 검증.
* **[ETC-03: Invalid IF-SEND Transfer Length]**
  - 목적: 하드웨어 메모리가 감당 가능한 전송 통신 제한 길이 값을 무시하고 터무니없이 큰 길이를 발송했을 때 메모리 범람 방지를 위한 규격 통신 거절 여부.
* **[ETC-04: Invalid SessionID - Regular Session]**
  - 목적: 이미 유효하게 인증되어 열려 있는 한 세션 통신 속에, 외부의 알 수 없는/존재하지 않는 가짜 '세션 아이디'를 주입한 하위 패킷을 받을 경우 차단하는지 방어 검증.
* **[ETC-05~ETC-08: Unexpected Token (Header/List/Control)]**
  - 목적: TCG 규약 구조에 어긋나는 위치(메서드 바깥, 헤더 리스트 끝 등)에 이상한 쓰레기값이나 파라미터 제어 기호를 고의로 섞어 넣어서 보냈을 때 스푸핑(Spoofing) 당하지 않고 에러 처리(거절)하는지 검증.
* **[ETC-09: Exceeding Transaction Limit]**
  - 목적: 장비가 감당 가능한 규정된 트랜잭션(작업) 수량 제한 한계치를 넘도록 요청할 때, 자원 소진 공격으로 뻗지 않고 초과로 인한 거부 상태를 응답하는 제한치 테스트.
* **[ETC-10/ETC-11: Invalid Invoking ID - Get / Non-Get]**
  - 목적: UID, 즉 존재하지 않는 고유 식별 주소값을 쿼리해달라(Get)거나 세팅해달라(Non-Get)고 조작할 경우, `NOT_AUTHORIZED`나 내용 감춤 처명령을 해서 은폐하는지 권한 방어 테스트.
* **[ETC-12: Authorization]**
  - 목적: 잠겨있는 계정 혹은 Enabled 속성으로 사용 허가가 켜지지 않은 아이디 상태에서 권한 인증 우회를 시도할 때 올바르게 에러 반환(거절)하는지 검증.
* **[ETC-13: Malformed ComPacket Header – Regular Session]**
  - 목적: 외부 사이즈 길이는 멀쩡하지만 내용물의 헤더 패킷 구조를 악의적으로 조작한 기형 패킷을 보내 공격할 때 멈추지 않고 에러 반환하는지 방어 능력.
* **[ETC-14/15: Exceed TPer Properties – Regular / Control Session]**
  - 목적: 서브 패킷 요소의 수를 허용 범위를 넘겨 미친듯이 많이 보냈을 때 시스템 오류 없이 제한 초과로 감지하고 세션을 중단하여 방어하는 상태 점검.
* **[ETC-16: Overlapping Locking Ranges]**
  - 목적: 디바이스 내 겹치게(Overlapping) 잠금 영역을 생성할 수 없음에도, 의도적으로 교집합 영역(주소 블록)을 지시하며 잠금 생성하려 할 때 겹침 오류를 내뱉어 설정 무결성 확보 목적.
* **[ETC-17: Invalid Type]**
  - 목적: 숫자 값이 들어가야 할 파라미터에 바이트열이나 문자 등 부적절한 형태(Type) 캐스팅 지시를 내렸을 때 시스템 결함 없이 Type Error를 내리치는지 검증.
* **[ETC-18: RevertSP – GlobalRange Locked]**
  - 목적: 강한 잠금을 설정한 특정 잠금 테이블 상태(GlobalRange) 환경에서 시스템 모듈 초기화(RevertSP)라는 치명적인 파괴 명령을 호출할 시 부적절한 상태/조건 오류로 처단하는지 점검.
* **[ETC-19: Activate / ATA Security Interaction]**
  - 목적: 과거 보안 방식(레거시 ATA 암호)과 최신 TCG 시스템 양쪽 기능 간 중첩이나 충돌 발생 시 원칙 규격에 맞춰 어느 쪽을 에러 처리해야 할 지 안전 기능 규제 검증.
* **[ETC-20: StartSession on Inactive Locking SP]**
  - 목적: 데이터 보호 관리 모듈(Locking SP)이 꺼진(Inactive) 잠금 해제 스토리지에 대해, 인증 세션을 성립하려고 억지를 부릴 때 불필요한 액세스 개시 오류 차이를 검증.
* **[ETC-21: StartSession with Incorrect HostChallenge]**
  - 목적: 패스워드 등과 같은 주요 접속 보안 키(HostChallenge) 파라미터가 처음부터 잘못 조작된 상태로 세션 연결을 요구할 때 즉각 인증 절차를 종료하고 쫓아내는지 차단 검증.
* **[ETC-22: Multiple Sessions]**
  - 목적: 제품별 동시 연결 가능한 한계수량을 넘치게 여러 세션 입구를 점유하려 시도 시, 추가된 초과 세션을 모두 거절하는 다중 액세스 보안 스펙 거부 검증.
* **[ETC-23: Data Removal Mechanism – Set Unsupported Value]**
  - 목적: 존재하지도 않는 영속적 파기 방식 코드나 하드웨어가 지원하지 않는 삭제 메커니즘을 지정명령할 때, 고장의 위협에서 올바르게 불허 응답을 주는지 검증.
* **[ETC-24: Read Locked and Write Locked Error Responses]**
  - 목적: 명시적으로 잠겨있는 논리 구역에 무책임하게 TCG 통신 명령어(IF-RECV) 읽기 및 쓰기 처리를 호출할 시 권한 막힘 Error로 응답 차단하는지 목적 확인.
