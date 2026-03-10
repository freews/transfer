### TCG Storage Architecture Core Specification - Transactions (Page 77 / Section 3.3.7.3)

TCG(Trusted Computing Group) Storage Core Specification의 77 페이지(문서상 60~61페이지 인접, 섹션 3.3.7.3)에 명시된 **Transaction(트랜잭션)**에 대한 설명입니다.

#### 트랜잭션의 목적과 특징
트랜잭션은 SP(Security Provider, 보안 제공자)에 대한 변경 사항이 어떻게 적용될지에 대한 명확한 모델을 제공하며, 호스트 애플리케이션이 오류 복구를 쉽게 처리할 수 있도록 돕습니다.

1. **상태 변경의 적용 (Persistence)**
   - **트랜잭션 외부:** 메서드가 성공적으로 실행되면 변경 사항이 즉시 적용(Commit)되고 영구적으로 저장됩니다(Persistent).
   - **트랜잭션 내부:** 메서드로 인한 변경 사항은 최상위(Top-level) 트랜잭션이 커밋(Commit)될 때만 영구적으로 적용됩니다. 그 전까지 변경 사항은 해당 트랜잭션 내부에서만 보입니다 (예: 트랜잭션 안에서 변경된 테이블 값은 해당 트랜잭션 내의 Get 메서드에서는 변경된 값으로 반환됨).

2. **원자성 (Atomicity) 및 롤백 (Rollback)**
   - 트랜잭션이 중단(Abort)되면 SP의 상태는 트랜잭션이 시작되기 전 상태로 **전면 롤백(Rolled-back)** 됩니다.
   - 단, 로그 기록(Logging) 등 일부 명시된 예외 작업은 트랜잭션 롤백에 영향을 받지 않고 즉시 커밋될 수 있습니다 (Exception to rollback).
   - 트랜잭션 내에서 특정 메서드가 실패하더라도, 이는 트랜잭션 자체의 상태나 다른 작업들에 직접적인 영향을 미치지 않습니다 (호스트가 판단하여 커밋 또는 중단 결정 가능).

3. **원자적 커밋 보장 (Guaranteed Persistence)**
   - 디바이스(TPer)는 트랜잭션 커밋 도중 전원 주기가 변경(Power cycle)되거나 리셋이 발생하더라도, 복구 시 해당 커밋이 완전히 반영되거나 아니면 완전히 취소되도록 원자성을 엄격히 보장해야 합니다. 이는 전원 차단 공격(Power-off attacks) 등을 방지합니다.

4. **중첩 트랜잭션 (Nested Transactions)**
   - 세션 내에서 트랜잭션을 중첩하여 사용할 수 있습니다 (지원 여부 및 최대 횟수는 SSC 속성의 `MaxTransactionLimit`에 명시).
   - 중첩 트랜잭션은 부모 트랜잭션에 종속되며, 자식 트랜잭션이 커밋되더라도 부모 트랜잭션이 커밋되기 전까지는 디바이스에 최종적으로 영구 저장되지 않습니다.

---

#### 트랜잭션의 라이프사이클 (The Steps)
모든 트랜잭션은 다음 3단계를 거칩니다.
1. **The transaction is opened:** 트랜잭션 시작 토큰(`StartTransaction`)을 통해 열립니다.
2. **Zero or more method calls are made:** 0개 이상의 메서드(Set, Get 등) 호출이 진행됩니다.
3. **The transaction is either aborted or committed:** 호스트가 상태 코드와 함께 `EndTransaction` 토큰을 보내 커밋(0x00)하거나 중단(비제로)합니다.

---

### 샘플 코드 (Pseudo-code)

TCG Opal 환경을 다루는 저수준 라이브러리(예: C/C++ sedutil, Python sedpython 등)에서 트랜잭션을 구성하는 통신 스트림을 생성하는 개념적인(Pseudo-code) 샘플입니다. 실제 TCG 통신에서는 패킷(Packet), 서브패킷(Subpacket), 데이터 토큰(Token) 구조로 인코딩되어 전송됩니다.

```python
import struct

# TCG Control Tokens (예시, 스펙 3.2.2 정의 기준)
CALL_TOKEN = 0xF8
START_TRANSACTION_TOKEN = 0xFB
END_TRANSACTION_TOKEN = 0xFC

class TCGSession:
    def __init__(self, connection, host_session_id, tper_session_id):
        self.connection = connection
        self.host_session_id = host_session_id
        self.tper_session_id = tper_session_id

    def begin_transaction(self):
        """1. 트랜잭션 열기"""
        print("Starting transaction...")
        # StartTransaction 토큰 전송
        payload = bytes([START_TRANSACTION_TOKEN])
        self.connection.send_payload(self.host_session_id, self.tper_session_id, payload)
        
    def end_transaction(self, commit=True):
        """3. 트랜잭션 커밋 또는 중단 (Abort)"""
        status_code = 0x00 if commit else 0x01  # 0x00은 Success/Commit, 이외는 Abort를 의미
        print(f"Ending transaction... (Commit={commit})")
        # EndTransaction 토큰 및 상태 코드 전송
        payload = bytes([END_TRANSACTION_TOKEN, status_code])
        self.connection.send_payload(self.host_session_id, self.tper_session_id, payload)

    def execute_method(self, object_uid, method_uid, params):
        """2. 트랜잭션 내에서 메서드 호출 (예: Set / Get 등)"""
        print(f"Executing method: Obj={object_uid.hex()}, Method={method_uid.hex()}")
        # CALL 토큰과 함께 인자 전달
        payload = bytes([CALL_TOKEN]) + object_uid + method_uid + params
        self.connection.send_payload(self.host_session_id, self.tper_session_id, payload)
        
# --- 실행 예제 ---

class VirtualTCGConnection:
    def send_payload(self, host_sid, tper_sid, payload):
        # 실제 TPer 장치로 ComPacket -> Packet -> Subpacket 형태로 전송 (직렬화 구현체 생략)
        pass

# 가상의 디바이스 커넥션과 세션 초기화
dev_conn = VirtualTCGConnection()
session = TCGSession(dev_conn, host_session_id=1, tper_session_id=100)

try:
    # 1. 트랜잭션 시작 (Transaction is opened)
    session.begin_transaction()
    
    # 2. 메서드 호출 구성
    # 예: Locking SP의 특정 범위(Range)의 ReadLock/WriteLock 상태 변경 (Set Method)
    LOCKING_RANGE_OBJ = b'\x00\x00\x08\x02\x00\x00\x00\x01' # Band1
    SET_METHOD        = b'\x00\x00\x00\x06\x00\x00\x00\x17'
    # ReadLock = True, WriteLock = True를 설정하는 파라미터라고 가정
    PARAMS = b'\x01\x01' 
    
    session.execute_method(LOCKING_RANGE_OBJ, SET_METHOD, PARAMS)
    
    # 3-a. 성공적으로 모두 전송한 경우 트랜잭션 커밋
    # 이 때 디바이스는 이 변경사항들을 원자적으로 미디어(Persistent)에 기록합니다.
    session.end_transaction(commit=True)
    
except Exception as e:
    # 3-b. 과정 중 통신 오류 등 예외가 발생하면 트랜잭션 중단 (Roll-back)
    print(f"Error occurred: {e}. Aborting transaction.")
    session.end_transaction(commit=False)
```

**코드 설명:**
- `START_TRANSACTION_TOKEN`: TPer에게 지금부터 전달하는 메서드들은 독립적으로 커밋하지 말고 트랜잭션으로 묶어 처리하라고 지시합니다.
- `execute_method`: 테이블 설정 변경(Set Method) 등을 수행합니다. 파라미터가 디바이스로 전송되지만, 아직 영구 저장(Persistent)되지는 않은 휘발성 상태입니다.
- `END_TRANSACTION_TOKEN`: 최종적으로 호스트가 이 토큰을 디바이스에 보내면, 디바이스는 그동안 전송받은 변경사항을 원자적(All-or-Nothing)으로 적용(Commit)합니다. 만약 상태 코드가 0x00이 아니거나 세션이 예기치않게 닫히면 모든 변경 내용은 완전히 무시되고 트랜잭션 이전 상태로 복구됩니다.
