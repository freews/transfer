# UCT-04 핵심 개념 정리

## 📚 근거 문서

### 1. TCG_Storage_Opal_Family_Test_Cases_v1_00_r1_00_pub.pdf
- **Section UCT-04** (Page 25): Activate Locking SP when in Manufactured-Inactive State

### 2. TCG_Storage_Architecture_Core_Spec_v2_01_r1_00.pdf
- **Section 3.3.3** (Page 38-42): ComID Management
- **Section 3.3.4.3.1** (Page 44): GET_COMID
- **Table 26** (Page 39): ComID Assignments
- **Section 5.2.3.1** (Page 132): StartSession Method
- **Section 5.2.3.2** (Page 134): SyncSession Method
- **Section 3.3.7.1.1** (Page 55-56): Regular Sessions

---

## 🎯 핵심 1: ComID 사용 규칙

### ComID 종류 (Table 26, Page 39)

```
ComID           용도
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
0x0000          Reserved
0x0001          Level 0 Discovery ONLY ⭐
0x0002-0x07FF   Reserved for TCG
0x0800-0x0FFF   Vendor Unique
0x1000-0xFFFF   Dynamic ComID (Session용) ⭐
```

### ❌ 잘못된 방법
```python
# Discovery에서 사용한 ComID 0x0001을 그대로 Session에 사용
ssd_h.security_send(
    send_buf,
    0x0001,  # ❌ 이건 Discovery 전용!
    ...
)
```

### ✅ 올바른 방법
```python
# 1. GET_COMID로 Dynamic ComID 할당받기
com_id, ext_comid = get_comid(ssd_h)  # 0x1234 같은 값 받음

# 2. Session에 할당받은 ComID 사용
ssd_h.security_send(
    send_buf,
    com_id,  # ✅ 0x1000~0xFFFF 범위
    ...
)
```

---

## 🎯 핵심 2: GET_COMID 구현

### 근거
- **TCG Core Spec Section 3.3.4.3.1** (Page 44)
- **Table 27**: GET_COMID Command Block

### 코드
```python
def get_comid(ssd_h):
    """
    GET_COMID: Dynamic ComID 할당
    
    Protocol ID = 0x02 (Communication Layer)
    ComID = 0x0000
    """
    recv_buf = ssd_h.buffer(4)
    ssd_h.security_receive(
        recv_buf,
        0x0000,  # ComID = 0x0000 for GET_COMID
        0x02,    # Protocol ID = 0x02
        0,
        4,       # 4 bytes: Extended ComID
        None
    )
    ssd_h.waitdone()
    
    response = bytes(recv_buf)
    
    # Parse Extended ComID (4 bytes)
    # Bytes 0-1: ComID
    # Bytes 2-3: ComID Extension
    extended_comid = struct.unpack('>I', response[:4])[0]
    com_id = (extended_comid >> 16) & 0xFFFF
    
    return (com_id, extended_comid)
```

---

## 🎯 핵심 3: Session ID = TSN + HSN

### 근거
- **TCG Core Spec Section 3.3.7.1.1** (Page 55-56): Regular Sessions

### 개념
```
Session Number (SN) = 8 bytes
┌────────────┬────────────┐
│ TSN (4 bytes) │ HSN (4 bytes) │
└────────────┴────────────┘

TSN = TPer Session Number (TPer가 할당)
HSN = Host Session Number (우리가 정함)
```

### HSN 결정 (우리가 정함)
```python
# 우리가 아무 값이나 정할 수 있음
HSN = 1  # 또는 2, 3, 100, 0x12345678 등 아무거나
```

### TSN 받기 (SyncSession response)

**근거: Section 5.2.3.2 SyncSession Method (Page 134)**

```
StartSession 보낼 때:
SMUID.StartSession [
    HostSessionID : uinteger,    ← HSN (우리가 정한 값)
    SPID : uidref,
    Write : boolean,
    ...
]

SyncSession 받을 때:
SMUID.SyncSession [
    HostSessionID : uinteger,    ← [0] HSN (echo)
    SPSessionID : uinteger,      ← [1] TSN (TPer가 할당!) ⭐
    ...
    [StatusList]                 ← [마지막] [0, 0, 0]
]
```

### 파싱 코드
```python
# Response payload를 token으로 파싱
parsed = parser.parse()

# parsed 구조:
# [
#   <HSN>,           ← Index 0 (우리가 보낸 HSN)
#   <TSN>,           ← Index 1 (TPer가 할당한 TSN) ⭐⭐⭐
#   [0, 0, 0]        ← Status list
# ]

hsn = bytes_to_int(parsed[0])  # Host Session Number (echo)
tsn = bytes_to_int(parsed[1])  # TPer Session Number ⭐

# Session ID 계산
session_id = (tsn << 32) | hsn
```

---

## 🎯 핵심 4: Control Session vs Regular Session

### 근거
- **TCG Core Spec Section 3.3.7.1.2** (Page 56): Control Sessions

### Control Session (session_id = 0)
```python
# Session Manager 메서드들 (StartSession, Properties 등)
# Packet.Session = 0x0000000000000000

session_id = 0

packet = PacketBuilder.build(
    session=0,  # Control Session
    ...
)
```

### Regular Session (session_id = TSN + HSN)
```python
# 일반 메서드들 (Activate, Get, Set 등)
# Packet.Session = TSN + HSN

session_id = (tsn << 32) | hsn

packet = PacketBuilder.build(
    session=session_id,  # TSN + HSN
    ...
)
```

---

## 🎯 핵심 5: Packet 구조

### 근거
- **Table 17**: ComPacket Format (Page 24)
- **Table 18**: Packet Format (Page 25)
- **Table 20**: Subpacket Format (Page 27)

### 구조
```
ComPacket {
    Header (20 bytes) {
        Reserved: 4
        ComID: 2           ⭐ GET_COMID로 받은 값
        ComID Extension: 2
        OutstandingData: 4
        MinTransfer: 4
        Length: 4
    }
    Payload = Packet
}

Packet {
    Header (24 bytes) {
        Session: 8         ⭐ 0 또는 (TSN << 32) | HSN
        SeqNumber: 4
        Reserved: 2
        AckType: 2
        Acknowledgement: 4
        Length: 4
    }
    Payload = Subpacket
}

Subpacket {
    Header (12 bytes) {
        Reserved: 6
        Kind: 2
        Length: 4
    }
    Payload = Token stream ⭐
    Padding (4-byte alignment)
}
```

---

## 📋 UCT-04 전체 흐름

### Test Sequence (근거: UCT-04, Page 25)

```python
# 1. GET_COMID
com_id, ext_comid = get_comid(ssd_h)

# 2. StartSession (Admin SP, SID)
#    - Session ID = 0 (Control Session)
#    - HSN = 1 (우리가 정함)
hsn, tsn = start_session(ssd_h, com_id, hsn=1)

# 3. Invoke Activate
#    - Session ID = (TSN << 32) | HSN (Regular Session)
invoke_activate(ssd_h, com_id, hsn, tsn)

# 4. Close Session
close_session(ssd_h, com_id)
```

---

## 🔑 핵심 요약

1. **ComID 0x0001 = Discovery 전용**
   - Session에는 **절대** 사용 불가!
   
2. **GET_COMID 필수**
   - Dynamic ComID (0x1000~0xFFFF) 할당받기
   
3. **HSN은 우리가 정함**
   - 1, 2, 3 아무거나 OK
   
4. **TSN은 TPer가 정함**
   - SyncSession response의 **Index 1**에 있음
   
5. **Session ID = (TSN << 32) | HSN**
   - Control Session: 0
   - Regular Session: TSN + HSN
   
6. **Packet 헤더에 Session ID와 ComID 필수**
   - ComPacket: ComID
   - Packet: Session ID

---

## 🧪 테스트 실행

```bash
pytest test_uct04_with_docs.py::test_activate_locking_sp_with_docs -v
```
======================================= 결론 ===============================================

TCG Core Spec Section 3.3.7.1.4 (Page 57-58):

"Because of the asynchronous nature of session startup and other Session Manager layer traffic, the StartSession/StartTrustedSession responses (SyncSession/SyncTrustedSession, respectively) are formatted as method calls back to the host."

핵심: SyncSession은 method call 형식으로 돌아옵니다!
일반 method response (결과 리스트 형식)가 아니라, method invocation 형식입니다!
Token 구조:
CALL
SMUID (Session Manager UID)
SYNC_SESSION (Method UID)
[ parameters... ]
EOD
[ status ]
파싱 시:
pythontokens = parse_tokens(payload)

# tokens[0] = CALL (0xF8)
# tokens[1] = SMUID
# tokens[2] = SYNC_SESSION UID
# tokens[3] = Parameter list [HSN, TSN, ...]
# tokens[4] = EOD
# tokens[5] = Status list [0, 0, 0]

param_list = tokens[3]  # This is a list
hsn = param_list[0]     # First parameter
tsn = param_list[1]     # Second parameter
근거 문서:

TCG Core Spec Section 3.3.7.1.4 (Page 57-58)
TCG Core Spec Section 3.2.4.2 (Page 32): Method Encoding
TCG Core Spec Section 5.2.3.2 (Page 134): SyncSession Method signature

이제 정확합니다! 😊