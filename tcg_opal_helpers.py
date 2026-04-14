"""
TCG Opal Generic Helper Functions
==================================

범용 Session / Table Read/Write 헬퍼 함수 모음

Dependencies:
    - correct_packet_builder.py  (ComPacket/Packet/Subpacket 빌더)
    - codec.py                   (TCG 토큰 인코딩/디코딩)

사용 예:
    from tcg_opal_helpers import open_session, close_session, table_get, table_set
"""

import struct
from typing import Optional, Tuple, Dict, Any

from correct_packet_builder import (
    build_complete_packet,
    SubpacketBuilder,
    PacketBuilder,
    ComPacketBuilder,
)
from codec import (
    encode_uid,
    encode_integer,
    encode_bytes,
    CALL, END_OF_DATA,
    START_LIST, END_LIST,
    START_NAME, END_NAME,
)


# ============================================================================
# UID 상수 (자주 쓰는 것만 — 프로젝트 UID_NAMES와 동기화)
# ============================================================================

class UID:
    # Special Purpose
    SM_UID          = bytes.fromhex("0000000000000FF")   # Session Manager
    THISSP          = bytes.fromhex("0000000000000001")

    # SP UIDs
    ADMIN_SP        = bytes.fromhex("0000020100000001")
    LOCKING_SP      = bytes.fromhex("0000020200000001")

    # Session Manager Methods
    START_SESSION   = bytes.fromhex("00000000000000FF")  # StartSession MethodID
    SYNC_SESSION    = bytes.fromhex("00000000000000FF")  # SyncSession (TPer response)

    # Method UIDs
    METHOD_GET          = bytes.fromhex("0000000600000016")
    METHOD_SET          = bytes.fromhex("0000000600000017")
    METHOD_AUTHENTICATE = bytes.fromhex("0000000600000C05")
    METHOD_CLOSE_SESSION= bytes.fromhex("0000000000000006")

    # Authority UIDs (AdminSP)
    SID             = bytes.fromhex("0000000900000006")
    PSID            = bytes.fromhex("000000090001FF01")
    ANYBODY         = bytes.fromhex("0000000900000001")
    ADMIN           = bytes.fromhex("0000000900000002")  # AdminSP::Admin
    ADMIN1          = bytes.fromhex("0000000900010001")  # LockingSP::Admin1
    MAKER           = bytes.fromhex("0000000900000003")

    # Authority UIDs (LockingSP) — User1~8
    USER1           = bytes.fromhex("0000000900030001")
    USER2           = bytes.fromhex("0000000900030002")
    USER3           = bytes.fromhex("0000000900030003")
    USER4           = bytes.fromhex("0000000900030004")
    USER5           = bytes.fromhex("0000000900030005")
    USER6           = bytes.fromhex("0000000900030006")
    USER7           = bytes.fromhex("0000000900030007")
    USER8           = bytes.fromhex("0000000900030008")

    @staticmethod
    def user(n: int) -> bytes:
        """USER n UID 동적 생성 (n=1~8)"""
        if not 1 <= n <= 8:
            raise ValueError(f"User index must be 1~8, got {n}")
        return bytes.fromhex(f"000000090003{n:04X}")


# ============================================================================
# 내부 유틸리티
# ============================================================================

SECURITY_PROTOCOL_TCG = 1   # IF-SEND/RECV protocol number

def _send(ssd_h, com_id: int, packet: bytes) -> None:
    """IF-SEND wrapper"""
    buf = ssd_h.buffer(len(packet))
    buf[:] = packet
    ssd_h.security_send(buf, com_id, SECURITY_PROTOCOL_TCG, 0, len(packet), None)
    ssd_h.waitdone()


def _recv(ssd_h, com_id: int, size: int = 2048) -> bytes:
    """IF-RECV wrapper — raw ComPacket bytes 반환"""
    buf = ssd_h.buffer(size)
    ssd_h.security_recv(buf, com_id, SECURITY_PROTOCOL_TCG, 0, size, None)
    ssd_h.waitdone()
    return bytes(buf)


def _build_session_packet(tsn: int, hsn: int, token_stream: bytes) -> bytes:
    """
    세션 내 패킷 빌드 (TSN/HSN 포함)
    StartSession 이후 모든 요청에 사용
    """
    subpacket = SubpacketBuilder.build(token_stream)
    session = (tsn << 32) | hsn          # 8 bytes: TSN(4) | HSN(4)
    packet = PacketBuilder.build(
        session=session,
        seq_number=1,
        subpackets=[subpacket],
    )
    com_packet = ComPacketBuilder.build(com_id=0x0001, packets=[packet])
    return com_packet


def _parse_sync_session(response: bytes) -> Tuple[int, int]:
    """
    SyncSession 응답에서 TSN, HSN 파싱
    Returns: (tsn, hsn)
    """
    # ComPacket(20) + Packet(24) + Subpacket(12) = offset 56 부터 payload
    PAYLOAD_OFFSET = 56
    payload = response[PAYLOAD_OFFSET:]

    tsn = 0
    hsn = 0
    i = 0
    # 토큰 스트림에서 TSN/HSN Named 파라미터 탐색
    # SyncSession 응답 구조:
    #   F8 [SM_UID] [SYNC_SESSION_METHOD] F0
    #     F4 <HSN> F5   (HostSessionID)
    #     F4 <TSN> F5   (SPSessionID = TSN)
    #   F1 F9 F0 00 00 00 F1
    while i < len(payload):
        b = payload[i]
        # Short atom: 단순 정수 탐색보다 Named token(F4/F5) 기반 파싱
        if b == 0xF4:   # START_NAME
            # name = next token value, value = following token value
            i += 1
            # name token (Short atom, 1~2 bytes)
            name_val, name_len = _read_short_atom(payload, i)
            i += name_len
            val, val_len = _read_short_atom(payload, i)
            i += val_len
            # F5 END_NAME
            if payload[i] == 0xF5:
                i += 1
            if name_val == 0:    # HostSessionID
                hsn = val
            elif name_val == 1:  # SPSessionID (= TSN)
                tsn = val
        else:
            i += 1

    return tsn, hsn


def _read_short_atom(data: bytes, offset: int) -> Tuple[int, int]:
    """
    Short Atom 1개 읽기
    Returns: (value, consumed_bytes)
    """
    b = data[offset]
    if b & 0x80 == 0:          # Tiny atom (0xxxxxxx)
        return b & 0x3F, 1
    if b & 0xC0 == 0x80:       # Short atom (10xxxxxx + n bytes)
        length = b & 0x0F
        val = int.from_bytes(data[offset+1:offset+1+length], 'big')
        return val, 1 + length
    if b & 0xE0 == 0xC0:       # Medium atom
        length = ((b & 0x07) << 8) | data[offset+1]
        val = int.from_bytes(data[offset+2:offset+2+length], 'big')
        return val, 2 + length
    return 0, 1                 # fallback


# ============================================================================
# 1. Session Open / Close
# ============================================================================

def open_session(
    ssd_h,
    com_id: int,
    sp_uid: bytes,
    authority_uid: Optional[bytes] = None,
    password: Optional[bytes] = None,
    host_session_id: int = 1,
    write: bool = True,
) -> Tuple[int, int]:
    """
    TCG Opal 세션 오픈 (StartSession + 필요시 Authenticate)

    Args:
        ssd_h           : 드라이브 핸들
        com_id          : ComID (예: 0x0001)
        sp_uid          : 대상 SP UID (UID.ADMIN_SP / UID.LOCKING_SP)
        authority_uid   : None → Anybody (Authenticate 스킵)
                          UID.ADMIN / UID.ADMIN1 / UID.SID / UID.PSID 등
        password        : None → Authenticate without challenge
                          bytes → Authenticate with HostChallenge
        host_session_id : HSN 초기값 (기본 1)
        write           : True=Read/Write 세션, False=Read-only

    Returns:
        (tsn, hsn): TPer Session Number, Host Session Number

    Examples:
        # Anybody (no auth)
        tsn, hsn = open_session(ssd_h, 0x0001, UID.ADMIN_SP)

        # SID with password
        tsn, hsn = open_session(ssd_h, 0x0001, UID.ADMIN_SP,
                                authority_uid=UID.SID, password=b'MyPassword')

        # Admin1 with password (LockingSP)
        tsn, hsn = open_session(ssd_h, 0x0001, UID.LOCKING_SP,
                                authority_uid=UID.ADMIN1, password=b'AdminPass')

        # User1 with password (LockingSP)
        tsn, hsn = open_session(ssd_h, 0x0001, UID.LOCKING_SP,
                                authority_uid=UID.user(1), password=b'User1Pass')
    """
    # ------------------------------------------------------------------ #
    # Step 1: StartSession 빌드 & 전송
    # ------------------------------------------------------------------ #
    ts = bytearray()

    ts += CALL
    ts += encode_uid(bytes.fromhex("0000000000000FF"))   # SM_UID
    ts += encode_uid(bytes.fromhex("00000000000000FF"))  # StartSession MethodID

    ts += START_LIST
    ts += encode_integer(host_session_id)                # HostSessionID
    ts += encode_uid(sp_uid)                             # SPID
    ts += encode_integer(1 if write else 0)              # Write

    # Anybody가 아닐 때: HostChallenge + HostSigningAuthority 포함
    if authority_uid is not None and authority_uid != UID.ANYBODY:
        if password is not None:
            # Named[0] = HostChallenge
            ts += START_NAME
            ts += encode_integer(0)
            ts += encode_bytes(password)
            ts += END_NAME
        # Named[3] = HostSigningAuthority
        ts += START_NAME
        ts += encode_integer(3)
        ts += encode_uid(authority_uid)
        ts += END_NAME

    ts += END_LIST
    ts += END_OF_DATA

    ts += START_LIST
    ts += encode_integer(0)
    ts += encode_integer(0)
    ts += encode_integer(0)
    ts += END_LIST

    packet = build_complete_packet(bytes(ts))
    _send(ssd_h, com_id, packet)

    # ------------------------------------------------------------------ #
    # Step 2: SyncSession 응답 수신 → TSN / HSN 파싱
    # ------------------------------------------------------------------ #
    response = _recv(ssd_h, com_id)
    tsn, hsn = _parse_sync_session(response)

    print(f"[open_session] SP={sp_uid.hex()}  TSN=0x{tsn:08X}  HSN=0x{hsn:08X}")

    # ------------------------------------------------------------------ #
    # Step 3: Authenticate (Anybody가 아닐 때)
    # ------------------------------------------------------------------ #
    if authority_uid is not None and authority_uid != UID.ANYBODY:
        _authenticate(ssd_h, com_id, tsn, hsn, authority_uid, password)

    return tsn, hsn


def _authenticate(
    ssd_h,
    com_id: int,
    tsn: int,
    hsn: int,
    authority_uid: bytes,
    password: Optional[bytes] = None,
) -> bool:
    """
    Authenticate 메서드 전송 (내부용)
    Returns: True=성공
    """
    ts = bytearray()

    ts += CALL
    ts += encode_uid(authority_uid)                      # InvokingID = Authority
    ts += encode_uid(bytes.fromhex("0000000600000C05"))  # Authenticate MethodID

    ts += START_LIST
    ts += encode_uid(authority_uid)                      # Authority

    if password is not None:
        # Named[0] = Challenge
        ts += START_NAME
        ts += encode_integer(0)
        ts += encode_bytes(password)
        ts += END_NAME

    ts += END_LIST
    ts += END_OF_DATA

    ts += START_LIST
    ts += encode_integer(0)
    ts += encode_integer(0)
    ts += encode_integer(0)
    ts += END_LIST

    packet = _build_session_packet(tsn, hsn, bytes(ts))
    _send(ssd_h, com_id, packet)

    response = _recv(ssd_h, com_id)

    # Authenticate 결과: [bool, status, ...]
    # 간단히 payload에서 첫 번째 bool token 확인
    payload = response[56:]
    success = _parse_authenticate_result(payload)
    print(f"[authenticate]  Authority={authority_uid.hex()}  Result={'PASS' if success else 'FAIL'}")
    return success


def _parse_authenticate_result(payload: bytes) -> bool:
    """
    Authenticate 응답에서 결과 bool 파싱
    응답 구조: F8 [auth_uid] [method_uid] F0 <bool> F1 F9 F0 <status> F1
    """
    # F0(START_LIST) 이후 첫 토큰이 bool
    for i, b in enumerate(payload):
        if b == 0xF0 and i + 1 < len(payload):   # START_LIST
            nxt = payload[i + 1]
            if nxt == 0x00:   # False
                return False
            if nxt == 0x01:   # True (Tiny atom 1)
                return True
    return False


def close_session(ssd_h, com_id: int, tsn: int, hsn: int) -> None:
    """
    세션 종료 (CloseSession)

    Args:
        ssd_h  : 드라이브 핸들
        com_id : ComID
        tsn    : TPer Session Number
        hsn    : Host Session Number
    """
    ts = bytearray()

    ts += CALL
    ts += encode_uid(bytes.fromhex("0000000000000FF"))   # SM_UID
    ts += encode_uid(bytes.fromhex("0000000000000006"))  # CloseSession MethodID

    ts += START_LIST
    ts += encode_integer(hsn)
    ts += encode_integer(tsn)
    ts += END_LIST
    ts += END_OF_DATA

    ts += START_LIST
    ts += encode_integer(0)
    ts += encode_integer(0)
    ts += encode_integer(0)
    ts += END_LIST

    packet = _build_session_packet(tsn, hsn, bytes(ts))
    _send(ssd_h, com_id, packet)

    _recv(ssd_h, com_id)   # 응답 drain
    print(f"[close_session] TSN=0x{tsn:08X}  HSN=0x{hsn:08X}  → Closed")


# ============================================================================
# 2. Table Read / Write
# ============================================================================

def build_get_payload(
    invoking_uid: bytes,
    tsn: int,
    hsn: int,
    start_col: Optional[int] = None,
    end_col: Optional[int] = None,
    start_row: Optional[int] = None,
    end_row: Optional[int] = None,
) -> bytes:
    """
    Get 메서드 패킷 빌드

    Args:
        invoking_uid : 대상 오브젝트/테이블 UID
        tsn, hsn     : 세션 번호
        start_col    : 시작 컬럼 번호 (Named param "startColumn")
        end_col      : 끝 컬럼 번호   (Named param "endColumn")
        start_row    : 시작 행 번호   (Named param "startRow")  — 테이블 전체 조회용
        end_row      : 끝 행 번호     (Named param "endRow")

    Returns:
        complete_packet bytes (IF-SEND 바로 사용 가능)

    Examples:
        # 오브젝트 전체 컬럼
        pkt = build_get_payload(row_uid, tsn, hsn)

        # 특정 컬럼 범위
        pkt = build_get_payload(row_uid, tsn, hsn, start_col=3, end_col=5)

        # 테이블 전체 행 범위
        pkt = build_get_payload(table_uid, tsn, hsn,
                                start_row=0, end_row=0x7FFFFFFF)
    """
    ts = bytearray()

    ts += CALL
    ts += encode_uid(invoking_uid)
    ts += encode_uid(bytes.fromhex("0000000600000016"))  # Get MethodID

    ts += START_LIST

    # Cellblock (Named params)
    ts += START_LIST

    if start_row is not None:
        ts += START_NAME
        ts += encode_integer(0)   # "startRow"
        ts += encode_integer(start_row)
        ts += END_NAME

    if end_row is not None:
        ts += START_NAME
        ts += encode_integer(1)   # "endRow"
        ts += encode_integer(end_row)
        ts += END_NAME

    if start_col is not None:
        ts += START_NAME
        ts += encode_integer(2)   # "startColumn"
        ts += encode_integer(start_col)
        ts += END_NAME

    if end_col is not None:
        ts += START_NAME
        ts += encode_integer(3)   # "endColumn"
        ts += encode_integer(end_col)
        ts += END_NAME

    ts += END_LIST   # Cellblock 끝

    ts += END_LIST
    ts += END_OF_DATA

    ts += START_LIST
    ts += encode_integer(0)
    ts += encode_integer(0)
    ts += encode_integer(0)
    ts += END_LIST

    return _build_session_packet(tsn, hsn, bytes(ts))


def build_set_payload(
    invoking_uid: bytes,
    tsn: int,
    hsn: int,
    values: Dict[int, Any],
) -> bytes:
    """
    Set 메서드 패킷 빌드

    Args:
        invoking_uid : 대상 오브젝트 UID
        tsn, hsn     : 세션 번호
        values       : {column_number: value} dict
                       value 타입:
                         int   → encode_integer
                         bytes → encode_bytes
                         bool  → encode_integer(1/0)

    Returns:
        complete_packet bytes

    Examples:
        # C_PIN 테이블 PIN 컬럼(3) 변경
        pkt = build_set_payload(cpin_uid, tsn, hsn, {3: b'NewPassword'})

        # Locking Range ReadLockEnabled(5), WriteLockEnabled(6) 설정
        pkt = build_set_payload(range_uid, tsn, hsn, {5: True, 6: True})

        # MBR Enable(1) 설정
        pkt = build_set_payload(mbrctrl_uid, tsn, hsn, {1: True})
    """
    ts = bytearray()

    ts += CALL
    ts += encode_uid(invoking_uid)
    ts += encode_uid(bytes.fromhex("0000000600000017"))  # Set MethodID

    ts += START_LIST

    # Named[1] = Values
    ts += START_NAME
    ts += encode_integer(1)   # "Values"
    ts += START_LIST

    for col_num, val in values.items():
        ts += START_NAME
        ts += encode_integer(col_num)
        if isinstance(val, bool):
            ts += encode_integer(1 if val else 0)
        elif isinstance(val, int):
            ts += encode_integer(val)
        elif isinstance(val, (bytes, bytearray)):
            ts += encode_bytes(val)
        else:
            raise TypeError(f"Unsupported value type: {type(val)} for column {col_num}")
        ts += END_NAME

    ts += END_LIST   # Values list 끝
    ts += END_NAME   # Named[1] 끝

    ts += END_LIST
    ts += END_OF_DATA

    ts += START_LIST
    ts += encode_integer(0)
    ts += encode_integer(0)
    ts += encode_integer(0)
    ts += END_LIST

    return _build_session_packet(tsn, hsn, bytes(ts))


# ============================================================================
# 3. Table send + raw recv wrapper
# ============================================================================

def table_get(
    ssd_h,
    com_id: int,
    tsn: int,
    hsn: int,
    invoking_uid: bytes,
    start_col: Optional[int] = None,
    end_col: Optional[int] = None,
    start_row: Optional[int] = None,
    end_row: Optional[int] = None,
    recv_size: int = 2048,
) -> bytes:
    """
    Get 메서드 전송 → raw response bytes 반환

    Returns:
        raw ComPacket bytes (tcg_payload_parser로 파싱 가능)
    """
    packet = build_get_payload(invoking_uid, tsn, hsn,
                               start_col, end_col, start_row, end_row)
    _send(ssd_h, com_id, packet)
    return _recv(ssd_h, com_id, recv_size)


def table_set(
    ssd_h,
    com_id: int,
    tsn: int,
    hsn: int,
    invoking_uid: bytes,
    values: Dict[int, Any],
    recv_size: int = 2048,
) -> bytes:
    """
    Set 메서드 전송 → raw response bytes 반환

    Returns:
        raw ComPacket bytes
    """
    packet = build_set_payload(invoking_uid, tsn, hsn, values)
    _send(ssd_h, com_id, packet)
    return _recv(ssd_h, com_id, recv_size)


# ============================================================================
# 사용 예시 (실제 드라이브 없이 패킷 구조 확인용)
# ============================================================================

if __name__ == "__main__":

    print("=" * 60)
    print("TCG Opal Helper Functions — 패킷 구조 확인")
    print("=" * 60)

    # ── Session 예시 (패킷만 빌드) ──────────────────────────────────
    print("\n[1] open_session 예시 (Anybody)")
    print("    open_session(ssd_h, 0x0001, UID.ADMIN_SP)")
    print("    → StartSession (no Authenticate)")

    print("\n[2] open_session 예시 (SID + password)")
    print("    open_session(ssd_h, 0x0001, UID.ADMIN_SP,")
    print("                 authority_uid=UID.SID, password=b'MyPass')")
    print("    → StartSession → SyncSession → Authenticate")

    print("\n[3] open_session 예시 (Admin1, LockingSP)")
    print("    open_session(ssd_h, 0x0001, UID.LOCKING_SP,")
    print("                 authority_uid=UID.ADMIN1, password=b'AdminPass')")

    print("\n[4] open_session 예시 (User1, LockingSP)")
    print("    open_session(ssd_h, 0x0001, UID.LOCKING_SP,")
    print("                 authority_uid=UID.user(1), password=b'User1Pass')")

    # ── Table 예시 (패킷만 빌드) ────────────────────────────────────
    TSN, HSN = 0x01000001, 0x00000001   # 예시 값

    print("\n[5] build_get_payload — 전체 컬럼")
    invoking = bytes.fromhex("0000000400010001")  # 예시 UID
    pkt = build_get_payload(invoking, TSN, HSN)
    print(f"    Packet size: {len(pkt)} bytes")

    print("\n[6] build_get_payload — 컬럼 3~5")
    pkt = build_get_payload(invoking, TSN, HSN, start_col=3, end_col=5)
    print(f"    Packet size: {len(pkt)} bytes")

    print("\n[7] build_set_payload — PIN 변경 + Enable 플래그")
    pkt = build_set_payload(invoking, TSN, HSN, {3: b'NewPass', 5: True, 6: True})
    print(f"    Packet size: {len(pkt)} bytes")

    print("\n완료. 실제 드라이브 사용 시: open_session() 호출 후 table_get/set 사용")
