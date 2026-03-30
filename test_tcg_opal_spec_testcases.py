"""
TCG Storage Opal Family Test Cases (Page 53~)
==============================================
TCG Storage Opal Family Test Cases Specification v1.02 문서의
53페이지부터의 테스트 항목(SPF-05 ~ SPF-20, ETC-01 ~ ETC-24)에 대한
payload 생성, 사용법, 테스트 실험 방법을 구현합니다.

실행 방법:
    pytest test_tcg_opal_spec_testcases.py -v --tb=short

각 테스트는:
  1. TCG token stream payload를 bytes([...]) 형태로 생성
  2. build_complete_packet()으로 ComPacket 패킷을 생성
  3. 패킷 구조를 검증 (header, length, token encoding 등)

실제 장치 테스트 시:
  1. payload를 build_complete_packet()으로 감싸서 ComPacket 생성
  2. IF-SEND (Security Protocol=1)로 ComPacket을 장치에 전송
  3. IF-RECV (Security Protocol=1)로 응답 ComPacket 수신
  4. 응답 ComPacket에서 status code 확인
"""

import pytest
import struct
from correct_packet_builder import (
    SubpacketBuilder,
    PacketBuilder,
    ComPacketBuilder,
    build_complete_packet
)


# ============================================================================
# TCG UID Constants
# ============================================================================

# Session Manager UID
SMUID = bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF])

# SP UIDs
ADMIN_SP_UID = bytes([0x00, 0x00, 0x02, 0x05, 0x00, 0x00, 0x00, 0x01])
LOCKING_SP_UID = bytes([0x00, 0x00, 0x02, 0x05, 0x00, 0x00, 0x00, 0x02])

# Authority UIDs
SID_AUTHORITY_UID = bytes([0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x06])
ADMIN1_AUTHORITY_UID = bytes([0x00, 0x00, 0x00, 0x09, 0x00, 0x01, 0x00, 0x01])
USER1_AUTHORITY_UID = bytes([0x00, 0x00, 0x00, 0x09, 0x00, 0x03, 0x00, 0x01])
ANYBODY_AUTHORITY_UID = bytes([0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x01])
THISSP_UID = bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01])

# Table UIDs
LOCKING_GLOBALRANGE_UID = bytes([0x00, 0x00, 0x08, 0x02, 0x00, 0x00, 0x00, 0x01])
LOCKING_RANGE1_UID = bytes([0x00, 0x00, 0x08, 0x02, 0x00, 0x00, 0x00, 0x02])
LOCKING_RANGE2_UID = bytes([0x00, 0x00, 0x08, 0x02, 0x00, 0x00, 0x00, 0x03])
LOCKINGINFO_UID = bytes([0x00, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00, 0x01])
MBRCONTROL_UID = bytes([0x00, 0x00, 0x08, 0x03, 0x00, 0x00, 0x00, 0x01])
DATASTORE_UID = bytes([0x00, 0x00, 0x10, 0x01, 0x00, 0x00, 0x00, 0x00])
DATAREMOVAL_UID = bytes([0x00, 0x00, 0x11, 0x01, 0x00, 0x00, 0x00, 0x01])

# C_PIN UIDs
C_PIN_SID_UID = bytes([0x00, 0x00, 0x00, 0x0B, 0x00, 0x00, 0x00, 0x01])
C_PIN_ADMIN1_UID = bytes([0x00, 0x00, 0x00, 0x0B, 0x00, 0x01, 0x00, 0x01])
C_PIN_USER1_UID = bytes([0x00, 0x00, 0x00, 0x0B, 0x00, 0x03, 0x00, 0x01])
C_PIN_MSID_UID = bytes([0x00, 0x00, 0x00, 0x0B, 0x00, 0x00, 0x84, 0x02])

# Method UIDs
METHOD_STARTSESSION = bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x02])
METHOD_SYNCSESSION = bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x01])
METHOD_CLOSESESSION = bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x06])
METHOD_GET = bytes([0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x16])
METHOD_SET = bytes([0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x17])
METHOD_AUTHENTICATE = bytes([0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x1C])
METHOD_RANDOM = bytes([0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x06, 0x01])
METHOD_REVERTSP = bytes([0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x02, 0x02])
METHOD_ACTIVATE = bytes([0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x02, 0x03])
METHOD_NEXT = bytes([0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x08])
METHOD_PROPERTIES = bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x01])

# Token Constants
CALL = 0xF8
EOD = 0xF9          # END_OF_DATA
EOS = 0xFA          # END_OF_SESSION
START_LIST = 0xF0
END_LIST = 0xF1
START_NAME = 0xF2
END_NAME = 0xF3
START_TRANSACTION = 0xF7
END_TRANSACTION = 0xFC

# Short atom header for 8-byte UID
SHORT_ATOM_8 = 0xA8


def make_uid_token(uid: bytes) -> bytes:
    """UID를 short atom token으로 변환 (0xA8 + 8 bytes)"""
    return bytes([SHORT_ATOM_8]) + uid


def build_call_token_stream(invoking_id: bytes, method_id: bytes,
                            params: bytes = b"") -> bytes:
    """
    표준 CALL token stream 생성

    구조: CALL + InvokingID + MethodID + START_LIST + params + END_LIST + EOD

    사용법:
        token_stream = build_call_token_stream(
            invoking_id=ADMIN_SP_UID,
            method_id=METHOD_GET,
            params=bytes([0x01])  # parameter bytes
        )
        com_packet = build_complete_packet(token_stream)
        # com_packet을 IF-SEND로 장치에 전송
    """
    stream = bytes([CALL])
    stream += make_uid_token(invoking_id)
    stream += make_uid_token(method_id)
    stream += bytes([START_LIST])
    stream += params
    stream += bytes([END_LIST])
    stream += bytes([EOD])
    return stream


def build_startsession_payload(host_session_id: int, sp_uid: bytes,
                               write: bool = False,
                               host_signing_authority: bytes = None,
                               host_challenge: bytes = None) -> bytes:
    """
    StartSession method의 token stream 생성

    Args:
        host_session_id: Host Session ID (정수)
        sp_uid: SP UID (Admin SP 또는 Locking SP)
        write: Read-Write 세션 여부
        host_signing_authority: 인증 authority UID (optional)
        host_challenge: 인증 challenge (optional)

    사용법:
        payload = build_startsession_payload(
            host_session_id=1,
            sp_uid=ADMIN_SP_UID,
            write=True,
            host_signing_authority=SID_AUTHORITY_UID
        )
        com_packet = build_complete_packet(payload)

    실험 방법:
        1. com_packet을 IF-SEND (Protocol=1, ComID=assigned)로 전송
        2. IF-RECV로 SyncSession 응답 수신
        3. 응답의 status code 확인 (SUCCESS/NOT_AUTHORIZED/INVALID_PARAMETER)
    """
    params = bytes([host_session_id & 0xFF]) if host_session_id <= 0x3F else \
        bytes([SHORT_ATOM_8]) + host_session_id.to_bytes(8, "big")
    params += make_uid_token(sp_uid)
    params += bytes([0x01 if write else 0x00])

    if host_signing_authority:
        params += bytes([START_NAME, 0x00])  # HostChallenge name = 0
        if host_challenge:
            challenge_len = len(host_challenge)
            if challenge_len < 16:
                params += bytes([0xA0 | challenge_len]) + host_challenge
            else:
                params += bytes([0xD0 | (challenge_len >> 8), challenge_len & 0xFF]) + host_challenge
        params += bytes([END_NAME])
        params += bytes([START_NAME, 0x03])  # HostSigningAuthority name = 3
        params += make_uid_token(host_signing_authority)
        params += bytes([END_NAME])

    return build_call_token_stream(SMUID, METHOD_STARTSESSION, params)


def build_get_payload(invoking_id: bytes, start_col: int = None,
                      end_col: int = None) -> bytes:
    """
    Get method의 token stream 생성

    Args:
        invoking_id: 대상 object UID
        start_col: 시작 column 번호 (optional)
        end_col: 끝 column 번호 (optional)

    사용법:
        payload = build_get_payload(C_PIN_SID_UID, start_col=3, end_col=3)
        com_packet = build_complete_packet(payload)

    실험 방법:
        1. 먼저 StartSession으로 세션 수립
        2. Get payload를 build_complete_packet()으로 감싸 IF-SEND 전송
        3. IF-RECV로 응답 수신하여 반환 값 확인
    """
    params = b""
    if start_col is not None or end_col is not None:
        params += bytes([START_LIST])  # cellblock
        if start_col is not None:
            params += bytes([START_NAME, 0x03, start_col, END_NAME])
        if end_col is not None:
            params += bytes([START_NAME, 0x04, end_col, END_NAME])
        params += bytes([END_LIST])
    return build_call_token_stream(invoking_id, METHOD_GET, params)


def build_set_payload(invoking_id: bytes, col_values: list) -> bytes:
    """
    Set method의 token stream 생성

    Args:
        invoking_id: 대상 object UID
        col_values: [(col_num, value_bytes), ...] 리스트

    사용법:
        payload = build_set_payload(
            LOCKING_GLOBALRANGE_UID,
            [(5, bytes([0x01])),  # ReadLocked = TRUE
             (6, bytes([0x01]))]  # WriteLocked = TRUE
        )
        com_packet = build_complete_packet(payload)
    """
    params = bytes([START_NAME, 0x01, START_LIST])  # Values
    for col_num, value in col_values:
        params += bytes([START_NAME, col_num]) + value + bytes([END_NAME])
    params += bytes([END_LIST, END_NAME])
    return build_call_token_stream(invoking_id, METHOD_SET, params)


def verify_packet_structure(com_packet: bytes, token_stream: bytes):
    """ComPacket 구조 검증 헬퍼"""
    padding = (4 - (len(token_stream) % 4)) % 4
    expected_size = 20 + 24 + 12 + len(token_stream) + padding
    assert len(com_packet) == expected_size, \
        f"ComPacket size mismatch: expected={expected_size}, actual={len(com_packet)}"
    com_id = struct.unpack(">H", com_packet[4:6])[0]
    assert com_id == 0x0001, f"ComID should be 0x0001, got 0x{com_id:04X}"
    return True


# ============================================================================
# SPF-05: Tries Reset on Power Cycle (Page 53-55)
# ============================================================================
class TestSPF05_TriesResetOnPowerCycle:
    """
    SPF-05: Tries 값이 power cycle 시 리셋되는지 검증

    Prerequisites: User1 is enabled

    실험 방법:
        1. SID/Admin1/User1의 TryLimit 조회
        2. 잘못된 password로 Tries를 TryLimit까지 증가
        3. Power cycle 수행
        4. Tries 값이 0으로 리셋되었는지 확인

    Expected: Power cycle 후 모든 Authority의 Tries = 0
    """

    def test_step1_get_sid_trylimit(self):
        """Step 1-3: Admin SP 세션 열고 SID C_PIN TryLimit 조회"""
        token_stream = build_startsession_payload(
            host_session_id=1,
            sp_uid=ADMIN_SP_UID,
            write=True,
            host_signing_authority=SID_AUTHORITY_UID
        )
        com_packet = build_complete_packet(token_stream)
        verify_packet_structure(com_packet, token_stream)

        get_payload = build_get_payload(C_PIN_SID_UID, start_col=5, end_col=5)
        com_get = build_complete_packet(get_payload)
        verify_packet_structure(com_get, get_payload)

    def test_step4_get_admin1_user1_trylimit(self):
        """Step 4-7: Locking SP 세션 열고 Admin1/User1 TryLimit 조회"""
        token_stream = build_startsession_payload(
            host_session_id=1,
            sp_uid=LOCKING_SP_UID,
            write=True,
            host_signing_authority=ADMIN1_AUTHORITY_UID
        )
        com_packet = build_complete_packet(token_stream)
        verify_packet_structure(com_packet, token_stream)

        get_admin1 = build_get_payload(C_PIN_ADMIN1_UID, start_col=5, end_col=5)
        com_get_admin1 = build_complete_packet(get_admin1)
        verify_packet_structure(com_get_admin1, get_admin1)

        get_user1 = build_get_payload(C_PIN_USER1_UID, start_col=5, end_col=5)
        com_get_user1 = build_complete_packet(get_user1)
        verify_packet_structure(com_get_user1, get_user1)

    def test_step8_failed_auth_sid(self):
        """Step 8: 잘못된 challenge로 SID 인증 시도 (TryLimit>0인 경우)"""
        wrong_challenge = bytes([0xDE, 0xAD, 0xBE, 0xEF])
        token_stream = build_startsession_payload(
            host_session_id=1,
            sp_uid=ADMIN_SP_UID,
            write=True,
            host_signing_authority=SID_AUTHORITY_UID,
            host_challenge=wrong_challenge
        )
        com_packet = build_complete_packet(token_stream)
        assert len(com_packet) > 56, "패킷이 최소 크기 이상이어야 함"
        assert com_packet[56:56+1] == bytes([CALL]), "Token stream은 CALL로 시작"

    def test_step12_verify_tries_reset_after_powercycle(self):
        """Step 12-14: Power cycle 후 Tries=0 확인"""
        token_stream = build_startsession_payload(
            host_session_id=1,
            sp_uid=ADMIN_SP_UID,
            write=True,
            host_signing_authority=SID_AUTHORITY_UID
        )
        com_packet = build_complete_packet(token_stream)
        verify_packet_structure(com_packet, token_stream)

        get_tries = build_get_payload(C_PIN_SID_UID, start_col=4, end_col=4)
        com_get = build_complete_packet(get_tries)
        verify_packet_structure(com_get, get_tries)


# ============================================================================
# SPF-06: Next (Page 55-57)
# ============================================================================
class TestSPF06_Next:
    """
    SPF-06: Next method 검증 (Opal)

    실험 방법:
        1. Locking SP 세션 수립
        2. Next method로 Locking table의 UID 목록 조회
        3. Where/Count 파라미터로 특정 UID 조회
    """

    def test_next_locking_table(self):
        """Next on Locking table with empty params"""
        locking_table_uid = bytes([0x00, 0x00, 0x08, 0x02, 0x00, 0x00, 0x00, 0x00])
        token_stream = build_call_token_stream(locking_table_uid, METHOD_NEXT)
        com_packet = build_complete_packet(token_stream)
        verify_packet_structure(com_packet, token_stream)

    def test_next_with_where_count(self):
        """Next on Locking table with Where and Count=1"""
        locking_table_uid = bytes([0x00, 0x00, 0x08, 0x02, 0x00, 0x00, 0x00, 0x00])
        first_uid = LOCKING_GLOBALRANGE_UID
        params = bytes([START_NAME, 0x00])
        params += make_uid_token(first_uid)
        params += bytes([END_NAME])
        params += bytes([START_NAME, 0x01, 0x01, END_NAME])
        token_stream = build_call_token_stream(locking_table_uid, METHOD_NEXT, params)
        com_packet = build_complete_packet(token_stream)
        verify_packet_structure(com_packet, token_stream)

    def test_next_methodid_table(self):
        """Next on MethodID table (Opalite/Pyrite/Ruby)"""
        methodid_table_uid = bytes([0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00])
        token_stream = build_call_token_stream(methodid_table_uid, METHOD_NEXT)
        com_packet = build_complete_packet(token_stream)
        verify_packet_structure(com_packet, token_stream)


# ============================================================================
# SPF-07: Host Session Number (Page 57)
# ============================================================================
class TestSPF07_HostSessionNumber:
    """
    SPF-07: HSN이 SyncSession 응답에 올바르게 반영되는지 검증

    실험 방법:
        1. 임의의 HSN으로 StartSession
        2. SyncSession 응답의 HSN 확인
        3. Get 응답 Packet의 HSN 확인
    """

    def test_arbitrary_hsn(self):
        """임의의 HSN=0x12345678로 StartSession"""
        hsn = 0x12345678
        params = bytes([SHORT_ATOM_8]) + hsn.to_bytes(8, "big")
        params += make_uid_token(ADMIN_SP_UID)
        params += bytes([0x01])  # Write=TRUE
        params += bytes([START_NAME, 0x03])
        params += make_uid_token(SID_AUTHORITY_UID)
        params += bytes([END_NAME])
        token_stream = build_call_token_stream(SMUID, METHOD_STARTSESSION, params)
        com_packet = build_complete_packet(token_stream)
        verify_packet_structure(com_packet, token_stream)

    def test_get_msid_pin(self):
        """Get MSID C_PIN credentials PIN column"""
        get_payload = build_get_payload(C_PIN_MSID_UID, start_col=3, end_col=3)
        com_packet = build_complete_packet(get_payload)
        verify_packet_structure(com_packet, get_payload)


# ============================================================================
# SPF-08: RevertSP (Page 58-60)
# ============================================================================
class TestSPF08_RevertSP:
    """
    SPF-08: RevertSP 검증 (3 cases)

    Case 1: KeepGlobalRangeKey 생략
    Case 2: KeepGlobalRangeKey = FALSE
    Case 3: KeepGlobalRangeKey = TRUE
    """

    def test_case1_revertsp_omitted(self):
        """Case 1: RevertSP with KeepGlobalRangeKey omitted"""
        token_stream = build_call_token_stream(LOCKING_SP_UID, METHOD_REVERTSP)
        com_packet = build_complete_packet(token_stream)
        verify_packet_structure(com_packet, token_stream)

    def test_case2_revertsp_false(self):
        """Case 2: RevertSP with KeepGlobalRangeKey=FALSE"""
        params = bytes([START_NAME, 0x06, 0x00, END_NAME])
        token_stream = build_call_token_stream(LOCKING_SP_UID, METHOD_REVERTSP, params)
        com_packet = build_complete_packet(token_stream)
        verify_packet_structure(com_packet, token_stream)

    def test_case3_revertsp_true(self):
        """Case 3: RevertSP with KeepGlobalRangeKey=TRUE"""
        params = bytes([START_NAME, 0x06, 0x01, END_NAME])
        token_stream = build_call_token_stream(LOCKING_SP_UID, METHOD_REVERTSP, params)
        com_packet = build_complete_packet(token_stream)
        verify_packet_structure(com_packet, token_stream)


# ============================================================================
# SPF-09: Range Alignment Verification (Page 60-61)
# ============================================================================
class TestSPF09_RangeAlignment:
    """
    SPF-09: Locking Range alignment 검증

    Prerequisites: AlignmentRequired = TRUE
    """

    def test_get_locking_info(self):
        """LockingInfo table에서 alignment 정보 조회"""
        get_payload = build_get_payload(LOCKINGINFO_UID)
        com_packet = build_complete_packet(get_payload)
        verify_packet_structure(com_packet, get_payload)

    def test_set_aligned_range(self):
        """RangeStart/RangeLength를 alignment에 맞게 설정"""
        payload = build_set_payload(LOCKING_RANGE1_UID, [
            (0x03, bytes([0x00])),     # RangeStart = 0
            (0x04, bytes([0x40])),     # RangeLength = 64
        ])
        com_packet = build_complete_packet(payload)
        verify_packet_structure(com_packet, payload)


# ============================================================================
# SPF-10: Byte Table Access Granularity (Page 61-62)
# ============================================================================
class TestSPF10_ByteTableAccessGranularity:
    """SPF-10: DataStore table의 MandatoryWriteGranularity 검증"""

    def test_get_write_granularity(self):
        """DataStore의 MandatoryWriteGranularity 조회"""
        get_payload = build_get_payload(DATASTORE_UID)
        com_packet = build_complete_packet(get_payload)
        verify_packet_structure(com_packet, get_payload)

    def test_write_datastore(self):
        """DataStore에 granularity 배수만큼 0 쓰기"""
        payload = build_set_payload(DATASTORE_UID, [
            (0x00, bytes(64)),  # 64 bytes of zeros
        ])
        com_packet = build_complete_packet(payload)
        assert len(com_packet) > 56


# ============================================================================
# SPF-11: Stack Reset (Page 62)
# ============================================================================
class TestSPF11_StackReset:
    """
    SPF-11: Stack Reset으로 uncommitted changes가 rollback 되는지 검증

    Prerequisites: User1 is not enabled
    """

    def test_start_transaction(self):
        """StartTransaction token stream 생성"""
        token_stream = bytes([START_TRANSACTION, 0x00])
        com_packet = build_complete_packet(token_stream)
        verify_packet_structure(com_packet, token_stream)

    def test_set_user1_enabled(self):
        """User1 Authority Enabled = TRUE 설정 payload"""
        payload = build_set_payload(USER1_AUTHORITY_UID, [
            (0x05, bytes([0x01])),  # Enabled = TRUE
        ])
        com_packet = build_complete_packet(payload)
        verify_packet_structure(com_packet, payload)

    def test_get_user1_enabled_after_reset(self):
        """Stack Reset 후 User1 Enabled 조회 (FALSE 예상)"""
        get_payload = build_get_payload(USER1_AUTHORITY_UID, start_col=5, end_col=5)
        com_packet = build_complete_packet(get_payload)
        verify_packet_structure(com_packet, get_payload)


# ============================================================================
# SPF-12: TPer Reset (Page 62-65)
# ============================================================================
class TestSPF12_TPerReset:
    """
    SPF-12: TPer Reset 후 LockOnReset 동작 검증

    Case 1: Locking_GlobalRange의 ReadLocked/WriteLocked가 TRUE로 변경
    Case 2: MBR Done이 FALSE로 리셋
    """

    def test_case1_get_lock_status(self):
        """TPer Reset 후 GlobalRange lock 상태 조회"""
        get_payload = build_get_payload(
            LOCKING_GLOBALRANGE_UID, start_col=5, end_col=6
        )
        com_packet = build_complete_packet(get_payload)
        verify_packet_structure(com_packet, get_payload)

    def test_case2_get_mbr_done(self):
        """TPer Reset 후 MBRControl Done column 조회"""
        get_payload = build_get_payload(MBRCONTROL_UID, start_col=2, end_col=2)
        com_packet = build_complete_packet(get_payload)
        verify_packet_structure(com_packet, get_payload)


# ============================================================================
# SPF-13: Authenticate (Page 65)
# ============================================================================
class TestSPF13_Authenticate:
    """
    SPF-13: Authenticate method 검증

    실험 방법:
        1. Admin SP에 Read-Only 세션 수립
        2. Authenticate(SID, PIN) 호출
        3. C_PIN_SID의 UID column 조회 가능 확인
    """

    def test_authenticate_sid(self):
        """Authenticate method with SID authority"""
        pin_value = bytes([0x00] * 4)  # placeholder PIN
        params = bytes([START_NAME, 0x00])
        params += make_uid_token(SID_AUTHORITY_UID)
        params += bytes([END_NAME])
        params += bytes([START_NAME, 0x01])
        if len(pin_value) < 16:
            params += bytes([0xA0 | len(pin_value)]) + pin_value
        else:
            params += bytes([0xD0 | (len(pin_value) >> 8), len(pin_value) & 0xFF]) + pin_value
        params += bytes([END_NAME])
        token_stream = build_call_token_stream(THISSP_UID, METHOD_AUTHENTICATE, params)
        com_packet = build_complete_packet(token_stream)
        verify_packet_structure(com_packet, token_stream)

    def test_get_cpin_uid(self):
        """SID C_PIN의 UID column Get"""
        get_payload = build_get_payload(C_PIN_SID_UID, start_col=0, end_col=0)
        com_packet = build_complete_packet(get_payload)
        verify_packet_structure(com_packet, get_payload)


# ============================================================================
# SPF-15: Random (Page 66)
# ============================================================================
class TestSPF15_Random:
    """
    SPF-15: Random method 검증

    Expected: 32바이트 난수 2회 호출, 값이 다르고 all-0/all-1이 아닌지 확인
    """

    def test_random_method(self):
        """Random method with Count=32"""
        params = bytes([START_NAME, 0x00, 0x20, END_NAME])  # Count=32
        token_stream = build_call_token_stream(THISSP_UID, METHOD_RANDOM, params)
        com_packet = build_complete_packet(token_stream)
        verify_packet_structure(com_packet, token_stream)


# ============================================================================
# SPF-16: CommonName (Page 66-67)
# ============================================================================
class TestSPF16_CommonName:
    """SPF-16: CommonName column Set/Get 검증"""

    def test_set_commonname_admin1(self):
        """Admin1 authority의 CommonName 설정"""
        magic = bytes([0xDE, 0xAD, 0xBE, 0xEF])
        payload = build_set_payload(ADMIN1_AUTHORITY_UID, [
            (0x02, magic),  # CommonName column
        ])
        com_packet = build_complete_packet(payload)
        verify_packet_structure(com_packet, payload)

    def test_get_commonname_admin1(self):
        """Admin1 authority의 CommonName 조회"""
        get_payload = build_get_payload(ADMIN1_AUTHORITY_UID, start_col=2, end_col=2)
        com_packet = build_complete_packet(get_payload)
        verify_packet_structure(com_packet, get_payload)


# ============================================================================
# SPF-17: Additional DataStore Tables (Page 67-69)
# ============================================================================
class TestSPF17_AdditionalDataStoreTables:
    """SPF-17: Activate with DataStoreTableSize 파라미터 검증"""

    def test_activate_with_datastore_size(self):
        """Activate method with DataStoreTableSize parameter"""
        params = bytes([START_NAME, 0x01])
        params += bytes([START_LIST])
        params += bytes([SHORT_ATOM_8]) + (1024).to_bytes(8, "big")
        params += bytes([END_LIST])
        params += bytes([END_NAME])
        token_stream = build_call_token_stream(LOCKING_SP_UID, METHOD_ACTIVATE, params)
        com_packet = build_complete_packet(token_stream)
        verify_packet_structure(com_packet, token_stream)


# ============================================================================
# SPF-18: Range Crossing Behavior (Page 69-70)
# ============================================================================
class TestSPF18_RangeCrossing:
    """SPF-18: Range crossing 동작 검증"""

    def test_setup_range1(self):
        """Locking_Range1 설정"""
        payload = build_set_payload(LOCKING_RANGE1_UID, [
            (0x03, bytes([0x00])),     # RangeStart
            (0x04, bytes([0x40])),     # RangeLength = 64
        ])
        com_packet = build_complete_packet(payload)
        verify_packet_structure(com_packet, payload)


# ============================================================================
# SPF-19: Block SID Authentication (Page 70-71)
# ============================================================================
class TestSPF19_BlockSIDAuth:
    """
    SPF-19: Block SID Authentication 검증

    IF-SEND(Protocol=0x02, ComID=0x0005) payload 생성
    """

    def test_block_sid_payload(self):
        """Block SID IF-SEND payload: ClearEvents.HardwareReset=1"""
        payload = bytes([0x01])  # HardwareReset bit = 1
        assert len(payload) == 1

    def test_startsession_after_block(self):
        """Block SID 후 SID로 StartSession (NOT_AUTHORIZED 예상)"""
        token_stream = build_startsession_payload(
            host_session_id=1,
            sp_uid=ADMIN_SP_UID,
            write=True,
            host_signing_authority=SID_AUTHORITY_UID
        )
        com_packet = build_complete_packet(token_stream)
        verify_packet_structure(com_packet, token_stream)


# ============================================================================
# SPF-20: Data Removal Mechanism (Page 71-72)
# ============================================================================
class TestSPF20_DataRemoval:
    """SPF-20: ActiveDataRemovalMechanism column Get/Set 검증"""

    def test_get_active_mechanism(self):
        """DataRemovalMechanism table의 ActiveDataRemovalMechanism 조회"""
        get_payload = build_get_payload(DATAREMOVAL_UID, start_col=1, end_col=1)
        com_packet = build_complete_packet(get_payload)
        verify_packet_structure(com_packet, get_payload)

    def test_set_crypto_erase(self):
        """Cryptographic Erase Data Removal Mechanism 설정"""
        payload = build_set_payload(DATAREMOVAL_UID, [
            (0x01, bytes([0x01])),  # ActiveDataRemovalMechanism = CryptoErase
        ])
        com_packet = build_complete_packet(payload)
        verify_packet_structure(com_packet, payload)


# ============================================================================
# ETC-01: Native Protocol Read/Write Locked Error (Page 73-74)
# ============================================================================
class TestETC01_ReadWriteLockedError:
    """
    ETC-01: GlobalRange locked 상태에서 Read/Write 명령 시 Data Protection Error

    Prerequisites: GlobalRange ReadLocked=WriteLocked=TRUE
    Expected: 모든 Read/Write 명령 FAIL + Data Protection Error
    """

    def test_prerequisites_set_locked(self):
        """GlobalRange ReadLocked/WriteLocked = TRUE 설정"""
        payload = build_set_payload(LOCKING_GLOBALRANGE_UID, [
            (0x05, bytes([0x01])),  # ReadLocked = TRUE
            (0x06, bytes([0x01])),  # WriteLocked = TRUE
            (0x07, bytes([0x01])),  # ReadLockEnabled = TRUE
            (0x08, bytes([0x01])),  # WriteLockEnabled = TRUE
        ])
        com_packet = build_complete_packet(payload)
        verify_packet_structure(com_packet, payload)


# ============================================================================
# ETC-02: IF-SEND/IF-RECV Synchronous Protocol (Page 74)
# ============================================================================
class TestETC02_SyncProtocol:
    """
    ETC-02: Synchronous protocol violation 검증

    실험: IF-SEND 후 IF-RECV 없이 다시 IF-SEND → error
    """

    def test_properties_method(self):
        """Properties method payload"""
        token_stream = build_call_token_stream(SMUID, METHOD_PROPERTIES)
        com_packet = build_complete_packet(token_stream)
        verify_packet_structure(com_packet, token_stream)


# ============================================================================
# ETC-03: Invalid IF-SEND Transfer Length (Page 75)
# ============================================================================
class TestETC03_InvalidTransferLength:
    """ETC-03: Transfer Length > MaxComPacketSize 시 에러"""

    def test_properties_for_max_size(self):
        """Properties로 MaxComPacketSize 조회"""
        token_stream = build_call_token_stream(SMUID, METHOD_PROPERTIES)
        com_packet = build_complete_packet(token_stream)
        verify_packet_structure(com_packet, token_stream)


# ============================================================================
# ETC-04: Invalid SessionID (Page 75-76)
# ============================================================================
class TestETC04_InvalidSessionID:
    """ETC-04: 잘못된 SessionID로 Get 호출"""

    def test_get_with_wrong_session(self):
        """MSID C_PIN Get payload (잘못된 session에서 사용)"""
        get_payload = build_get_payload(C_PIN_MSID_UID, start_col=3, end_col=3)
        com_packet = build_complete_packet(get_payload)
        verify_packet_structure(com_packet, get_payload)
        # 실제 테스트: Packet header의 Session 필드를 잘못된 값으로 설정하여 전송
        wrong_session_packet = PacketBuilder.build(
            session=0xDEADBEEFCAFEBABE,
            seq_number=0,
            subpackets=[SubpacketBuilder.build(get_payload)]
        )
        assert struct.unpack(">Q", wrong_session_packet[0:8])[0] == 0xDEADBEEFCAFEBABE


# ============================================================================
# ETC-05: Unexpected Token Outside of Method - Regular Session (Page 76)
# ============================================================================
class TestETC05_UnexpectedTokenRegular:
    """
    ETC-05: Method 외부에 EndList Token이 있는 경우

    실험: Set method 앞에 END_LIST 토큰 삽입
    Expected: ComPacket "All Response(s) returned" 또는 CloseSession
    """

    def test_endlist_before_call(self):
        """END_LIST + Set method payload (malformed)"""
        normal_set = build_set_payload(USER1_AUTHORITY_UID, [
            (0x05, bytes([0x00])),  # Enabled = FALSE
        ])
        # END_LIST를 CALL 앞에 삽입한 malformed stream
        malformed = bytes([END_LIST]) + normal_set
        com_packet = build_complete_packet(malformed)
        verify_packet_structure(com_packet, malformed)
        # 첫 바이트가 END_LIST인지 확인
        payload_start = 20 + 24 + 12
        assert com_packet[payload_start] == END_LIST


# ============================================================================
# ETC-06: Unexpected Token in Method Header - Regular Session (Page 76-77)
# ============================================================================
class TestETC06_UnexpectedTokenInHeader:
    """
    ETC-06: CALL 직후에 END_LIST Token

    Expected: NOT_AUTHORIZED 또는 CloseSession
    """

    def test_endlist_after_call(self):
        """CALL + END_LIST (malformed method header)"""
        malformed = bytes([CALL, END_LIST])
        com_packet = build_complete_packet(malformed)
        verify_packet_structure(com_packet, malformed)


# ============================================================================
# ETC-07: Unexpected Token Outside of Method - Control Session (Page 77)
# ============================================================================
class TestETC07_UnexpectedTokenControl:
    """ETC-07: Control session에서 CALL 전에 END_LIST"""

    def test_endlist_before_startsession(self):
        """END_LIST + StartSession (malformed)"""
        normal = build_startsession_payload(1, LOCKING_SP_UID)
        malformed = bytes([END_LIST]) + normal
        com_packet = build_complete_packet(malformed)
        verify_packet_structure(com_packet, malformed)


# ============================================================================
# ETC-08: Unexpected Token in Parameter List - Control Session (Page 78)
# ============================================================================
class TestETC08_UnexpectedTokenInParams:
    """ETC-08: Properties method에 중복 START_LIST"""

    def test_double_startlist_properties(self):
        """Properties with extra START_LIST in params"""
        params = bytes([START_LIST])  # extra START_LIST
        token_stream = build_call_token_stream(SMUID, METHOD_PROPERTIES, params)
        com_packet = build_complete_packet(token_stream)
        verify_packet_structure(com_packet, token_stream)


# ============================================================================
# ETC-09: Exceeding Transaction Limit (Page 78-79)
# ============================================================================
class TestETC09_ExceedingTransactionLimit:
    """ETC-09: MaxTransactionLimit+1 StartTransaction tokens"""

    def test_multiple_start_transactions(self):
        """5개의 StartTransaction token (MaxTransactionLimit+1)"""
        tokens = bytes([START_TRANSACTION, 0x00] * 5)
        com_packet = build_complete_packet(tokens)
        verify_packet_structure(com_packet, tokens)


# ============================================================================
# ETC-10: Invalid Invoking ID - Get (Page 79-82, 4 cases)
# ============================================================================
class TestETC10_InvalidInvokingIDGet:
    """ETC-10: 존재하지 않는 UID로 Get 호출"""

    def test_case1_nonexistent_row(self):
        """Case1: LockingInfo row 5 (존재하지 않는 row)"""
        invalid_uid = bytes([0x00, 0x00, 0x08, 0x01, 0xAA, 0xBB, 0xCC, 0xDD])
        get_payload = build_get_payload(invalid_uid)
        com_packet = build_complete_packet(get_payload)
        verify_packet_structure(com_packet, get_payload)

    def test_case2_datastore_nobody(self):
        """Case2: Anybody authority로 DataStore Get → NOT_AUTHORIZED"""
        get_payload = build_get_payload(DATASTORE_UID)
        com_packet = build_complete_packet(get_payload)
        verify_packet_structure(com_packet, get_payload)

    def test_case3_cpin_admin1_restricted(self):
        """Case3: Admin1 C_PIN에서 PIN column 접근 제한 확인"""
        get_payload = build_get_payload(C_PIN_ADMIN1_UID, start_col=3, end_col=5)
        com_packet = build_complete_packet(get_payload)
        verify_packet_structure(com_packet, get_payload)

    def test_case4_thissp_nobody(self):
        """Case4: Anybody authority로 ThisSP Get → NOT_AUTHORIZED"""
        get_payload = build_get_payload(THISSP_UID)
        com_packet = build_complete_packet(get_payload)
        verify_packet_structure(com_packet, get_payload)


# ============================================================================
# ETC-11: Invalid Invoking ID - Non-Get (Page 82)
# ============================================================================
class TestETC11_InvalidInvokingIDSet:
    """ETC-11: LockingInfo row 5 (존재하지 않는 row)에 Set 호출"""

    def test_set_invalid_uid(self):
        """Set on 00 00 08 01 00 00 00 05"""
        invalid_uid = bytes([0x00, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00, 0x05])
        payload = build_set_payload(invalid_uid, [(0x00, bytes([0x01]))])
        com_packet = build_complete_packet(payload)
        verify_packet_structure(com_packet, payload)


# ============================================================================
# ETC-12: Authorization (Page 82-83)
# ============================================================================
class TestETC12_Authorization:
    """ETC-12: 권한 없는 상태에서 Set → NOT_AUTHORIZED"""

    def test_unauthorized_set(self):
        """Read-only session에서 User1 Enabled Set (unauthorized)"""
        payload = build_set_payload(USER1_AUTHORITY_UID, [
            (0x05, bytes([0x01])),
        ])
        com_packet = build_complete_packet(payload)
        verify_packet_structure(com_packet, payload)


# ============================================================================
# ETC-13: Malformed ComPacket Header (Page 83-84)
# ============================================================================
class TestETC13_MalformedComPacket:
    """ETC-13: ComPacket Length > MaxComPacketSize"""

    def test_oversized_compacket_header(self):
        """ComPacket Length 필드를 실제보다 크게 설정"""
        payload = build_set_payload(DATASTORE_UID, [(0x00, bytes(64))])
        subpacket = SubpacketBuilder.build(payload)
        packet = PacketBuilder.build(session=0, seq_number=0, subpackets=[subpacket])
        # ComPacket header를 수동으로 생성하여 Length를 과대 설정
        oversized_length = 0xFFFFFF
        header = struct.pack(">I H H I I I",
            0, 0x0001, 0, 0, 0, oversized_length)
        malformed_com = header + packet
        com_id = struct.unpack(">H", malformed_com[4:6])[0]
        assert com_id == 0x0001
        length = struct.unpack(">I", malformed_com[16:20])[0]
        assert length == oversized_length


# ============================================================================
# ETC-14: Exceed TPer Properties - Regular Session (Page 84)
# ============================================================================
class TestETC14_ExceedTPerRegular:
    """ETC-14: MaxSubPackets+1 SubPackets 전송"""

    def test_multiple_subpackets(self):
        """MaxSubPackets+1개 SubPacket 생성"""
        set_payload = build_set_payload(DATASTORE_UID, [(0x00, bytes(4))])
        subpackets = [SubpacketBuilder.build(set_payload) for _ in range(5)]
        packet = PacketBuilder.build(session=0, seq_number=0, subpackets=subpackets)
        com_packet = ComPacketBuilder.build(com_id=0x0001, packets=[packet])
        assert len(com_packet) > 20


# ============================================================================
# ETC-15: Exceed TPer Properties - Control Session (Page 85)
# ============================================================================
class TestETC15_ExceedTPerControl:
    """ETC-15: Control session에서 MaxSubPackets+1"""

    def test_multiple_properties_subpackets(self):
        """MaxSubPackets+1개 Properties SubPacket"""
        props = build_call_token_stream(SMUID, METHOD_PROPERTIES)
        subpackets = [SubpacketBuilder.build(props) for _ in range(5)]
        packet = PacketBuilder.build(session=0, seq_number=0, subpackets=subpackets)
        com_packet = ComPacketBuilder.build(com_id=0x0001, packets=[packet])
        assert len(com_packet) > 20


# ============================================================================
# ETC-16: Overlapping Locking Ranges (Page 85-86)
# ============================================================================
class TestETC16_OverlappingRanges:
    """ETC-16: Range1과 Range2를 겹치게 설정 시 INVALID_PARAMETER"""

    def test_set_overlapping_ranges(self):
        """Range1과 Range2 동일 범위 설정"""
        payload1 = build_set_payload(LOCKING_RANGE1_UID, [
            (0x03, bytes([0x00])),  (0x04, bytes([0x40])),
        ])
        payload2 = build_set_payload(LOCKING_RANGE2_UID, [
            (0x03, bytes([0x00])),  (0x04, bytes([0x40])),
        ])
        com1 = build_complete_packet(payload1)
        com2 = build_complete_packet(payload2)
        verify_packet_structure(com1, payload1)
        verify_packet_structure(com2, payload2)


# ============================================================================
# ETC-17: Invalid Type (Page 86-87)
# ============================================================================
class TestETC17_InvalidType:
    """ETC-17: Enabled column에 잘못된 type (0xAAAA) Set"""

    def test_set_invalid_type(self):
        """User1 Enabled = 0xAAAA (invalid boolean)"""
        payload = build_set_payload(USER1_AUTHORITY_UID, [
            (0x05, bytes([0x82, 0xAA, 0xAA])),  # Short atom 2bytes: 0xAAAA
        ])
        com_packet = build_complete_packet(payload)
        verify_packet_structure(com_packet, payload)


# ============================================================================
# ETC-18: RevertSP - GlobalRange Locked (Page 87)
# ============================================================================
class TestETC18_RevertSPLocked:
    """ETC-18: GlobalRange Locked 상태에서 RevertSP(KeepData=TRUE) → FAIL"""

    def test_set_global_locked(self):
        """GlobalRange ReadLocked/WriteLocked = TRUE"""
        payload = build_set_payload(LOCKING_GLOBALRANGE_UID, [
            (0x05, bytes([0x01])),  (0x06, bytes([0x01])),
            (0x07, bytes([0x01])),  (0x08, bytes([0x01])),
        ])
        com_packet = build_complete_packet(payload)
        verify_packet_structure(com_packet, payload)

    def test_revertsp_keepdata_true(self):
        """RevertSP with KeepGlobalRangeKey=TRUE (locked에서 FAIL 예상)"""
        params = bytes([START_NAME, 0x06, 0x01, END_NAME])
        token_stream = build_call_token_stream(LOCKING_SP_UID, METHOD_REVERTSP, params)
        com_packet = build_complete_packet(token_stream)
        verify_packet_structure(com_packet, token_stream)


# ============================================================================
# ETC-19: Activate / ATA Security Interaction (Page 88)
# ============================================================================
class TestETC19_ActivateATASecurity:
    """ETC-19: ATA Security Enabled 상태에서 Activate → FAIL"""

    def test_activate_locking_sp(self):
        """Activate method on Locking SP"""
        token_stream = build_call_token_stream(LOCKING_SP_UID, METHOD_ACTIVATE)
        com_packet = build_complete_packet(token_stream)
        verify_packet_structure(com_packet, token_stream)


# ============================================================================
# ETC-20: StartSession on Inactive Locking SP (Page 88-89)
# ============================================================================
class TestETC20_InactiveLockingSP:
    """ETC-20: Manufactured-Inactive 상태의 Locking SP에 StartSession"""

    def test_startsession_inactive_sp(self):
        """StartSession to inactive Locking SP (INVALID_PARAMETER 예상)"""
        token_stream = build_startsession_payload(
            host_session_id=1, sp_uid=LOCKING_SP_UID
        )
        com_packet = build_complete_packet(token_stream)
        verify_packet_structure(com_packet, token_stream)


# ============================================================================
# ETC-21: StartSession with Incorrect HostChallenge (Page 89)
# ============================================================================
class TestETC21_IncorrectHostChallenge:
    """ETC-21: 잘못된 HostChallenge → NOT_AUTHORIZED"""

    def test_wrong_challenge(self):
        """Admin1으로 잘못된 password StartSession"""
        wrong_pw = bytes([0xFF, 0xEE, 0xDD, 0xCC])
        token_stream = build_startsession_payload(
            host_session_id=1,
            sp_uid=LOCKING_SP_UID,
            write=True,
            host_signing_authority=ADMIN1_AUTHORITY_UID,
            host_challenge=wrong_pw
        )
        com_packet = build_complete_packet(token_stream)
        verify_packet_structure(com_packet, token_stream)


# ============================================================================
# ETC-22: Multiple Sessions (Page 89-90)
# ============================================================================
class TestETC22_MultipleSessions:
    """ETC-22: RW session 2개 시도 → SP_BUSY"""

    def test_case1_two_rw_sessions(self):
        """두 번째 RW StartSession payload"""
        token_stream = build_startsession_payload(
            host_session_id=2,
            sp_uid=LOCKING_SP_UID,
            write=True
        )
        com_packet = build_complete_packet(token_stream)
        verify_packet_structure(com_packet, token_stream)

    def test_case2_exceed_max_sessions(self):
        """MaxSessions+1 Read-Only sessions"""
        token_stream = build_startsession_payload(
            host_session_id=99,
            sp_uid=LOCKING_SP_UID,
            write=False
        )
        com_packet = build_complete_packet(token_stream)
        verify_packet_structure(com_packet, token_stream)


# ============================================================================
# ETC-23: Data Removal Mechanism - Set Unsupported Value (Page 90-91)
# ============================================================================
class TestETC23_UnsupportedDataRemoval:
    """ETC-23: 지원하지 않는 DataRemovalMechanism 설정 → INVALID_PARAMETER"""

    def test_set_unsupported_mechanism(self):
        """ActiveDataRemovalMechanism = 0xFF (unsupported)"""
        payload = build_set_payload(DATAREMOVAL_UID, [
            (0x01, bytes([0xFF])),
        ])
        com_packet = build_complete_packet(payload)
        verify_packet_structure(com_packet, payload)


# ============================================================================
# ETC-24: Read Locked and Write Locked Error Responses (Page 91-93)
# ============================================================================
class TestETC24_ReadWriteLockedErrors:
    """
    ETC-24: Range1의 Read/WriteLocked 조합별 에러 응답 검증

    Case A: ReadLocked=F, WriteLocked=T → Read OK, Write FAIL
    Case B: ReadLocked=T, WriteLocked=F → Read FAIL, Write OK
    Case C: ReadLocked=T, WriteLocked=T → Read FAIL, Write FAIL
    """

    def test_setup_range1(self):
        """Locking_Range1 설정: RangeStart=0, RangeLength=1024"""
        payload = build_set_payload(LOCKING_RANGE1_UID, [
            (0x03, bytes([0x00])),
            (0x04, bytes([SHORT_ATOM_8]) + (1024).to_bytes(8, "big")),
        ])
        com_packet = build_complete_packet(payload)
        assert len(com_packet) > 56

    def test_case_a_write_locked_only(self):
        """ReadLocked=F, WriteLocked=T 설정"""
        payload = build_set_payload(LOCKING_RANGE1_UID, [
            (0x05, bytes([0x00])),  # ReadLocked = FALSE
            (0x06, bytes([0x01])),  # WriteLocked = TRUE
            (0x07, bytes([0x01])),  # ReadLockEnabled = TRUE
            (0x08, bytes([0x01])),  # WriteLockEnabled = TRUE
        ])
        com_packet = build_complete_packet(payload)
        verify_packet_structure(com_packet, payload)

    def test_case_b_read_locked_only(self):
        """ReadLocked=T, WriteLocked=F 설정"""
        payload = build_set_payload(LOCKING_RANGE1_UID, [
            (0x05, bytes([0x01])),  # ReadLocked = TRUE
            (0x06, bytes([0x00])),  # WriteLocked = FALSE
            (0x07, bytes([0x01])),
            (0x08, bytes([0x01])),
        ])
        com_packet = build_complete_packet(payload)
        verify_packet_structure(com_packet, payload)

    def test_case_c_both_locked(self):
        """ReadLocked=T, WriteLocked=T 설정"""
        payload = build_set_payload(LOCKING_RANGE1_UID, [
            (0x05, bytes([0x01])),
            (0x06, bytes([0x01])),
            (0x07, bytes([0x01])),
            (0x08, bytes([0x01])),
        ])
        com_packet = build_complete_packet(payload)
        verify_packet_structure(com_packet, payload)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
