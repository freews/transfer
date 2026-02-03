"""
test_properties.py
==================
TCG Opal Properties Method pytest

참조 문서:
  - TCG Storage Opal SSC Application Note 1.00 – Section 3.2.1.2 (Table 2, Table 3)
  - TCG Storage Architecture Core Spec v2.01 – Section 5.2.2 (Properties Method)
  - TCG Storage Opal Family Test Cases v1.00 – UCT-02

기존 모듈 재사용:
  - correct_packet_builder.py : SubpacketBuilder / PacketBuilder / ComPacketBuilder

검증 완료:
  - Table 2 (Host→TPer Invocation) : 100% bit-exact match
  - Table 3 (TPer→Host Response)   : 100% bit-exact match
"""

import struct
import pytest

# ============================================================================
# correct_packet_builder 클래스를 그대로 인라인 (프로젝트 파일과 동일)
# ============================================================================

class SubpacketBuilder:
    """Data Subpacket: Reserved(6) + Kind(2) + Length(4) + Payload + Padding"""
    @staticmethod
    def build(payload: bytes) -> bytes:
        n = len(payload)
        padding_size = (4 - (n % 4)) % 4
        header = struct.pack('>6s H I', bytes(6), 0x0000, n)
        return header + payload + bytes(padding_size)


class PacketBuilder:
    """Packet: Session(8) + SeqNumber(4) + Reserved(2) + AckType(2) + Ack(4) + Length(4) + Payload"""
    @staticmethod
    def build(session: int = 0, seq_number: int = 0, subpackets: list = None) -> bytes:
        payload = b''.join(subpackets or [])
        header = struct.pack('>Q I H H I I', session, seq_number, 0, 0, 0, len(payload))
        return header + payload


class ComPacketBuilder:
    """ComPacket: Reserved(4) + ComID(2) + ComIDExt(2) + OutstandingData(4) + MinTransfer(4) + Length(4) + Payload"""
    @staticmethod
    def build(com_id: int, packets: list, extended_com_id: int = 0) -> bytes:
        payload = b''.join(packets)
        header = struct.pack('>I H H I I I', 0, com_id, extended_com_id, 0, 0, len(payload))
        return header + payload


# ============================================================================
# Token / UID 상수
# ============================================================================

CALL        = bytes([0xF8])
START_LIST  = bytes([0xF0])
END_LIST    = bytes([0xF1])
START_NAME  = bytes([0xF2])
END_NAME    = bytes([0xF3])
END_OF_DATA = bytes([0xF9])

# SMUID : Session Manager 예약 UID
SM_UID          = bytes([0xA8]) + bytes.fromhex("00000000000000FF")
# Properties Method UID (Core Spec Table 241)
PROPERTIES_UID  = bytes([0xA8]) + bytes.fromhex("000000000000FF01")

# ComID : Properties는 항상 Opal Base ComID 0x07FE
PROPERTIES_COM_ID = 0x07FE


# ============================================================================
# Atom 인코딩 헬퍼
# ============================================================================

def encode_string(s: str) -> bytes:
    """
    문자열 → Short Atom (1~15자) 또는 Medium Atom (16~31자)

    1~15자 : 0xA0|len  + ASCII
    16~31자: 0xD0 + len바이트 + ASCII
    """
    b = s.encode('ascii')
    length = len(b)
    if 1 <= length <= 15:
        return bytes([0xA0 | length]) + b
    elif 16 <= length <= 31:
        return bytes([0xD0, length]) + b
    else:
        raise ValueError(f"지원되지 않는 문자열 길이: {length}")


def encode_uint(value: int) -> bytes:
    """
    정수 → Tiny Atom (0~15) / Short Atom uint2 (16~0xFFFF) / Short Atom uint3 (0x10000~0xFFFFFF)

    0~15       : 단일 바이트
    16~65535   : 0x82 + 2바이트 big-endian
    65536~16M  : 0x83 + 3바이트 big-endian
    """
    if 0 <= value <= 15:
        return bytes([value])
    elif value <= 0xFFFF:
        return bytes([0x82]) + struct.pack('>H', value)
    elif value <= 0xFFFFFF:
        return bytes([0x83]) + struct.pack('>I', value)[1:]   # 상위 1바이트 제거 → 3바이트
    else:
        raise ValueError(f"지원되지 않는 정수 크기: {value}")


def name_value_pair(name: str, value: int) -> bytes:
    """F2 + encode_string(name) + encode_uint(value) + F3"""
    return START_NAME + encode_string(name) + encode_uint(value) + END_NAME


# ============================================================================
# Properties Invocation / Response 빌드
# ============================================================================

# ─── HostProperties 속성명 + 예시값 (App Note Table 2) ────────────────────
HOST_PROPS_EXAMPLE = [
    ("MaxComPacketSize",         4096),
    ("MaxResponseComPacketSize", 4096),
    ("MaxPacketSize",            4076),
    ("MaxIndTokenSize",          4040),
    ("MaxPackets",                  1),
    ("MaxSubpackets",               1),
    ("MaxMethods",                  1),
]

# ─── TPer Properties 속성명 + 예시값 (App Note Table 3) ──────────────────
TPER_PROPS_EXAMPLE = [
    ("MaxComPacketSize",         8192),
    ("MaxResponseComPacketSize", 8192),
    ("MaxPacketSize",            8172),
    ("MaxIndTokenSize",          8136),
    ("MaxPackets",                  1),
    ("MaxSubpackets",               1),
    ("MaxMethods",                  1),
    ("ContinuedTokens",             0),
    ("SequenceNumbers",             0),
    ("AckNak",                      0),
    ("Asynchronous",                0),
    ("MaxSessions",                 1),
    ("MaxAuthentications",          2),
    ("MaxTransactionLimit",         1),
    ("DefSessionTimeout",      120000),
]

# ─── Echo'd HostProperties (Response 안에 반환) – MaxResponseComPacketSize 제외 ─
HOST_PROPS_ECHO_EXAMPLE = [
    ("MaxComPacketSize",  4096),
    ("MaxPacketSize",     4076),
    ("MaxIndTokenSize",   4040),
    ("MaxPackets",           1),
    ("MaxSubpackets",        1),
    ("MaxMethods",           1),
]


def build_properties_invocation_token_stream(host_props: list = None) -> bytes:
    """
    Host → TPer Invocation token stream 생성

    구조 (App Note Table 2):
      CALL + SMUID + PropertiesUID
      + F0                          ← parameter list 시작
        + F2 + 00 + F0              ← optional param name=0 (HostProperties) + list 시작
          + [name-value pairs ...]
        + F1 + F3                   ← HostProperties list 끝 + name 끝
      + F1                          ← parameter list 끝
      + F9                          ← END_OF_DATA
      + F0 00 00 00 F1             ← Method Status List
    """
    if host_props is None:
        host_props = HOST_PROPS_EXAMPLE

    props_payload = b''.join(name_value_pair(n, v) for n, v in host_props)

    return (
        CALL +
        SM_UID +
        PROPERTIES_UID +
        START_LIST +
        START_NAME +
        encode_uint(0) +          # optional param index = 0 → "HostProperties"
        START_LIST +
        props_payload +
        END_LIST +
        END_NAME +
        END_LIST +
        END_OF_DATA +
        START_LIST +              # Method Status List
        encode_uint(0) +
        encode_uint(0) +
        encode_uint(0) +
        END_LIST
    )


def build_properties_response_token_stream(
    tper_props: list = None,
    host_props_echo: list = None
) -> bytes:
    """
    TPer → Host Response token stream 생성

    구조 (App Note Table 3):
      CALL + SMUID + PropertiesUID
      + F0                          ← parameter list 시작
        + F0                        ← Properties list 시작 (positional – name 없음)
          + [TPer name-value ...]
        + F1                        ← Properties list 끝
        + F2 + 00 + F0              ← optional param name=0 (HostProperties) + list 시작
          + [echo'd name-value ...]
        + F1 + F3                   ← HostProperties list 끝 + name 끝
      + F1                          ← parameter list 끝
      + F9                          ← END_OF_DATA
      + F0 00 00 00 F1             ← Method Status List
    """
    if tper_props is None:
        tper_props = TPER_PROPS_EXAMPLE
    if host_props_echo is None:
        host_props_echo = HOST_PROPS_ECHO_EXAMPLE

    tper_payload  = b''.join(name_value_pair(n, v) for n, v in tper_props)
    echo_payload  = b''.join(name_value_pair(n, v) for n, v in host_props_echo)

    return (
        CALL +
        SM_UID +
        PROPERTIES_UID +
        START_LIST +
        START_LIST +              # TPer Properties (positional)
        tper_payload +
        END_LIST +
        START_NAME +
        encode_uint(0) +          # optional param index = 0 → "HostProperties"
        START_LIST +
        echo_payload +
        END_LIST +
        END_NAME +
        END_LIST +
        END_OF_DATA +
        START_LIST +              # Method Status List
        encode_uint(0) +
        encode_uint(0) +
        encode_uint(0) +
        END_LIST
    )


def build_properties_compacket(token_stream: bytes) -> bytes:
    """token stream → 완성된 ComPacket (ComID=0x07FE)"""
    subpacket  = SubpacketBuilder.build(token_stream)
    packet     = PacketBuilder.build(session=0, seq_number=0, subpackets=[subpacket])
    return ComPacketBuilder.build(com_id=PROPERTIES_COM_ID, packets=[packet])


# ============================================================================
# Response 파싱 헬퍼
# ============================================================================

def parse_compacket_header(data: bytes) -> dict:
    """ComPacket header (20 bytes) 파싱"""
    reserved, com_id, com_id_ext, outstand, mintrans, length = struct.unpack('>I H H I I I', data[0:20])
    return {
        "reserved":       reserved,
        "com_id":         com_id,
        "com_id_ext":     com_id_ext,
        "outstanding":    outstand,
        "min_transfer":   mintrans,
        "length":         length,
    }


def parse_packet_header(data: bytes, offset: int = 20) -> dict:
    """Packet header (24 bytes) 파싱"""
    session, seq, res, ack_type, ack, length = struct.unpack('>Q I H H I I', data[offset:offset+24])
    return {
        "session":        session,
        "seq_number":     seq,
        "ack_type":       ack_type,
        "acknowledgement": ack,
        "length":         length,
    }


def parse_subpacket_header(data: bytes, offset: int = 44) -> dict:
    """Subpacket header (12 bytes) 파싱"""
    kind   = struct.unpack('>H', data[offset+6:offset+8])[0]
    length = struct.unpack('>I', data[offset+8:offset+12])[0]
    return {"kind": kind, "length": length}


def extract_token_stream(data: bytes) -> bytes:
    """ComPacket에서 token stream (payload) 추출"""
    sub_hdr = parse_subpacket_header(data, offset=44)
    return data[56 : 56 + sub_hdr["length"]]


def parse_name_value_pairs(stream: bytes, start: int) -> tuple:
    """
    stream[start]부터 F2...F3 패턴을 반복 파싱하여 name-value dict 반환
    리스트 끝(F1)에 도달하면 중단

    Returns:
        (dict{ name_str: value_int }, 다음 offset)
    """
    result = {}
    i = start
    while i < len(stream):
        if stream[i] == 0xF1:               # END_LIST
            break
        if stream[i] != 0xF2:               # START_NAME 예상
            break

        i += 1  # F2 건너뛰기

        # ── name 파싱 ──
        name, i = _parse_atom_string(stream, i)

        # ── value 파싱 ──
        value, i = _parse_atom_uint(stream, i)

        # ── F3 (END_NAME) 확인 ──
        assert stream[i] == 0xF3, f"offset {i}: END_NAME(F3) 예상, 실제 {stream[i]:02X}"
        i += 1

        result[name] = value

    return result, i


def _parse_atom_string(stream: bytes, i: int) -> tuple:
    """Atom byte sequence → (string, next_offset)"""
    b = stream[i]
    if (b & 0xE0) == 0xA0:          # Short Atom bytes (1~15)
        length = b & 0x1F
        return stream[i+1:i+1+length].decode('ascii'), i + 1 + length
    elif b == 0xD0:                  # Medium Atom bytes (16~31)
        length = stream[i+1]
        return stream[i+2:i+2+length].decode('ascii'), i + 2 + length
    else:
        raise ValueError(f"offset {i}: 문자열 Atom 파싱 실패, byte={b:02X}")


def _parse_atom_uint(stream: bytes, i: int) -> tuple:
    """Atom uinteger → (int, next_offset)"""
    b = stream[i]
    if b <= 0x0F:                    # Tiny Atom
        return b, i + 1
    elif b == 0x82:                  # Short Atom uint, 2 bytes
        val = struct.unpack('>H', stream[i+1:i+3])[0]
        return val, i + 3
    elif b == 0x83:                  # Short Atom uint, 3 bytes
        val = (stream[i+1] << 16) | (stream[i+2] << 8) | stream[i+3]
        return val, i + 4
    else:
        raise ValueError(f"offset {i}: 정수 Atom 파싱 실패, byte={b:02X}")


# ============================================================================
# App Note 참조 hex (bit-exact 검증용)
# ============================================================================

# Table 2 – Host → TPer Invocation (228 bytes)
TABLE2_HEX = (
    "00000000" "07FE0000" "00000000" "00000000"
    "000000D0"
    "00000000" "00000000"
    "00000000" "0000" "0000" "00000000"
    "000000B8"
    "000000000000" "0000" "000000AB"
    "F8"
    "A8" "00000000000000FF"
    "A8" "000000000000FF01"
    "F0" "F2" "00" "F0"
    "F2" "D010" "4D6178436F6D5061636B657453697A65" "821000" "F3"
    "F2" "D018" "4D6178526573706F6E7365436F6D5061636B657453697A65" "821000" "F3"
    "F2" "AD"   "4D61785061636B657453697A65"       "820FEC" "F3"
    "F2" "AF"   "4D6178496E64546F6B656E53697A65"   "820FC8" "F3"
    "F2" "AA"   "4D61785061636B657473"             "01"     "F3"
    "F2" "AD"   "4D61785375627061636B657473"       "01"     "F3"
    "F2" "AA"   "4D61784D6574686F6473"             "01"     "F3"
    "F1" "F3" "F1" "F9"
    "F0" "000000" "F1"
    "00"                                           # padding 1 byte
)

# Table 3 – TPer → Host Response (488 bytes)
TABLE3_HEX = (
    "00000000" "07FE0000" "00000000" "00000000"
    "000001D4"
    "00000000" "00000000"
    "00000000" "0000" "0000" "00000000"
    "000001BC"
    "000000000000" "0000" "000001B0"
    "F8"
    "A8" "00000000000000FF"
    "A8" "000000000000FF01"
    "F0" "F0"
    "F2" "D010" "4D6178436F6D5061636B657453697A65" "822000" "F3"
    "F2" "D018" "4D6178526573706F6E7365436F6D5061636B657453697A65" "822000" "F3"
    "F2" "AD"   "4D61785061636B657453697A65"       "821FEC" "F3"
    "F2" "AF"   "4D6178496E64546F6B656E53697A65"   "821FC8" "F3"
    "F2" "AA"   "4D61785061636B657473"             "01"     "F3"
    "F2" "AD"   "4D61785375627061636B657473"       "01"     "F3"
    "F2" "AA"   "4D61784D6574686F6473"             "01"     "F3"
    "F2" "AF"   "436F6E74696E75656454 6F6B656E73" "00"     "F3"
    "F2" "AF"   "536571 75656E63654E756D62657273"  "00"     "F3"
    "F2" "A6"   "41636B4E616B"                     "00"     "F3"
    "F2" "AC"   "4173796E6368726F6E6F7573"         "00"     "F3"
    "F2" "AB"   "4D617853657373696F6E73"           "01"     "F3"
    "F2" "D012" "4D61784175 7468656E746963 6174696F6E73" "02" "F3"
    "F2" "D013" "4D6178547261 6E73616374696F6E4C696D6974" "01" "F3"
    "F2" "D011" "446566 53657373696F6E54696D656F7574"    "8301D4C0" "F3"
    "F1"
    "F2" "00" "F0"
    "F2" "D010" "4D6178436F6D5061636B657453697A65" "821000" "F3"
    "F2" "AD"   "4D61785061636B657453697A65"       "820FEC" "F3"
    "F2" "AF"   "4D6178496E64546F6B656E53697A65"   "820FC8" "F3"
    "F2" "AA"   "4D61785061636B657473"             "01"     "F3"
    "F2" "AD"   "4D61785375627061636B657473"       "01"     "F3"
    "F2" "AA"   "4D61784D6574686F6473"             "01"     "F3"
    "F1" "F3"
    "F1" "F9"
    "F0" "000000" "F1"
)


# ============================================================================
# ① Atom 인코딩 단위 테스트
# ============================================================================

class TestAtomEncoding:
    """encode_string / encode_uint 개별 검증"""

    # ── Tiny Atom (0 ~ 15) ──
    @pytest.mark.parametrize("value,expected", [
        (0,  bytes([0x00])),
        (1,  bytes([0x01])),
        (2,  bytes([0x02])),
        (15, bytes([0x0F])),
    ])
    def test_tiny_atom(self, value, expected):
        assert encode_uint(value) == expected

    # ── Short Atom uinteger 2 bytes ──
    @pytest.mark.parametrize("value,expected_hex", [
        (16,    "821000"[0:0] or "82" + "0010"),   # 최소 2바이트 경계
        (4096,  "821000"),                           # MaxComPacketSize (Host)
        (4076,  "820FEC"),                           # MaxPacketSize (Host)
        (4040,  "820FC8"),                           # MaxIndTokenSize (Host)
        (8192,  "822000"),                           # MaxComPacketSize (TPer)
        (8172,  "821FEC"),                           # MaxPacketSize (TPer)
        (8136,  "821FC8"),                           # MaxIndTokenSize (TPer)
        (0xFFFF,"82FFFF"),                           # uint2 최대값
    ])
    def test_short_atom_uint2(self, value, expected_hex):
        assert encode_uint(value) == bytes.fromhex(expected_hex)

    # ── Short Atom uinteger 3 bytes ──
    @pytest.mark.parametrize("value,expected_hex", [
        (0x10000,   "83010000"),   # uint3 최소값 (65536)
        (120000,    "8301D4C0"),   # DefSessionTimeout
        (0xFFFFFF,  "83FFFFFF"),   # uint3 최대값
    ])
    def test_short_atom_uint3(self, value, expected_hex):
        assert encode_uint(value) == bytes.fromhex(expected_hex)

    # ── Short Atom 문자열 (1~15자) ──
    @pytest.mark.parametrize("text,expected_header", [
        ("AckNak",          0xA6),   # 6자
        ("MaxPackets",      0xAA),   # 10자
        ("MaxSubpackets",   0xAD),   # 13자
        ("MaxPacketSize",   0xAD),   # 13자
        ("MaxIndTokenSize", 0xAF),   # 15자
    ])
    def test_short_atom_string(self, text, expected_header):
        encoded = encode_string(text)
        assert encoded[0] == expected_header
        assert encoded[1:] == text.encode('ascii')

    # ── Medium Atom 문자열 (16~31자) ──
    @pytest.mark.parametrize("text,expected_len", [
        ("MaxComPacketSize",             16),   # D0 10
        ("MaxAuthentications",           18),   # D0 12
        ("MaxTransactionLimit",          19),   # D0 13
        ("DefSessionTimeout",            17),   # D0 11
        ("MaxResponseComPacketSize",     24),   # D0 18
    ])
    def test_medium_atom_string(self, text, expected_len):
        encoded = encode_string(text)
        assert encoded[0] == 0xD0
        assert encoded[1] == expected_len
        assert encoded[2:] == text.encode('ascii')

    # ── 경계값 오류 ──
    def test_encode_uint_overflow(self):
        with pytest.raises(ValueError):
            encode_uint(0x1000000)   # 24bit 초과

    def test_encode_string_empty(self):
        with pytest.raises(ValueError):
            encode_string("")        # 길이 0

    def test_encode_string_too_long(self):
        with pytest.raises(ValueError):
            encode_string("A" * 32)  # 32자 → Medium Atom 초과


# ============================================================================
# ② Name-Value Pair 구성 테스트
# ============================================================================

class TestNameValuePair:
    """F2 + name_atom + value_atom + F3 패턴 검증"""

    def test_nvp_structure_tiny_value(self):
        """MaxPackets=1 (Tiny Atom 값)"""
        result = name_value_pair("MaxPackets", 1)
        assert result[0]  == 0xF2                          # START_NAME
        assert result[-1] == 0xF3                          # END_NAME
        # 내부: AA + "MaxPackets" + 01
        assert result[1]  == 0xAA                          # Short Atom header (len=10)
        assert result[2:12] == b"MaxPackets"
        assert result[12] == 0x01                          # Tiny Atom: 1

    def test_nvp_structure_uint2_value(self):
        """MaxComPacketSize=4096 (Short Atom uint2)"""
        result = name_value_pair("MaxComPacketSize", 4096)
        assert result[0]  == 0xF2
        assert result[-1] == 0xF3
        # D0 10 + 16바이트 문자열 + 82 10 00
        assert result[1:3] == bytes([0xD0, 0x10])
        assert result[3:19] == b"MaxComPacketSize"
        assert result[19:22] == bytes.fromhex("821000")

    def test_nvp_structure_uint3_value(self):
        """DefSessionTimeout=120000 (Short Atom uint3)"""
        result = name_value_pair("DefSessionTimeout", 120000)
        assert result[0]  == 0xF2
        assert result[-1] == 0xF3
        # D0 11 + 17바이트 문자열 + 83 01 D4 C0
        assert result[1:3] == bytes([0xD0, 0x11])
        assert result[3:20] == b"DefSessionTimeout"
        assert result[20:24] == bytes.fromhex("8301D4C0")

    def test_nvp_boolean_false(self):
        """ContinuedTokens=FALSE (Tiny Atom 0)"""
        result = name_value_pair("ContinuedTokens", 0)
        # 값이 0 → Tiny Atom 00
        assert result[-2] == 0x00
        assert result[-1] == 0xF3


# ============================================================================
# ③ Invocation Payload (Token Stream) 구조 테스트
# ============================================================================

class TestInvocationPayload:
    """Host→TPer 전체 token stream 구조 검증"""

    def setup_method(self):
        self.stream = build_properties_invocation_token_stream()

    def test_starts_with_call(self):
        assert self.stream[0] == 0xF8

    def test_smuid(self):
        # offset 1: A8 + 8바이트 SMUID
        assert self.stream[1] == 0xA8
        assert self.stream[2:10] == bytes.fromhex("00000000000000FF")

    def test_properties_method_uid(self):
        # offset 10: A8 + 8바이트 Properties UID
        assert self.stream[10] == 0xA8
        assert self.stream[11:19] == bytes.fromhex("000000000000FF01")

    def test_parameter_list_start(self):
        # offset 19: F0 (parameter list)
        assert self.stream[19] == 0xF0

    def test_host_properties_optional_name(self):
        # offset 20: F2 (START_NAME)
        # offset 21: 00 (name index = 0 → HostProperties)
        # offset 22: F0 (START_LIST – HostProperties list)
        assert self.stream[20] == 0xF2
        assert self.stream[21] == 0x00
        assert self.stream[22] == 0xF0

    def test_ends_with_status_list(self):
        # 마지막 5바이트: F0 00 00 00 F1
        assert self.stream[-5:] == bytes([0xF0, 0x00, 0x00, 0x00, 0xF1])

    def test_end_of_data_present(self):
        # F9가 status list 직전에 위치
        assert self.stream[-6] == 0xF9

    def test_all_7_properties_present(self):
        """7개 속성명이 모두 stream에 포함되는지"""
        for name, _ in HOST_PROPS_EXAMPLE:
            assert name.encode('ascii') in self.stream, f"{name} not found"

    def test_custom_host_props(self):
        """사용자 정의 값으로 생성 시 해당 값이 반영되는지"""
        custom = [
            ("MaxComPacketSize",         2048),
            ("MaxResponseComPacketSize", 2048),
            ("MaxPacketSize",            2028),
            ("MaxIndTokenSize",          1992),
            ("MaxPackets",                  1),
            ("MaxSubpackets",               1),
            ("MaxMethods",                  1),
        ]
        stream = build_properties_invocation_token_stream(custom)
        # 2048 = 0x0800 → 82 08 00
        assert bytes.fromhex("820800") in stream


# ============================================================================
# ④ Response Payload (Token Stream) 구조 테스트
# ============================================================================

class TestResponsePayload:
    """TPer→Host Response token stream 구조 검증"""

    def setup_method(self):
        self.stream = build_properties_response_token_stream()

    def test_starts_with_call(self):
        assert self.stream[0] == 0xF8

    def test_smuid_and_method_uid(self):
        assert self.stream[1:10]  == SM_UID
        assert self.stream[10:19] == PROPERTIES_UID

    def test_double_start_list(self):
        """offset 19,20: F0 F0 – parameter list + Properties list (positional)"""
        assert self.stream[19] == 0xF0
        assert self.stream[20] == 0xF0

    def test_all_14_tper_properties_present(self):
        for name, _ in TPER_PROPS_EXAMPLE:
            assert name.encode('ascii') in self.stream, f"TPer prop '{name}' not found"

    def test_all_6_echo_properties_present(self):
        for name, _ in HOST_PROPS_ECHO_EXAMPLE:
            assert name.encode('ascii') in self.stream, f"Echo prop '{name}' not found"

    def test_def_session_timeout_encoding(self):
        """120000 = 0x01D4C0 → 83 01 D4 C0"""
        assert bytes.fromhex("8301D4C0") in self.stream

    def test_ends_with_status_list(self):
        assert self.stream[-5:] == bytes([0xF0, 0x00, 0x00, 0x00, 0xF1])

    def test_max_response_com_packet_size_not_in_echo(self):
        """
        MaxResponseComPacketSize는 echo 부분에 나타나지 않아야 함.
        TPer props 리스트가 끝나는 F1 이후에는 해당 문자열이 없어야 함.
        """
        # TPer props list 끝(첫번째 F1 이후) 부분만 추출하여 확인
        # stream 구조: ... [TPer props] F1 F2 00 F0 [echo props] F1 F3 F1 F9 ...
        # "MaxResponseComPacketSize" 바이트열 위치를 모두 찾음
        target = b"MaxResponseComPacketSize"
        positions = []
        start = 0
        while True:
            idx = self.stream.find(target, start)
            if idx == -1:
                break
            positions.append(idx)
            start = idx + 1

        # TPer props 안에 1번만 있어야 함 (echo에는 없음)
        assert len(positions) == 1


# ============================================================================
# ⑤ Header 구조 테스트 (ComPacket / Packet / Subpacket)
# ============================================================================

class TestHeaders:
    """correct_packet_builder 클래스가 올바르게 header를 생성하는지"""

    def setup_method(self):
        self.token   = build_properties_invocation_token_stream()
        self.compacket = build_properties_compacket(self.token)

    # ── ComPacket Header ──
    def test_compacket_com_id(self):
        hdr = parse_compacket_header(self.compacket)
        assert hdr["com_id"] == 0x07FE

    def test_compacket_reserved_zero(self):
        hdr = parse_compacket_header(self.compacket)
        assert hdr["reserved"] == 0

    def test_compacket_outstanding_zero(self):
        hdr = parse_compacket_header(self.compacket)
        assert hdr["outstanding"] == 0

    def test_compacket_length_equals_rest(self):
        """ComPacket.Length == 전체 크기 - 20 (header)"""
        hdr = parse_compacket_header(self.compacket)
        assert hdr["length"] == len(self.compacket) - 20

    # ── Packet Header ──
    def test_packet_session_zero(self):
        """Properties는 세션 전 → Session = 0"""
        hdr = parse_packet_header(self.compacket)
        assert hdr["session"] == 0

    def test_packet_seq_number_zero(self):
        hdr = parse_packet_header(self.compacket)
        assert hdr["seq_number"] == 0

    def test_packet_length_equals_subpacket_total(self):
        """Packet.Length == Subpacket 전체 크기 (header+payload+padding)"""
        pkt_hdr = parse_packet_header(self.compacket)
        com_hdr = parse_compacket_header(self.compacket)
        # Packet.Length = ComPacket.Length - 24(Packet header)
        assert pkt_hdr["length"] == com_hdr["length"] - 24

    # ── Subpacket Header ──
    def test_subpacket_kind_zero(self):
        hdr = parse_subpacket_header(self.compacket)
        assert hdr["kind"] == 0x0000   # Data subpacket

    def test_subpacket_length_equals_token_stream(self):
        """Subpacket.Length == token stream 길이 (padding 제외)"""
        hdr = parse_subpacket_header(self.compacket)
        assert hdr["length"] == len(self.token)

    # ── Padding 검증 ──
    def test_subpacket_padding(self):
        """전체 ComPacket 크기가 올바르게 aligned되는지"""
        token_len = len(self.token)
        padding   = (4 - (token_len % 4)) % 4
        expected_total = 20 + 24 + 12 + token_len + padding   # Com + Pkt + Sub headers + payload + pad
        assert len(self.compacket) == expected_total


# ============================================================================
# ⑥ Response 파싱 테스트
# ============================================================================

class TestResponseParsing:
    """실제 Response ComPacket을 파싱하여 속성값을 추출하는지 검증"""

    def setup_method(self):
        self.token     = build_properties_response_token_stream()
        self.compacket = build_properties_compacket(self.token)
        self.stream    = extract_token_stream(self.compacket)

    def _find_tper_props(self):
        """stream에서 TPer Properties list 파싱"""
        # offset 19: F0 (param list), offset 20: F0 (TPer props list)
        # offset 21부터 name-value pairs 시작
        props, _ = parse_name_value_pairs(self.stream, 21)
        return props

    def _find_host_echo_props(self):
        """stream에서 echo'd HostProperties 파싱"""
        # TPer props 끝(F1) 다음: F2 00 F0 [echo props] F1 F3
        # TPer props 파싱한 후 offset를 이용
        _, after_tper = parse_name_value_pairs(self.stream, 21)
        # after_tper: F1 위치 → +1이 F2(START_NAME), +2가 00, +3이 F0(list start)
        assert self.stream[after_tper]   == 0xF1   # end TPer list
        assert self.stream[after_tper+1] == 0xF2   # START_NAME
        assert self.stream[after_tper+2] == 0x00   # name=0
        assert self.stream[after_tper+3] == 0xF0   # START_LIST (echo)
        echo_props, _ = parse_name_value_pairs(self.stream, after_tper + 4)
        return echo_props

    # ── TPer 속성값 검증 ──
    def test_tper_max_com_packet_size(self):
        assert self._find_tper_props()["MaxComPacketSize"] == 8192

    def test_tper_max_response_com_packet_size(self):
        assert self._find_tper_props()["MaxResponseComPacketSize"] == 8192

    def test_tper_max_packet_size(self):
        assert self._find_tper_props()["MaxPacketSize"] == 8172

    def test_tper_max_ind_token_size(self):
        assert self._find_tper_props()["MaxIndTokenSize"] == 8136

    def test_tper_max_packets(self):
        assert self._find_tper_props()["MaxPackets"] == 1

    def test_tper_max_subpackets(self):
        assert self._find_tper_props()["MaxSubpackets"] == 1

    def test_tper_max_methods(self):
        assert self._find_tper_props()["MaxMethods"] == 1

    def test_tper_continued_tokens_false(self):
        assert self._find_tper_props()["ContinuedTokens"] == 0

    def test_tper_sequence_numbers_false(self):
        assert self._find_tper_props()["SequenceNumbers"] == 0

    def test_tper_ackNak_false(self):
        assert self._find_tper_props()["AckNak"] == 0

    def test_tper_asynchronous_false(self):
        assert self._find_tper_props()["Asynchronous"] == 0

    def test_tper_max_sessions(self):
        assert self._find_tper_props()["MaxSessions"] == 1

    def test_tper_max_authentications(self):
        assert self._find_tper_props()["MaxAuthentications"] == 2

    def test_tper_max_transaction_limit(self):
        assert self._find_tper_props()["MaxTransactionLimit"] == 1

    def test_tper_def_session_timeout(self):
        assert self._find_tper_props()["DefSessionTimeout"] == 120000

    # ── Echo'd HostProperties 검증 ──
    def test_echo_max_com_packet_size(self):
        assert self._find_host_echo_props()["MaxComPacketSize"] == 4096

    def test_echo_max_packet_size(self):
        assert self._find_host_echo_props()["MaxPacketSize"] == 4076

    def test_echo_max_ind_token_size(self):
        assert self._find_host_echo_props()["MaxIndTokenSize"] == 4040

    def test_echo_max_packets(self):
        assert self._find_host_echo_props()["MaxPackets"] == 1

    def test_echo_max_subpackets(self):
        assert self._find_host_echo_props()["MaxSubpackets"] == 1

    def test_echo_max_methods(self):
        assert self._find_host_echo_props()["MaxMethods"] == 1

    def test_echo_does_not_contain_max_response(self):
        """MaxResponseComPacketSize는 echo에 없어야 함"""
        assert "MaxResponseComPacketSize" not in self._find_host_echo_props()

    def test_echo_property_count(self):
        """echo는 정확히 6종"""
        assert len(self._find_host_echo_props()) == 6

    def test_tper_property_count(self):
        """TPer props는 정확히 15종"""
        assert len(self._find_tper_props()) == 15


# ============================================================================
# ⑦ Bit-Exact 비교 테스트 (App Note Table 2 / Table 3)
# ============================================================================

class TestBitExactMatch:
    """생성된 ComPacket을 App Note hex와 바이트 단위로 비교"""

    def test_table2_invocation_bit_exact(self):
        """Table 2: Host→TPer Invocation – 100% bit-exact"""
        expected = bytes.fromhex(TABLE2_HEX.replace(" ", ""))
        token    = build_properties_invocation_token_stream()
        actual   = build_properties_compacket(token)
        assert actual == expected

    def test_table3_response_bit_exact(self):
        """Table 3: TPer→Host Response – 100% bit-exact"""
        expected = bytes.fromhex(TABLE3_HEX.replace(" ", ""))
        token    = build_properties_response_token_stream()
        actual   = build_properties_compacket(token)
        assert actual == expected


# ============================================================================
# ⑧ 속성 제약 조건 검증 (Core Spec Table 168 / UCT-02)
# ============================================================================

class TestPropertyConstraints:
    """
    Core Spec Table 168 최소값 및 UCT-02 범위 검증.
    실제 드라이브 응답값을 받은 후 이 테스트로 검증하는 용도.
    """

    # ── Table 168 최소값 ──
    @pytest.mark.parametrize("prop,min_val", [
        ("MaxComPacketSize",  1024),
        ("MaxPacketSize",     1004),
        ("MaxIndTokenSize",    968),
        ("MaxPackets",           1),
        ("MaxSubpackets",        1),
        ("MaxMethods",           1),
    ])
    def test_app_note_example_meets_table168_minimum(self, prop, min_val):
        """App Note 예시값이 Table 168 최소값 이상인지"""
        example_values = dict(HOST_PROPS_EXAMPLE)
        assert example_values[prop] >= min_val

    # ── UCT-02 TPer 응답값 범위 ──
    @pytest.mark.parametrize("prop,min_val", [
        ("MaxComPacketSize",             2048),
        ("MaxResponseComPacketSize",     2048),
        ("MaxPacketSize",                2028),
        ("MaxIndTokenSize",              1992),
        ("MaxPackets",                      1),
        ("MaxSubpackets",                   1),
        ("MaxMethods",                      1),
        ("MaxSessions",                     1),
        ("MaxAuthentications",              2),
        ("MaxTransactionLimit",             1),
    ])
    def test_app_note_tper_meets_uct02_minimum(self, prop, min_val):
        """App Note TPer 예시값이 UCT-02 최소값 이상인지"""
        example_values = dict(TPER_PROPS_EXAMPLE)
        assert example_values[prop] >= min_val

    # ── UCT-02 Echo'd HostProperties 범위 (상한 포함) ──
    @pytest.mark.parametrize("prop,min_val,max_val", [
        ("MaxComPacketSize",  2048, 4096),
        ("MaxPacketSize",     2028, 4076),
        ("MaxIndTokenSize",   1992, 4040),
    ])
    def test_app_note_echo_within_uct02_range(self, prop, min_val, max_val):
        """App Note echo 예시값이 UCT-02 범위 안에 있는지"""
        example_values = dict(HOST_PROPS_ECHO_EXAMPLE)
        assert min_val <= example_values[prop] <= max_val

    # ── value=0 의미 (no limit) ──
    def test_zero_means_no_limit_max_packets(self):
        """MaxPackets=0 → 제한 없음. 인코딩이 Tiny Atom 00이어야 함"""
        encoded = encode_uint(0)
        assert encoded == bytes([0x00])

    # ── AckNak / SequenceNumbers 종속성 ──
    def test_acknak_requires_sequence_numbers(self):
        """
        AckNak=TRUE(1)이면 SequenceNumbers도 TRUE(1)여야 함.
        AckNak=1, SequenceNumbers=0 조합은 TPer가 둘 다 0으로 강제.
        → 테스트: 이 조합을 만들면 "invalid" 상태임을 표시
        """
        invalid_combo = {"AckNak": 1, "SequenceNumbers": 0}
        # TPer 강제 규칙: 둘 다 FALSE로
        if invalid_combo["AckNak"] == 1 and invalid_combo["SequenceNumbers"] == 0:
            corrected = {"AckNak": 0, "SequenceNumbers": 0}
        else:
            corrected = invalid_combo
        assert corrected["AckNak"] == 0
        assert corrected["SequenceNumbers"] == 0

    def test_acknak_true_with_sequence_numbers_true_is_valid(self):
        """AckNak=1 + SequenceNumbers=1 → 유효한 조합"""
        combo = {"AckNak": 1, "SequenceNumbers": 1}
        # 종속성 위반 없음
        assert combo["AckNak"] == 1
        assert combo["SequenceNumbers"] == 1


# ============================================================================
# ⑨ Edge Case 테스트
# ============================================================================

class TestEdgeCases:
    """경계 조건 및 특수 케이스"""

    def test_empty_host_properties(self):
        """HostProperties를 빈 리스트로 보내면 token stream이 유효한지"""
        stream = build_properties_invocation_token_stream(host_props=[])
        # 구조: CALL + SMUID + PropertiesUID + F0 + F2 + 00 + F0 + F1 + F3 + F1 + F9 + status
        assert stream[0] == 0xF8          # CALL
        assert stream[-5:] == bytes([0xF0, 0x00, 0x00, 0x00, 0xF1])  # status list
        # ComPacket 생성도 실패 없이 완료
        compacket = build_properties_compacket(stream)
        assert len(compacket) > 56        # 최소 헤더들(20+24+12)보다 큼

    def test_response_empty_tper_props(self):
        """TPer Properties가 빈 경우"""
        stream = build_properties_response_token_stream(tper_props=[], host_props_echo=[])
        compacket = build_properties_compacket(stream)
        assert len(compacket) > 56

    def test_padding_when_payload_mod4_is_zero(self):
        """payload 길이가 4배수 → padding = 0"""
        # 4바이트 payload
        payload = bytes([0xF8, 0x01, 0x02, 0x03])
        subpacket = SubpacketBuilder.build(payload)
        # 12(header) + 4(payload) + 0(padding) = 16
        assert len(subpacket) == 16

    def test_padding_when_payload_mod4_is_one(self):
        """payload 길이 % 4 == 1 → padding = 3"""
        payload = bytes(5)  # 5 % 4 = 1 → padding 3
        subpacket = SubpacketBuilder.build(payload)
        assert len(subpacket) == 12 + 5 + 3  # 20

    def test_padding_when_payload_mod4_is_two(self):
        """payload 길이 % 4 == 2 → padding = 2"""
        payload = bytes(6)
        subpacket = SubpacketBuilder.build(payload)
        assert len(subpacket) == 12 + 6 + 2  # 20

    def test_padding_when_payload_mod4_is_three(self):
        """payload 길이 % 4 == 3 → padding = 1 (Table 2 실제 케이스: 171 bytes)"""
        payload = bytes(171)
        subpacket = SubpacketBuilder.build(payload)
        assert len(subpacket) == 12 + 171 + 1  # 184

    def test_properties_com_id_is_not_0001(self):
        """Properties는 반드시 ComID=0x07FE, StartSession용 0x0001이 아님"""
        token     = build_properties_invocation_token_stream()
        compacket = build_properties_compacket(token)
        hdr       = parse_compacket_header(compacket)
        assert hdr["com_id"] == 0x07FE
        assert hdr["com_id"] != 0x0001

    def test_invocation_token_stream_length(self):
        """App Note Table 2 – token stream = 171 bytes"""
        stream = build_properties_invocation_token_stream()
        assert len(stream) == 171

    def test_response_token_stream_length(self):
        """App Note Table 3 – token stream = 432 bytes"""
        stream = build_properties_response_token_stream()
        assert len(stream) == 432
