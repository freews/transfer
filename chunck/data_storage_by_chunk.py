"""
DataStore Chunked Write/Read
=============================

Application Note p.88 의 DataStore.Set[ Where=offset, Values=data ] 구조를
MaxComPacketSize / MaxIndTokenSize 제한에 맞춰 청크 단위로 분할 전송.

참조:
  - TCG Storage Application Note p.87-91  (3.2.13.6 Write / 3.2.13.9 Read)
  - TCG Core Spec Section 5.2.2.4.1       (MaxComPacketSize, MaxIndTokenSize)
  - TCG Core Spec Section 5.2.2.4.1.5     (MaxIndTokenSize: token header + data)
"""

import struct
from typing import Optional
from codec import (          # 기존 codec.py 의 클래스들
    TCGPayloadBuilder,
    TCGPayloadParser,
    TCGResponseParser,
    TCGComPacketBuilder,
    UID,
)


# ──────────────────────────────────────────────────────────────
# 오버헤드 상수  (bytes)
# ──────────────────────────────────────────────────────────────

_COMPACKET_HEADER  = 20   # Reserved(4) + ComID(2) + ExtComID(2) + Outstanding(4)
                           # + MinTransfer(4) + Length(4)
_PACKET_HEADER     = 28   # Session(8) + SeqNum(4) + Reserved(2) + AckType(2)
                           # + Ack(4) + Length(4)  →  합계 24, 단 4-byte align 패딩 포함 28
_SUBPACKET_HEADER  = 12   # Reserved(6) + Kind(2) + Length(4)

# Set 메서드 고정 토큰 오버헤드 (Where 값이 tiny atom 범위 0-63 일 때)
#   CALL(1) + InvokingUID short atom(10) + MethodUID short atom(10)
#   + F0(1) + F2(1) + 00"Where"(1) + tiny_where(1) + F3(1)
#   + F2(1) + 01"Values"(1) + [atom header 별도] + F3(1) + F1(1) + F9(1)
#   + status list: F0(1) + 00(1) + 00(1) + 00(1) + F1(1) = 5
_SET_METHOD_FIXED  = 1+10+10 + 1+1+1+1+1 + 1+1+1+1+1 + 5   # = 36
_LONG_ATOM_HEADER  = 4    # Long Atom 헤더 (최대 경우)

# Where 오프셋이 커지면 atom 크기가 늘어나지만,
# DataStore 는 일반적으로 128 KB~10 MB 이므로 short atom(1+1=2 bytes) 또는
# medium atom(2 bytes) 으로 충분.  보수적으로 5 bytes(medium+1) 예약.
_WHERE_ATOM_MAX    = 5

_FRAME_OVERHEAD = (
    _COMPACKET_HEADER
    + _PACKET_HEADER
    + _SUBPACKET_HEADER
    + _SET_METHOD_FIXED
    + _WHERE_ATOM_MAX
    + _LONG_ATOM_HEADER
)  # ≈ 87 bytes


# ──────────────────────────────────────────────────────────────
# 청크 크기 계산
# ──────────────────────────────────────────────────────────────

def calculate_chunk_size(tper_properties: dict) -> int:
    """
    TPer Properties 에서 안전한 청크 크기(데이터만)를 계산.

    제약:
      1) MaxComPacketSize  : 전체 ComPacket ≤ 이 값
      2) MaxIndTokenSize   : Values 토큰(헤더+데이터) ≤ 이 값  (Core Spec 5.2.2.4.1.5)

    반환: 청크 1개당 실제 데이터 bytes (atom 헤더 제외)
    """
    max_com  = tper_properties.get('MaxComPacketSize', 2048)
    max_tok  = tper_properties.get('MaxIndTokenSize',  1024)

    # 0 → no limit (매우 큰 값으로 처리)
    if max_com == 0:
        max_com = 0x7FFFFFFF
    if max_tok == 0:
        max_tok = 0x7FFFFFFF

    # ComPacket 크기 제약에서 역산
    from_com_size = max_com - _FRAME_OVERHEAD

    # MaxIndTokenSize 는 "token header + data" 이므로 헤더 제외
    from_tok_size = max_tok - _LONG_ATOM_HEADER

    chunk = min(from_com_size, from_tok_size)

    if chunk <= 0:
        raise ValueError(
            f"TPer 속성으로 유효한 청크 크기를 계산할 수 없음: "
            f"MaxComPacketSize={max_com}, MaxIndTokenSize={max_tok}"
        )

    return chunk


# ──────────────────────────────────────────────────────────────
# Set 메서드 payload 빌드 (단일 청크)
# ──────────────────────────────────────────────────────────────

def _build_set_payload(
    tsn: int,
    hsn: int,
    offset: int,
    chunk: bytes,
) -> bytes:
    """
    DataStore_UID.Set[ Where=offset, Values=chunk ] payload 생성.

    Application Note p.88 Table 54 구조:
      CALL
      InvokingUID (DataStore_UID)
      MethodUID   (SET_UID)
      F0  (param list start)
        F2 00 <offset> F3         ← Where = offset
        F2 01 <chunk bytes> F3    ← Values = chunk data
      F1  (param list end)
      F9  (End of Data)
      F0 00 00 00 F1              ← status list
    """
    builder = TCGPayloadBuilder()
    (builder
        .add_call()
        .add_uid(UID.DATASTORE)
        .add_uid(UID.SET)
        .start_list()
            .start_name()
                .add_tiny_atom(0)          # Name: "Where" = 0
                .add_integer(offset)       # Value: byte offset
            .end_name()
            .start_name()
                .add_tiny_atom(1)          # Name: "Values" = 1
                .add_bytes(chunk)          # Value: 실제 데이터
            .end_name()
        .end_list()
        .add_end_of_data()
        .start_list()
            .add_tiny_atom(0)              # status = SUCCESS
            .add_tiny_atom(0)
            .add_tiny_atom(0)
        .end_list()
    )
    return builder.get_payload()


# ──────────────────────────────────────────────────────────────
# DataStore 청크 분할 쓰기
# ──────────────────────────────────────────────────────────────

def datastore_write_chunked(
    send_recv,                # callable(compacket_bytes) → response_bytes
    com_id: int,
    tsn: int,
    hsn: int,
    data: bytes,
    tper_properties: dict,
    start_offset: int = 0,
) -> bool:
    """
    DataStore 테이블에 임의 길이의 데이터를 청크 분할하여 씀.

    Args:
        send_recv        : IF-SEND 후 IF-RECV 결과를 반환하는 콜백
                           예) lambda pkt: device.security_send_recv(pkt)
        com_id           : 세션에 사용 중인 ComID
        tsn              : TPer Session Number
        hsn              : Host Session Number
        data             : 저장할 전체 데이터
        tper_properties  : Properties 메서드 응답에서 얻은 딕셔너리
                           {'MaxComPacketSize': 4096, 'MaxIndTokenSize': 4040, ...}
        start_offset     : DataStore 내 시작 오프셋 (기본 0)

    Returns:
        True  → 전체 쓰기 성공
        False → 일부 또는 전체 실패
    """
    chunk_size = calculate_chunk_size(tper_properties)
    total      = len(data)
    offset     = start_offset
    sent       = 0

    print(f"[DataStore Write] total={total} bytes, chunk_size={chunk_size}, "
          f"chunks={_ceil_div(total, chunk_size)}")

    while sent < total:
        chunk = data[sent : sent + chunk_size]

        # payload → ComPacket 조립
        payload    = _build_set_payload(tsn, hsn, offset, chunk)
        compacket  = _build_compacket(com_id, tsn, hsn, payload)

        print(f"  → Set[ Where={offset}, len={len(chunk)} ] "
              f"({sent+1}~{sent+len(chunk)}/{total})")

        response = send_recv(compacket)
        status   = _parse_status(response)

        if status != 0x00:
            print(f"  ✗ 실패: status=0x{status:02X} at offset={offset}")
            return False

        print(f"  ✓ 성공")
        sent   += len(chunk)
        offset += len(chunk)

    print(f"[DataStore Write] 완료: {total} bytes 전송")
    return True


# ──────────────────────────────────────────────────────────────
# Get 메서드 payload 빌드 (단일 청크 범위)
# ──────────────────────────────────────────────────────────────

def _build_get_payload(
    tsn: int,
    hsn: int,
    start_row: int,
    end_row: int,
) -> bytes:
    """
    DataStore_UID.Get[ Cellblock: [startRow=start_row, endRow=end_row] ] payload.

    Application Note p.90 Table 56 구조:
      CALL
      InvokingUID (DataStore_UID)
      MethodUID   (GET_UID)
      F0                         ← param list start
        F0                       ← cell block start
          F2 01 <start_row> F3   ← startRow
          F2 02 <end_row>   F3   ← endRow
        F1                       ← cell block end
      F1                         ← param list end
      F9                         ← End of Data
      F0 00 00 00 F1             ← status list
    """
    builder = TCGPayloadBuilder()
    (builder
        .add_call()
        .add_uid(UID.DATASTORE)
        .add_uid(UID.GET)
        .start_list()
            .start_list()                  # cell block
                .start_name()
                    .add_tiny_atom(1)      # Name: "startRow"
                    .add_integer(start_row)
                .end_name()
                .start_name()
                    .add_tiny_atom(2)      # Name: "endRow"
                    .add_integer(end_row)
                .end_name()
            .end_list()
        .end_list()
        .add_end_of_data()
        .start_list()
            .add_tiny_atom(0)
            .add_tiny_atom(0)
            .add_tiny_atom(0)
        .end_list()
    )
    return builder.get_payload()


# ──────────────────────────────────────────────────────────────
# DataStore 청크 분할 읽기
# ──────────────────────────────────────────────────────────────

def datastore_read_chunked(
    send_recv,
    com_id: int,
    tsn: int,
    hsn: int,
    length: int,
    tper_properties: dict,
    start_offset: int = 0,
) -> Optional[bytes]:
    """
    DataStore 테이블에서 임의 길이의 데이터를 청크 분할하여 읽음.

    DataStore 의 Get 은 startRow/endRow 가 byte offset 이므로
    (Application Note p.90: startRow=0, endRow=37 → 38 bytes)
    end_row = start_row + chunk_size - 1 로 계산.

    Returns:
        읽은 데이터 bytes, 실패 시 None
    """
    # 응답 크기 기준으로 청크 계산 (MaxResponseComPacketSize 우선)
    max_resp = tper_properties.get('MaxResponseComPacketSize',
               tper_properties.get('MaxComPacketSize', 2048))
    if max_resp == 0:
        max_resp = 0x7FFFFFFF

    # 응답 오버헤드: ComPacket(20) + Packet(28) + SubPacket(12)
    # + result list: F0(1) + atom_header(4) + F1(1) + F9(1) + status(6) = 13
    _RESP_OVERHEAD = 20 + 28 + 12 + 13
    read_chunk_size = max_resp - _RESP_OVERHEAD - _LONG_ATOM_HEADER

    if read_chunk_size <= 0:
        raise ValueError(f"응답 버퍼 너무 작음: MaxResponseComPacketSize={max_resp}")

    result    = bytearray()
    offset    = start_offset
    remaining = length

    print(f"[DataStore Read] total={length} bytes, chunk_size={read_chunk_size}, "
          f"chunks={_ceil_div(length, read_chunk_size)}")

    while remaining > 0:
        chunk_len = min(read_chunk_size, remaining)
        start_row = offset
        end_row   = offset + chunk_len - 1

        payload   = _build_get_payload(tsn, hsn, start_row, end_row)
        compacket = _build_compacket(com_id, tsn, hsn, payload)

        print(f"  → Get[ startRow={start_row}, endRow={end_row} ] ({chunk_len} bytes)")

        response = send_recv(compacket)
        chunk_data, status = _parse_get_response(response)

        if status != 0x00 or chunk_data is None:
            print(f"  ✗ 실패: status=0x{status:02X} at offset={offset}")
            return None

        print(f"  ✓ 수신: {len(chunk_data)} bytes")
        result   += chunk_data
        offset   += len(chunk_data)
        remaining -= len(chunk_data)

    print(f"[DataStore Read] 완료: {len(result)} bytes 수신")
    return bytes(result)


# ──────────────────────────────────────────────────────────────
# 내부 헬퍼
# ──────────────────────────────────────────────────────────────

def _build_compacket(com_id: int, tsn: int, hsn: int, payload: bytes) -> bytes:
    """payload → Subpacket → Packet → ComPacket 조립"""
    from correct_packet_builder import SubpacketBuilder, PacketBuilder, ComPacketBuilder

    subpacket = SubpacketBuilder.build(payload)
    packet    = PacketBuilder.build(tsn, hsn, subpacket)
    return ComPacketBuilder.build(com_id, packet)


def _parse_status(response: bytes) -> int:
    """Set 응답에서 status code 추출"""
    try:
        # ComPacket → Packet → SubPacket payload 추출
        payload = _extract_payload(response)
        parsed  = TCGResponseParser.parse_method_response(payload)
        return parsed.get('status', 0xFF)
    except Exception as e:
        print(f"  응답 파싱 오류: {e}")
        return 0xFF


def _parse_get_response(response: bytes):
    """Get 응답에서 (data_bytes, status) 추출"""
    try:
        payload = _extract_payload(response)
        parsed  = TCGResponseParser.parse_method_response(payload)
        status  = parsed.get('status', 0xFF)
        data    = parsed.get('data')

        # data = [[bytes_value]] 구조 (result list 안에 bytes)
        if isinstance(data, list) and len(data) > 0:
            inner = data[0]
            if isinstance(inner, bytes):
                return inner, status
            elif isinstance(inner, list) and len(inner) > 0:
                return bytes(inner[0]) if isinstance(inner[0], bytes) else None, status

        return None, status
    except Exception as e:
        print(f"  응답 파싱 오류: {e}")
        return None, 0xFF


def _extract_payload(compacket: bytes) -> bytes:
    """ComPacket → SubPacket payload 추출"""
    # ComPacket header: 20 bytes
    # Packet header:    28 bytes
    # SubPacket header: 12 bytes  → payload 시작: 20+28+12 = 60
    if len(compacket) < 60:
        raise ValueError(f"ComPacket 너무 짧음: {len(compacket)}")

    sp_length = struct.unpack('>I', compacket[56:60])[0]
    return compacket[60 : 60 + sp_length]


def _ceil_div(a: int, b: int) -> int:
    return (a + b - 1) // b


# ──────────────────────────────────────────────────────────────
# UID 추가 (codec.py 의 UID 클래스에 없는 것)
# ──────────────────────────────────────────────────────────────

# codec.py 의 UID 클래스에 DATASTORE 가 없으면 아래를 사용
UID.DATASTORE = bytes([0x00, 0x00, 0x10, 0x01, 0x00, 0x00, 0x00, 0x00])