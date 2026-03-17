# =============================================================================
# UCT-10: Enable MBR Shadowing
# Opal 2.00/2.01 기준 payload 중심 구현
# =============================================================================

# MandatoryWriteGranularity는 Table table의 column입니다. 즉 드라이브(TPer)가 직접 정의하는 값입니다.

# 정의
# MandatoryWriteGranularity는 Table table에 있는 column으로, byte table(MBR, DataStore 등)에 Set method로 데이터를 쓸 때 **반드시 지켜야 하는 최소 쓰기 단위(바이트 수)**입니다.
# 즉 한 번의 Set 호출에서 쓰는 데이터의 크기가 반드시 이 값의 배수여야 합니다.

# 어디서 읽어오나?
# Table table의 MBR Descriptor row에서 Get으로 읽어옵니다.
# InvokingID : 00 00 00 01 00 00 08 04  (MBR Table Descriptor)
# Column     : MandatoryWriteGranularity

# 왜 필요한가?
# 드라이브 펌웨어 내부적으로 MBR 데이터를 NAND 플래시에 기록할 때 특정 단위(예: 4KB, 512KB)로만 처리할 수 있기 때문입니다. 이 단위보다 작거나 정렬이 안 맞는 크기로 Set을 호출하면 TPer가 INVALID_PARAMETER 등의 오류를 반환합니다.

# 예시
# MandatoryWriteGranularity 값의미1제한 없음 (1바이트 단위도 가능) → Opal 1.00이 이에 해당, 청크 분할 불필요512반드시 512바이트 배수로 쓸 것524288 (512KB)반드시 512KB 배수로 쓸 것
# 그래서 test case 문서에서도:

# Opal 1.00: MandatoryWriteGranularity 규정 없음 → MBR 전체를 한 번에 써도 됨
# Opal 2.00 이상: MandatoryWriteGranularity 준수 필요 → 청크 분할 필수


MandatoryWriteGranularity는 Core Spec Table table의 표준 column이 아니라 Opal 2.00 이후 SSC에서 Table table에 추가된 확장 column입니다.

Core Spec Table table: column 0x00~0x0C 까지만 정의
MandatoryWriteGranularity = column 0x0D (Opal SSC 확장)

InvokingID : 00 00 00 01 00 00 08 04   ← MBR Table Descriptor Object
MethodID   : 00 00 00 06 00 00 00 16   ← Get
Column     : 0x0D                      ← MandatoryWriteGranularity



F8                              # Call token
A8 00 00 00 01 00 00 08 04      # InvokingID: MBR Table Descriptor
A8 00 00 00 06 00 00 00 16      # MethodID: Get
F0                              # Start param list
  F2 00 0D F3                   # startColumn = 0x0D
  F2 01 0D F3                   # endColumn   = 0x0D
F1                              # End param list
F9                              # End of Data
F0 00 00 00 F1                  # Status list


















# 실제 사용 흐름
# 1. Get MBR Table Descriptor → MandatoryWriteGranularity 값 읽기
# 2. MBR 전체를 그 값의 배수 단위로 나눠서 Set 반복 호출
# python# MandatoryWriteGranularity = 524288 (512KB) 인 경우
# # MBR 크기 = 128MB → 256번 Set 호출 필요
# chunk_size = mandatory_write_granularity          # 반드시 이 크기의 배수
# assert write_size % mandatory_write_granularity == 0



















# UID 상수 정의
UID = {
    # SP
    'LOCKING_SP'               : bytes.fromhex('0000020500000002'),
    # Session Manager
    'SM_UID'                   : bytes.fromhex('0000000000000FF'),  # SMUID
    'START_SESSION'            : bytes.fromhex('000000000000FF02'),
    # Method
    'GET'                      : bytes.fromhex('0000000600000016'),
    'SET'                      : bytes.fromhex('0000000600000017'),
    # ACE
    'ACE_MBRCONTROL_SET_DONE'  : bytes.fromhex('000000080003F801'),
    # Authority
    'USER1'                    : bytes.fromhex('0000000900030001'),
    'LAST_REQUIRED_USER'       : bytes.fromhex('0000000900030002'),  # Opal 2.00: User2
    # Table Descriptor (Table table row)
    'MBR_TABLE_DESCRIPTOR'     : bytes.fromhex('0000000100000804'),
    # MBR Table 자체 (byte table, Set/Get data)
    'MBR_TABLE'                : bytes.fromhex('0000080400000000'),
    # MBRControl object
    'MBRCONTROL_OBJ'           : bytes.fromhex('0000080300000001'),
    # Locking Range (Opal 2.00: Range8 = LAST_REQUIRED_RANGE)
    'LAST_REQUIRED_RANGE'      : bytes.fromhex('0000080200000009'),  # Locking_Range8
}

MAGIC_PATTERN = b'\xAB\xCD\xEF\x01'  # 임의의 MAGIC_PATTERN


# =============================================================================
# Step 1: StartSession (Locking SP, Admin1)
# - 스펙상 payload이므로 세션 열기 payload만 기술
# =============================================================================
def payload_start_session_admin1(hsn: int, admin1_pin: bytes) -> bytes:
    """
    StartSession → Locking SP, HostSigningAuthority = Admin1
    """
    p = bytearray()
    p += b'\xF8'                            # Call token
    p += b'\xA8' + bytes.fromhex('000000000000FF')  # SMUID (invoking)
    # 정정: SMUID = 00 00 00 00 00 00 00 FF
    p.clear()

    def uid(hex_str): return b'\xA8' + bytes.fromhex(hex_str)

    p += b'\xF8'                                        # Call
    p += b'\xA8\x00\x00\x00\x00\x00\x00\x00\xFF'       # SMUID
    p += b'\xA8\x00\x00\x00\x00\x00\x00\xFF\x02'       # StartSession MethodUID
    p += b'\xF0'                                        # Start List
    # HostSessionID (HSN)
    p += hsn.to_bytes(1, 'big') if hsn < 64 else (b'\x84' + hsn.to_bytes(4, 'big'))
    # SPID = Locking SP
    p += b'\xA8\x00\x00\x02\x05\x00\x00\x00\x02'
    # Write = 1
    p += b'\x01'
    # HostChallenge (Named param 0)
    p += b'\xF2\x00'
    pin_len = len(admin1_pin)
    if pin_len <= 15:
        p += bytes([0xA0 | pin_len]) + admin1_pin
    else:
        p += bytes([0xD0, pin_len]) + admin1_pin
    p += b'\xF3'
    # HostSigningAuthority (Named param 3) = Admin1
    p += b'\xF2\x03'
    p += b'\xA8\x00\x00\x00\x09\x00\x01\x00\x01'       # Admin1 UID
    p += b'\xF3'
    p += b'\xF1'                                        # End List
    p += b'\xF9'                                        # End of Data
    p += b'\xF0\x00\x00\x00\xF1'                       # Status list
    return bytes(p)


# =============================================================================
# Step 2: Set ACE_MBRControl_Set_Done.BooleanExpr = [User1 OR LAST_REQUIRED_USER]
# Opal 2.00: LAST_REQUIRED_USER = User2
# =============================================================================
def payload_set_ace_mbrcontrol_set_done() -> bytes:
    """
    ACE_MBRControl_Set_Done_UID.Set [
        Values = [ BooleanExpr = [ User1_UID | User2_UID ] ]
    ]
    BooleanExpr 인코딩: postfix 표현 → [User1, User2, OR]
    """
    p = bytearray()
    p += b'\xF8'                                        # Call
    p += b'\xA8\x00\x00\x00\x08\x00\x03\xF8\x01'       # ACE_MBRControl_Set_Done UID
    p += b'\xA8\x00\x00\x00\x06\x00\x00\x00\x17'       # Set MethodUID
    p += b'\xF0'                                        # Start param list

    p += b'\xF2\x01'                                    # Name = "Values"(1)
    p += b'\xF0'                                        # Start Values list

    p += b'\xF2\x03'                                    # Name = "BooleanExpr"(3)
    p += b'\xF0'                                        # Start BooleanExpr list

    # User1 Authority ref
    p += b'\xF2'
    p += b'\xA4\x00\x00\x0C\x05'                       # Half-UID: Authority_object_ref
    p += b'\xA8\x00\x00\x00\x09\x00\x03\x00\x01'       # User1 UID
    p += b'\xF3'

    # LAST_REQUIRED_USER (User2) Authority ref
    p += b'\xF2'
    p += b'\xA4\x00\x00\x0C\x05'                       # Half-UID: Authority_object_ref
    p += b'\xA8\x00\x00\x00\x09\x00\x03\x00\x02'       # User2 UID
    p += b'\xF3'

    # OR operator
    p += b'\xF2'
    p += b'\xA4\x00\x00\x04\x0E'                       # Half-UID: boolean_ACE
    p += b'\x01'                                        # OR = 1
    p += b'\xF3'

    p += b'\xF1'                                        # End BooleanExpr list
    p += b'\xF3'                                        # End Name(BooleanExpr)

    p += b'\xF1'                                        # End Values list
    p += b'\xF3'                                        # End Name(Values)

    p += b'\xF1'                                        # End param list
    p += b'\xF9'                                        # End of Data
    p += b'\xF0\x00\x00\x00\xF1'                       # Status list
    return bytes(p)


# =============================================================================
# Step 3: Get MBR Table Descriptor.Rows
# InvokingID = MBR Table Descriptor Object (Table table의 MBR row)
# Column 0x07 = Rows
# =============================================================================
def payload_get_mbr_table_rows() -> bytes:
    """
    MBR_TABLE_DESCRIPTOR_UID.Get [ startColumn=7, endColumn=7 ]
    """
    p = bytearray()
    p += b'\xF8'                                        # Call
    p += b'\xA8\x00\x00\x00\x01\x00\x00\x08\x04'       # MBR Table Descriptor UID
    p += b'\xA8\x00\x00\x00\x06\x00\x00\x00\x16'       # Get MethodUID
    p += b'\xF0'                                        # Start param list

    p += b'\xF2\x00'                                    # Name = startColumn(0)
    p += b'\x07'                                        # Column 7 = Rows
    p += b'\xF3'

    p += b'\xF2\x01'                                    # Name = endColumn(1)
    p += b'\x07'                                        # Column 7 = Rows
    p += b'\xF3'

    p += b'\xF1'                                        # End param list
    p += b'\xF9'
    p += b'\xF0\x00\x00\x00\xF1'
    return bytes(p)


# =============================================================================
# Step 4 (Opal 2.00): Set LAST_REQUIRED_RANGE.RangeLength
#   = SIZE_OF_MBR_TABLE_DESCRIPTOR_IN_LOGICAL_BLOCKS + 10
# LAST_REQUIRED_RANGE (Opal 2.00) = Locking_Range8, UID: 00 00 08 02 00 00 00 09
# RangeLength column = 0x04
# =============================================================================
def payload_set_range_length(mbr_logical_blocks: int, lba_size: int = 512) -> bytes:
    """
    Locking_Range8.Set [ Values = [ RangeLength = mbr_logical_blocks + 10 ] ]
    """
    range_length = mbr_logical_blocks + 10

    p = bytearray()
    p += b'\xF8'
    p += b'\xA8\x00\x00\x08\x02\x00\x00\x00\x09'       # Locking_Range8 UID
    p += b'\xA8\x00\x00\x00\x06\x00\x00\x00\x17'       # Set MethodUID
    p += b'\xF0'

    p += b'\xF2\x01'                                    # Name = Values
    p += b'\xF0'
    p += b'\xF2\x04'                                    # Name = RangeLength(column 4)
    # uinteger_8 인코딩
    val = range_length.to_bytes(8, 'big')
    p += b'\x88' + val                                  # 8-byte uinteger atom
    p += b'\xF3'
    p += b'\xF1'
    p += b'\xF3'

    p += b'\xF1'
    p += b'\xF9'
    p += b'\xF0\x00\x00\x00\xF1'
    return bytes(p)


# =============================================================================
# Step 6: Set MBR Table 전체를 MAGIC_PATTERN으로 Write
# MandatoryWriteGranularity 단위로 청크 분할 필요
# Where = byte offset, Values = data
# =============================================================================
def payload_set_mbr_data(offset: int, data: bytes) -> bytes:
    """
    MBR_TABLE_UID.Set [ Where=offset, Values=data ]
    MBR는 byte table이므로 Where = byte offset
    """
    p = bytearray()
    p += b'\xF8'
    p += b'\xA8\x00\x00\x08\x04\x00\x00\x00\x00'       # MBR Table UID (byte table)
    p += b'\xA8\x00\x00\x00\x06\x00\x00\x00\x17'       # Set MethodUID
    p += b'\xF0'

    # Where (Named param 0) = byte offset
    p += b'\xF2\x00'
    off_bytes = offset.to_bytes(4, 'big').lstrip(b'\x00') or b'\x00'
    p += bytes([0x80 | len(off_bytes)]) + off_bytes      # Short atom uinteger
    p += b'\xF3'

    # Values (Named param 1) = data bytes
    p += b'\xF2\x01'
    data_len = len(data)
    if data_len <= 15:
        p += bytes([0xA0 | data_len]) + data
    elif data_len <= 2047:
        p += bytes([0xD0 | (data_len >> 8), data_len & 0xFF]) + data
    else:
        p += b'\xE2' + data_len.to_bytes(3, 'big') + data
    p += b'\xF3'

    p += b'\xF1'
    p += b'\xF9'
    p += b'\xF0\x00\x00\x00\xF1'
    return bytes(p)


def build_mbr_write_payloads(mbr_size_bytes: int,
                              mandatory_write_granularity: int,
                              pattern: bytes) -> list[bytes]:
    """
    MBR 전체를 MAGIC_PATTERN으로 채우는 Set payload 목록 생성
    MandatoryWriteGranularity 단위로 청크 분할
    """
    payloads = []
    offset = 0
    chunk = mandatory_write_granularity

    # pattern을 chunk 크기에 맞게 타일링
    tile = (pattern * ((chunk // len(pattern)) + 1))[:chunk]

    while offset < mbr_size_bytes:
        remaining = mbr_size_bytes - offset
        write_size = min(chunk, remaining)
        data = tile[:write_size]
        payloads.append(payload_set_mbr_data(offset, data))
        offset += write_size

    return payloads


# =============================================================================
# Step 7: Set MBRControl.Enable = TRUE
# MBRControl object UID: 00 00 08 03 00 00 00 01
# Enable column = 0x01
# =============================================================================
def payload_set_mbrcontrol_enable_true() -> bytes:
    """
    MBRControl_UID.Set [ Values = [ Enable = TRUE ] ]
    """
    p = bytearray()
    p += b'\xF8'
    p += b'\xA8\x00\x00\x08\x03\x00\x00\x00\x01'       # MBRControl UID
    p += b'\xA8\x00\x00\x00\x06\x00\x00\x00\x17'       # Set MethodUID
    p += b'\xF0'

    p += b'\xF2\x01'                                    # Name = Values
    p += b'\xF0'
    p += b'\xF2\x01'                                    # Name = Enable(column 1)
    p += b'\x01'                                        # TRUE = 1
    p += b'\xF3'
    p += b'\xF1'
    p += b'\xF3'

    p += b'\xF1'
    p += b'\xF9'
    p += b'\xF0\x00\x00\x00\xF1'
    return bytes(p)


# =============================================================================
# Step 8: CloseSession payload
# =============================================================================
def payload_close_session(hsn: int, tsn: int) -> bytes:
    """
    SMUID.CloseSession [ HSN, TSN ]
    """
    p = bytearray()
    p += b'\xF8'
    p += b'\xA8\x00\x00\x00\x00\x00\x00\x00\xFF'       # SMUID
    p += b'\xA8\x00\x00\x00\x00\x00\x00\xFF\x06'       # CloseSession MethodUID
    p += b'\xF0'
    p += bytes([hsn]) if hsn < 64 else (b'\x84' + hsn.to_bytes(4, 'big'))
    p += bytes([tsn]) if tsn < 64 else (b'\x84' + tsn.to_bytes(4, 'big'))
    p += b'\xF1'
    p += b'\xF9'
    p += b'\xF0\x00\x00\x00\xF1'
    return bytes(p)


# =============================================================================
# UCT-10 전체 흐름 요약 (payload 호출 순서)
# =============================================================================
def uct10_payload_sequence(admin1_pin: bytes,
                            mbr_size_bytes: int,
                            lba_size: int,
                            mandatory_write_granularity: int):
    """
    UCT-10: Enable MBR Shadowing 전체 payload 시퀀스

    Steps:
      1.  StartSession(Locking SP, Admin1)
      2.  Set ACE_MBRControl_Set_Done.BooleanExpr = [User1 OR User2]
      3.  Get MBR_Table_Descriptor.Rows  → mbr_size_bytes 확인
      4.  Set Locking_Range8.RangeLength = MBR_logical_blocks + 10  (Opal 2.00)
      5.  [NVMe Write] Write 1s over LAST_REQUIRED_RANGE            (host side)
      6.  Set MBR Table = MAGIC_PATTERN (MandatoryWriteGranularity 단위)
      7.  Set MBRControl.Enable = TRUE
      8.  CloseSession
      9.  [Power cycle]                                             (host side)
      10. [NVMe Write] Write MAGIC_PATTERN → expect DPE            (host side)
      11. [NVMe Read]  LBA 0 ~ MBR size   → expect MAGIC_PATTERN   (host side)
      12. [NVMe Read]  LBA MBR+1 ~ +10    → expect 0s              (host side)
    """
    seq = {}

    # Step 1
    seq['step1_start_session'] = payload_start_session_admin1(hsn=1, admin1_pin=admin1_pin)

    # Step 2
    seq['step2_set_ace_mbrcontrol'] = payload_set_ace_mbrcontrol_set_done()

    # Step 3
    seq['step3_get_mbr_rows'] = payload_get_mbr_table_rows()

    # Step 4 (Opal 2.00)
    mbr_logical_blocks = mbr_size_bytes // lba_size
    seq['step4_set_range_length'] = payload_set_range_length(mbr_logical_blocks, lba_size)

    # Step 6: MBR 전체 MAGIC_PATTERN write (청크 분할)
    seq['step6_write_mbr_magic'] = build_mbr_write_payloads(
        mbr_size_bytes, mandatory_write_granularity, MAGIC_PATTERN
    )

    # Step 7
    seq['step7_enable_mbrcontrol'] = payload_set_mbrcontrol_enable_true()

    # Step 8
    seq['step8_close_session'] = payload_close_session(hsn=1, tsn=1)

    return seq


# =============================================================================
# 사용 예시
# =============================================================================
if __name__ == '__main__':
    seq = uct10_payload_sequence(
        admin1_pin                = b'Admin1_password',
        mbr_size_bytes            = 128 * 1024 * 1024,  # 128MB (예시)
        lba_size                  = 512,
        mandatory_write_granularity = 512 * 1024,       # 512KB (예시)
    )

    for step_name, payload in seq.items():
        if isinstance(payload, list):
            print(f"\n[{step_name}] {len(payload)} chunks")
            print(f"  chunk[0]: {payload[0].hex()}")
        else:
            print(f"\n[{step_name}]")
            print(f"  {payload.hex()}")