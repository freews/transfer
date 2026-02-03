"""
TCG Opal StartSession with SID Authentication
==============================================

MSID PIN을 사용하여 SID authority로 Admin SP 세션 시작
Application Note Table 11, 13 참고
"""

from tcg_opal_codec import TCGPayloadBuilder
import struct


def build_start_session_with_auth_payload(
    hsn: int,
    msid_pin: bytes
) -> bytes:
    """
    SID authority로 인증하는 StartSession payload 생성
    
    Application Note Table 11, 13 참고:
    SMUID.StartSession[
        HostSessionID = hsn,
        SPID = AdminSP_UID,
        Write = True,
        HostChallenge = msid_pin,
        HostSigningAuthority = SID_UID
    ]
    
    Args:
        hsn: Host Session Number
        msid_pin: MSID PIN 값 (Get MSID PIN에서 받은 값)
        
    Returns:
        bytes: StartSession payload
    """
    builder = TCGPayloadBuilder()
    
    # Call
    builder.add_call()
    
    # Invoking UID: SMUID (0x00 00 00 00 00 00 00 FF)
    smuid = bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF])
    builder.add_bytes(smuid)
    
    # Method UID: StartSession (0x00 00 00 00 00 00 FF 02)
    start_session_uid = bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x02])
    builder.add_bytes(start_session_uid)
    
    # Parameters
    builder.start_list()
    
    # HostSessionID
    builder.add_integer(hsn)
    
    # SPID: AdminSP (0x00 00 02 05 00 00 00 01)
    admin_sp_uid = bytes([0x00, 0x00, 0x02, 0x05, 0x00, 0x00, 0x00, 0x01])
    builder.add_bytes(admin_sp_uid)
    
    # Write = True
    builder.add_integer(1)
    
    # HostChallenge (named parameter)
    builder.start_name()
    builder.add_integer(0)  # Name: "HostChallenge"
    builder.add_bytes(msid_pin)  # Value: MSID PIN
    builder.end_name()
    
    # HostSigningAuthority (named parameter)
    builder.start_name()
    builder.add_integer(3)  # Name: "HostSigningAuthority"
    # SID UID (0x00 00 00 09 00 00 00 06)
    sid_uid = bytes([0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x06])
    builder.add_bytes(sid_uid)
    builder.end_name()
    
    builder.end_list()
    
    # End of Data
    builder.add_end_of_data()
    
    # Method Status List
    builder.start_list()
    builder.add_integer(0)
    builder.add_integer(0)
    builder.add_integer(0)
    builder.end_list()
    
    return builder.get_payload()


def build_start_session_with_auth_packet(
    com_id: int,
    hsn: int,
    msid_pin: bytes
) -> bytes:
    """
    SID 인증 StartSession 완전한 패킷 생성
    
    Args:
        com_id: ComID (0x0001)
        hsn: Host Session Number
        msid_pin: MSID PIN
        
    Returns:
        bytes: 완전한 패킷
    """
    # Payload 생성
    payload = build_start_session_with_auth_payload(hsn, msid_pin)
    
    # SubPacket 생성
    subpacket_header = struct.pack('>6sHI',
        b'\x00' * 6,  # Reserved
        0x0000,       # Kind: Data
        len(payload)  # Length
    )
    subpacket = subpacket_header + payload
    
    # Packet 생성 (Session = 0:0 - control session)
    session = 0
    packet_header = struct.pack('>QIHHII',
        session,         # Session 0:0
        0,               # SeqNumber
        0,               # Reserved
        0,               # AckType
        0,               # Acknowledgement
        len(subpacket)   # Length
    )
    packet = packet_header + subpacket
    
    # ComPacket 생성
    compacket_header = struct.pack('>IHHIII',
        0,           # Reserved
        com_id,      # ComID
        0,           # ComID Extension
        0,           # OutstandingData
        0,           # MinTransfer
        len(packet)  # Length
    )
    
    return compacket_header + packet


def start_session_with_sid(
    nvme,
    com_id: int,
    hsn: int,
    msid_pin: bytes
) -> bytes:
    """
    SID authority로 Admin SP 세션 시작
    
    Args:
        nvme: NVMe 컨트롤러
        com_id: ComID
        hsn: Host Session Number
        msid_pin: MSID PIN (Get MSID PIN에서 받은 값)
        
    Returns:
        bytes: SyncSession 응답
        
    Example:
        >>> # 1. Get MSID PIN
        >>> msid_pin = extract_msid_pin(get_response)
        >>> 
        >>> # 2. StartSession with SID
        >>> response = start_session_with_sid(nvme, 0x0001, 2, msid_pin)
        >>> tsn = extract_tsn(response)
    """
    # 패킷 생성
    packet = build_start_session_with_auth_packet(com_id, hsn, msid_pin)
    
    # Security Send
    nvme.security_send(
        nsid=0,
        nssf=0,
        spsp0=0x01,
        spsp1=0x00,
        secp=0x01,
        data=packet
    )
    
    # Security Receive
    response = nvme.security_receive(
        nsid=0,
        nssf=0,
        spsp0=0x01,
        spsp1=0x00,
        secp=0x01,
        al=2048
    )
    
    return response


def extract_tsn(response: bytes) -> int:
    """
    SyncSession 응답에서 TSN 추출
    
    Args:
        response: SyncSession 응답
        
    Returns:
        int: TPer Session Number
        
    Example:
        >>> response = start_session_with_sid(...)
        >>> tsn = extract_tsn(response)
        >>> print(f"TSN: 0x{tsn:08X}")
    """
    from tcg_packet_parser import TCGPacketParser
    
    try:
        parsed = TCGPacketParser.parse_complete_packet(response)
        
        # Payload detokenized에서 TSN 추출
        if 'payload' in parsed.get('layers', {}):
            detokenized = parsed['layers']['payload'].get('detokenized', {})
            if 'tper_session_id' in detokenized:
                return detokenized['tper_session_id']
        
        raise ValueError("TSN not found in response")
        
    except Exception as e:
        print(f"TSN 추출 실패: {e}")
        raise


# =====================================================
# 사용 예제
# =====================================================

if __name__ == "__main__":
    """
    StartSession with SID 사용 예제
    """
    
    # 예제: Payload 생성
    print("=" * 70)
    print("StartSession with SID Payload:")
    print("=" * 70)
    
    # 예제 MSID PIN (실제로는 Get MSID PIN에서 받음)
    msid_pin = b"<MSID_password>"  # 예제 값 (15 bytes)
    hsn = 2
    
    payload = build_start_session_with_auth_payload(hsn, msid_pin)
    print(f"Length: {len(payload)} bytes")
    print(f"Hex (first 100 bytes): {payload[:100].hex().upper()}")
    print()
    
    # Application Note 기준
    print("=" * 70)
    print("Application Note Table 11 - StartSession with SID:")
    print("=" * 70)
    print("""
    SMUID.StartSession[
        HostSessionID = 1,
        SPID = AdminSP_UID,
        Write = True,
        HostChallenge = <MSID_password>,
        HostSigningAuthority = SID_UID
    ]
    
    Data Payload:
    F8              Call
    A8 00...FF      SMUID
    A8 00...FF02    StartSession
    F0              Start List (params)
      01            HSN = 1
      A8 00...01    AdminSP UID
      01            Write = True
      F2            Start Name
        00          "HostChallenge"
        D0 12       18 bytes (예제)
        <MSID>      MSID password
      F3            End Name
      F2            Start Name
        03          "HostSigningAuthority"
        A8 00...06  SID UID
      F3            End Name
    F1              End List
    F9              End of Data
    F0 00 00 00 F1  Status
    """)
    
    # 전체 워크플로우
    print("=" * 70)
    print("Complete TakeOwnership Workflow:")
    print("=" * 70)
    print("""
    # 1. StartSession (Anybody)
    start_response = start_session_anybody(nvme, hsn=1)
    tsn1 = extract_tsn(start_response)
    
    # 2. Get MSID PIN
    get_response = get_msid_pin(nvme, 0x0001, tsn1, 1)
    msid_pin = extract_msid_pin(get_response)
    
    # 3. CloseSession
    close_session(nvme, 0x0001, tsn1, 1)
    
    # 4. StartSession with SID + MSID PIN ← 지금 이거!
    start_auth_response = start_session_with_sid(nvme, 0x0001, 2, msid_pin)
    tsn2 = extract_tsn(start_auth_response)
    
    # 5. Set SID Password (다음 단계!)
    new_password = b"MyNewPassword123"
    set_sid_password(nvme, 0x0001, tsn2, 2, new_password)
    
    # 6. CloseSession
    close_session(nvme, 0x0001, tsn2, 2)
    
    # 완료! 이제 SID password가 설정됨!
    """)
