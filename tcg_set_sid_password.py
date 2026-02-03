"""
TCG Opal Set SID Password
=========================

C_PIN_SID 테이블의 PIN 컬럼에 새 비밀번호 설정
Application Note Table 12 참고
"""

from tcg_opal_codec import TCGPayloadBuilder
import struct


def build_set_sid_password_payload(
    new_password: bytes
) -> bytes:
    """
    Set SID Password payload 생성
    
    Application Note Table 12 참고:
    C_PIN_SID_UID.Set[Values = [PIN = new_password]]
    
    Args:
        new_password: 새 SID 비밀번호
        
    Returns:
        bytes: Set payload
    """
    builder = TCGPayloadBuilder()
    
    # Call
    builder.add_call()
    
    # Invoking UID: C_PIN_SID (0x00 00 00 0B 00 00 00 01)
    c_pin_sid_uid = bytes([0x00, 0x00, 0x00, 0x0B, 0x00, 0x00, 0x00, 0x01])
    builder.add_bytes(c_pin_sid_uid)
    
    # Method UID: Set (0x00 00 00 06 00 00 00 17)
    set_method_uid = bytes([0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x17])
    builder.add_bytes(set_method_uid)
    
    # Parameters
    builder.start_list()
    
    # Values (named parameter)
    builder.start_name()
    builder.add_integer(1)  # Name: "Values"
    
    # Values list
    builder.start_list()
    
    # PIN = new_password (named value)
    builder.start_name()
    builder.add_integer(3)  # Name: "PIN" (column 3)
    builder.add_bytes(new_password)  # Value: new password
    builder.end_name()
    
    builder.end_list()  # End values list
    builder.end_name()  # End Values parameter
    
    builder.end_list()  # End parameters
    
    # End of Data
    builder.add_end_of_data()
    
    # Method Status List
    builder.start_list()
    builder.add_integer(0)
    builder.add_integer(0)
    builder.add_integer(0)
    builder.end_list()
    
    return builder.get_payload()


def build_set_sid_password_packet(
    com_id: int,
    tsn: int,
    hsn: int,
    new_password: bytes
) -> bytes:
    """
    Set SID Password 완전한 패킷 생성
    
    Args:
        com_id: ComID
        tsn: TPer Session Number
        hsn: Host Session Number
        new_password: 새 비밀번호
        
    Returns:
        bytes: 완전한 패킷
    """
    # Payload 생성
    payload = build_set_sid_password_payload(new_password)
    
    # SubPacket 생성
    subpacket_header = struct.pack('>6sHI',
        b'\x00' * 6,  # Reserved
        0x0000,       # Kind: Data
        len(payload)  # Length
    )
    subpacket = subpacket_header + payload
    
    # Packet 생성 (TSN:HSN 사용!)
    session = (tsn << 32) | hsn
    packet_header = struct.pack('>QIHHII',
        session,         # TSN:HSN
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


def set_sid_password(
    nvme,
    com_id: int,
    tsn: int,
    hsn: int,
    new_password: bytes
) -> bytes:
    """
    SID 비밀번호 설정
    
    Args:
        nvme: NVMe 컨트롤러
        com_id: ComID
        tsn: TPer Session Number
        hsn: Host Session Number
        new_password: 새 SID 비밀번호
        
    Returns:
        bytes: Set 메서드 응답
        
    Example:
        >>> # StartSession with SID 성공 후
        >>> new_pwd = b"MyNewPassword123"
        >>> response = set_sid_password(nvme, 0x0001, tsn, hsn, new_pwd)
        >>> if verify_set_response(response):
        >>>     print("비밀번호 변경 성공!")
    """
    # 패킷 생성
    packet = build_set_sid_password_packet(com_id, tsn, hsn, new_password)
    
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


def verify_set_response(response: bytes) -> bool:
    """
    Set 메서드 응답 검증
    
    Args:
        response: TPer 응답
        
    Returns:
        bool: 성공하면 True
    """
    from tcg_packet_parser import TCGPacketParser
    
    try:
        parsed = TCGPacketParser.parse_complete_packet(response)
        
        # Status code 확인
        if 'payload' in parsed.get('layers', {}):
            payload = parsed['layers']['payload']
            
            # Method Status List에서 status code 확인
            parsed_data = payload.get('parsed', [])
            
            # 일반적으로 [[status, 0, 0]] 형태
            if len(parsed_data) >= 1 and isinstance(parsed_data[0], list):
                status_list = parsed_data[0]
                if len(status_list) > 0:
                    status_code = status_list[0]
                    if isinstance(status_code, int):
                        return status_code == 0  # SUCCESS
                    elif isinstance(status_code, bytes):
                        return int.from_bytes(status_code, 'big') == 0
        
        return False
        
    except Exception as e:
        print(f"응답 검증 실패: {e}")
        return False


# =====================================================
# 사용 예제
# =====================================================

if __name__ == "__main__":
    """
    Set SID Password 사용 예제
    """
    
    # 예제: Payload 생성
    print("=" * 70)
    print("Set SID Password Payload:")
    print("=" * 70)
    
    new_password = b"<new_SID_password>"  # 18 bytes 예제
    payload = build_set_sid_password_payload(new_password)
    print(f"Length: {len(payload)} bytes")
    print(f"Hex (first 120 bytes): {payload[:120].hex().upper()}")
    print()
    
    # Application Note 기준
    print("=" * 70)
    print("Application Note Table 12 - Set C_PIN_SID:")
    print("=" * 70)
    print("""
    C_PIN_SID_UID.Set[Values = [PIN = new_password]]
    
    Data Payload:
    F8              Call
    A8 00...01      C_PIN_SID UID
    A8 00...17      Set method UID
    F0              Start List (params)
      F2            Start Name
        01          "Values"
        F0          Start List (values)
          F2        Start Name
            03      "PIN"
            D0 12   18 bytes (예제)
            <new>   new password
          F3        End Name
        F1          End List
      F3            End Name
    F1              End List
    F9              End of Data
    F0 00 00 00 F1  Status
    """)
    
    # 전체 TakeOwnership 흐름
    print("=" * 70)
    print("Complete TakeOwnership Flow:")
    print("=" * 70)
    print("""
    ✅ 1. StartSession (Anybody)
    ✅ 2. Get MSID PIN
    ✅ 3. CloseSession
    ✅ 4. StartSession (SID + MSID PIN)
    ✅ 5. Set SID Password ← 지금 완료!
    ⬜ 6. CloseSession
    
    코드:
    
    # 1-3: MSID PIN 가져오기
    start_response = start_session_anybody(nvme, hsn=1)
    tsn1 = extract_tsn(start_response)
    
    msid_pin = extract_msid_pin(
        get_msid_pin(nvme, 0x0001, tsn1, 1)
    )
    
    close_session(nvme, 0x0001, tsn1, 1)
    
    # 4-6: SID 비밀번호 변경
    start_auth_response = start_session_with_sid(
        nvme, 0x0001, 2, msid_pin
    )
    tsn2 = extract_tsn(start_auth_response)
    
    new_password = b"MySecurePassword123!"
    set_response = set_sid_password(
        nvme, 0x0001, tsn2, 2, new_password
    )
    
    if verify_set_response(set_response):
        print("✅ SID 비밀번호 변경 성공!")
    
    close_session(nvme, 0x0001, tsn2, 2)
    
    # 🎉 TakeOwnership 완료!
    # 이제 new_password로 SID 인증 가능!
    """)
    
    # 다음 단계
    print("=" * 70)
    print("Next Steps - Activate Locking SP:")
    print("=" * 70)
    print("""
    TakeOwnership 완료 후:
    
    7. StartSession (SID + new_password)
    8. Activate Locking SP
    9. CloseSession
    
    이후 Locking SP를 사용할 수 있게 됩니다!
    """)
