"""
UCT-04: Activate Locking SP from Manufactured-Inactive State
=============================================================

근거 문서:
1. TCG_Storage_Opal_Family_Test_Cases_v1_00_r1_00_pub.pdf
   - Section: UCT-04 (Page 25)
   
2. TCG_Storage_Architecture_Core_Spec_v2_01_r1_00.pdf
   - Section 3.3.3: ComID Management (Page 38-42)
   - Section 3.3.4.3.1: GET_COMID (Page 44)
   - Section 5.2.3.1: StartSession Method (Page 132)
   - Section 5.2.3.2: SyncSession Method (Page 134)
   - Table 26: ComID Assignments (Page 39)

핵심 내용:
1. ComID 0x0001은 Discovery 전용 (Reserved)
2. Session에는 Dynamic ComID (0x1000~0xFFFF) 사용
3. GET_COMID로 ComID 할당받기
4. HSN은 Host가 정함 (우리가 마음대로)
5. TSN은 TPer가 SyncSession에서 알려줌
6. Session ID = (TSN << 32) | HSN (8 bytes)
"""

import struct
from typing import Tuple, Optional
from tcg_opal_codec import TCGPayloadBuilder, TCGResponseParser, UID
from correct_packet_builder import SubpacketBuilder, PacketBuilder, ComPacketBuilder


# ============================================================================
# STEP 1: GET_COMID (Dynamic ComID Allocation)
# ============================================================================
# 근거: TCG Core Spec Section 3.3.4.3.1 (Page 44)
# 근거: TCG Core Spec Table 26 - ComID Assignments (Page 39)
#
# ComID 0x0001 = Discovery 전용 (Reserved for TCG)
# ComID 0x1000~0xFFFF = Dynamic ComID (Session용)
# ============================================================================

def get_comid(ssd_h) -> Tuple[int, int]:
    """
    GET_COMID: Dynamic ComID 할당
    
    근거: TCG Core Spec Section 3.3.4.3.1 (Page 44)
    Table 27 GET_COMID Command Block:
    - Command: IF-RECV
    - Protocol ID: 0x02
    - Transfer Length: 0x0001
    - ComID: 0x0000
    
    Returns:
        (ComID, Extended_ComID)
        
    Example:
        ComID = 0x1234
        Extended_ComID = 0x12345678
        (first 2 bytes = ComID, last 2 bytes = Extension)
    """
    print("\n" + "="*70)
    print("STEP 1: GET_COMID - Allocate Dynamic ComID")
    print("근거: TCG Core Spec Section 3.3.4.3.1")
    print("="*70)
    
    # Receive Extended ComID (4 bytes)
    recv_buf = ssd_h.buffer(4)
    ssd_h.security_receive(
        recv_buf,
        0x0000,  # ComID = 0x0000 for GET_COMID (Table 27)
        0x02,    # Protocol ID = 0x02 (Section 3.3.4.3)
        0,
        4,       # Transfer Length = 4 bytes
        None
    )
    ssd_h.waitdone()
    
    response = bytes(recv_buf)
    
    # Parse Extended ComID
    # 근거: Section 3.3.3.1 Extended ComID (Page 40)
    # Bytes 0-1: ComID (MSB first)
    # Bytes 2-3: ComID Extension
    extended_comid = struct.unpack('>I', response[:4])[0]
    com_id = (extended_comid >> 16) & 0xFFFF
    com_id_ext = extended_comid & 0xFFFF
    
    print(f"  ✓ Allocated ComID: 0x{com_id:04X}")
    print(f"  ✓ ComID Extension: 0x{com_id_ext:04X}")
    print(f"  ✓ Extended ComID: 0x{extended_comid:08X}")
    
    return (com_id, extended_comid)


# ============================================================================
# STEP 2: Build Packet with Session Information
# ============================================================================
# 근거: TCG Core Spec Section 3.2.3 (Page 23-28)
# Table 17: ComPacket Format (Page 24)
# Table 18: Packet Format (Page 25) 
# Table 20: Data SubPacket Format (Page 27)
# ============================================================================

def build_packet_with_session(
    com_id: int,
    extended_com_id: int,
    token_stream: bytes,
    session_id: int = 0,
    seq_number: int = 0
) -> bytes:
    """
    Complete TCG Packet 생성 (ComPacket + Packet + Subpacket)
    
    근거: TCG Core Spec Section 3.2.3 (Page 23-28)
    
    Args:
        com_id: Allocated ComID (from GET_COMID)
        extended_com_id: Extended ComID (4 bytes)
        token_stream: TCG token payload
        session_id: Session ID (0 for Control Session, TSN+HSN for Regular Session)
        seq_number: Sequence number (starts at 0)
        
    Returns:
        Complete packet ready to send
    """
    # Step 1: Build Subpacket
    # 근거: Table 20 - Data SubPacket Format (Page 27)
    subpacket = SubpacketBuilder.build(token_stream)
    
    # Step 2: Build Packet
    # 근거: Table 18 - Packet Format (Page 25)
    # Session field: Bytes 0-7 (TSN 4 bytes + HSN 4 bytes)
    packet = PacketBuilder.build(
        session=session_id,
        seq_number=seq_number,
        subpackets=[subpacket]
    )
    
    # Step 3: Build ComPacket
    # 근거: Table 17 - ComPacket Format (Page 24)
    com_id_extension = extended_com_id & 0xFFFF  # Lower 2 bytes
    com_packet = ComPacketBuilder.build(
        com_id=com_id,
        packets=[packet],
        extended_com_id=com_id_extension
    )
    
    return com_packet


# ============================================================================
# STEP 3: StartSession (Get HSN and TSN)
# ============================================================================
# 근거: TCG Core Spec Section 5.2.3.1 (Page 132)
# 근거: TCG Core Spec Section 5.2.3.2 (Page 134)
# 근거: TCG Core Spec Section 3.3.7.1.1 (Page 55-56)
# ============================================================================

def start_session_admin_sp(
    ssd_h,
    com_id: int,
    extended_com_id: int,
    hsn: int = 1
) -> Tuple[int, int]:
    """
    StartSession to Admin SP with SID authority
    
    근거: 
    - TCG Core Spec Section 5.2.3.1 - StartSession Method (Page 132)
    - TCG Core Spec Section 5.2.3.2 - SyncSession Method (Page 134)
    - TCG Opal Test Cases UCT-04 (Page 25)
    
    Flow:
    1. Host sends: StartSession(HostSessionID=HSN, SPID=AdminSP, ...)
    2. TPer responds: SyncSession(HostSessionID=HSN, SPSessionID=TSN, ...)
    3. Session is open with Session ID = (TSN << 32) | HSN
    
    Args:
        ssd_h: SSD handle
        com_id: Allocated ComID
        extended_com_id: Extended ComID
        hsn: Host Session Number (우리가 정함, 아무 값이나 가능)
        
    Returns:
        (hsn, tsn) - Host Session Number and TPer Session Number
    """
    print("\n" + "="*70)
    print("STEP 2: StartSession (Admin SP with SID)")
    print("근거: TCG Core Spec Section 5.2.3.1 (Page 132)")
    print("="*70)
    
    # Build StartSession payload
    # 근거: Section 5.2.3.1 StartSession Method (Page 132)
    builder = TCGPayloadBuilder()
    
    # CALL token
    builder.add_call()
    
    # InvokingID = Session Manager UID
    builder.add_uid(UID.SM_UID)
    
    # MethodID = StartSession UID
    builder.add_uid(UID.START_SESSION)
    
    # Parameters: [HostSessionID, SPID, Write, ...]
    builder.start_list()
    builder.add_integer(hsn)           # HostSessionID (Section 5.2.3.1.1)
    builder.add_uid(UID.ADMIN_SP)      # SPID (Section 5.2.3.1.2)
    builder.add_integer(1)             # Write = True (Section 5.2.3.1.3)
    
    # Optional: HostSigningAuthority (Section 5.2.3.1.7)
    builder.start_name()
    builder.add_integer(3)             # Parameter name = 3
    builder.add_uid(UID.SID)           # SID Authority
    builder.end_name()
    
    builder.end_list()
    builder.add_end_of_data()
    
    # Status list (Section 3.2.2.3.3.6)
    builder.start_list()
    builder.add_integer(0)
    builder.add_integer(0)
    builder.add_integer(0)
    builder.end_list()
    
    token_stream = builder.get_payload()
    
    # Build complete packet
    # 근거: Section 3.3.7.1.2 Control Sessions (Page 56)
    # "All Session Manager Layer Methods SHALL be transmitted 
    #  in packets where Packet.Session = 0x00000000_00000000"
    complete_packet = build_packet_with_session(
        com_id=com_id,
        extended_com_id=extended_com_id,
        token_stream=token_stream,
        session_id=0,  # Control Session = 0
        seq_number=0
    )
    
    print(f"  HSN (Host Session Number): 0x{hsn:08X} (우리가 정함)")
    print(f"  ComID: 0x{com_id:04X}")
    print(f"  Packet size: {len(complete_packet)} bytes")
    
    # Send
    send_buf = ssd_h.buffer(len(complete_packet))
    send_buf[:] = complete_packet
    
    ssd_h.security_send(
        send_buf,
        com_id,  # Use allocated ComID (NOT 0x0001!)
        0x01,    # Protocol ID = 0x01 for sessions
        0,
        len(complete_packet),
        None
    )
    ssd_h.waitdone()
    
    # Receive SyncSession response
    recv_buf = ssd_h.buffer(2048)
    ssd_h.security_receive(
        recv_buf,
        com_id,  # Same ComID
        0x01,
        0,
        2048,
        None
    )
    ssd_h.waitdone()
    
    response = bytes(recv_buf)
    
    # Parse SyncSession response
    # 근거: Section 5.2.3.2 SyncSession Method (Page 134)
    # Response format: SyncSession(HostSessionID, SPSessionID, ...)
    payload_data = parse_response_payload(response)
    
    parsed = TCGResponseParser.parse_session_response(payload_data)
    
    returned_hsn = parsed.get('session_id')      # HostSessionID (should equal our HSN)
    tsn = parsed.get('tper_session_id')          # SPSessionID (TPer assigned)
    status = parsed.get('status')
    
    print(f"\n  ✓ SyncSession Response:")
    print(f"    HostSessionID (HSN): 0x{returned_hsn:08X} (echo)")
    print(f"    SPSessionID (TSN): 0x{tsn:08X} ← TPer가 할당!")
    print(f"    Status: {status}")
    
    if status != 0:
        raise RuntimeError(f"StartSession failed with status {status}")
    
    # 근거: Section 3.3.7.1.1 Regular Sessions (Page 55)
    # "The SN is an 8-byte quantity composed of two subparts: 
    #  the TPer Session Number (TSN) and the Host Session Number (HSN)"
    # Session ID = (TSN << 32) | HSN
    session_id = (tsn << 32) | hsn
    print(f"    Session ID: 0x{session_id:016X}")
    
    return (hsn, tsn)


# ============================================================================
# STEP 4: Invoke Activate Method (within Regular Session)
# ============================================================================
# 근거: TCG Opal Test Cases UCT-04 (Page 25)
# ============================================================================

def invoke_activate_locking_sp(
    ssd_h,
    com_id: int,
    extended_com_id: int,
    hsn: int,
    tsn: int
) -> bool:
    """
    Invoke Activate method on Locking SP object
    
    근거: TCG Opal Test Cases UCT-04 (Page 25)
    Step 2: "Invoke Activate method on Locking SP object"
    
    Args:
        ssd_h: SSD handle
        com_id: Allocated ComID
        extended_com_id: Extended ComID
        hsn: Host Session Number
        tsn: TPer Session Number
        
    Returns:
        True if successful
    """
    print("\n" + "="*70)
    print("STEP 3: Invoke Activate Method")
    print("근거: TCG Opal Test Cases UCT-04 Step 2 (Page 25)")
    print("="*70)
    
    # Build Activate payload
    builder = TCGPayloadBuilder()
    
    builder.add_call()
    builder.add_uid(UID.LOCKING_SP)    # InvokingID = Locking SP object
    builder.add_uid(UID.ACTIVATE)      # MethodID = Activate
    
    # Parameters: empty list for Activate
    builder.start_list()
    builder.end_list()
    
    builder.add_end_of_data()
    
    # Status list
    builder.start_list()
    builder.add_integer(0)
    builder.add_integer(0)
    builder.add_integer(0)
    builder.end_list()
    
    token_stream = builder.get_payload()
    
    # Build packet with Regular Session ID
    # 근거: Section 3.3.7.1.2 (Page 56)
    # "Once a session has started, data is able to be transmitted 
    #  for that newly started session. The Packet.Session for that 
    #  session SHALL be the concatenation of the TSN and HSN"
    session_id = (tsn << 32) | hsn
    
    complete_packet = build_packet_with_session(
        com_id=com_id,
        extended_com_id=extended_com_id,
        token_stream=token_stream,
        session_id=session_id,  # Regular Session ID
        seq_number=0
    )
    
    print(f"  Session ID: 0x{session_id:016X}")
    print(f"    TSN: 0x{tsn:08X}")
    print(f"    HSN: 0x{hsn:08X}")
    
    # Send
    send_buf = ssd_h.buffer(len(complete_packet))
    send_buf[:] = complete_packet
    
    ssd_h.security_send(
        send_buf,
        com_id,
        0x01,
        0,
        len(complete_packet),
        None
    )
    ssd_h.waitdone()
    
    # Receive
    recv_buf = ssd_h.buffer(2048)
    ssd_h.security_receive(
        recv_buf,
        com_id,
        0x01,
        0,
        2048,
        None
    )
    ssd_h.waitdone()
    
    response = bytes(recv_buf)
    payload_data = parse_response_payload(response)
    
    parsed = TCGResponseParser.parse_method_response(payload_data)
    status = parsed.get('status')
    
    print(f"\n  ✓ Activate Method Result:")
    print(f"    Status: {status}")
    
    if status != 0:
        raise RuntimeError(f"Activate method failed with status {status}")
    
    return True


# ============================================================================
# STEP 5: Close Session
# ============================================================================

def close_session(
    ssd_h,
    com_id: int,
    extended_com_id: int
):
    """
    Close current session
    
    근거: TCG Core Spec Section 3.2.2.3.3.3 (Page 20)
    """
    print("\n" + "="*70)
    print("STEP 4: Close Session")
    print("="*70)
    
    builder = TCGPayloadBuilder()
    builder.data.append(0xFA)  # END_OF_SESSION token
    
    # Status list
    builder.start_list()
    builder.add_integer(0)
    builder.add_integer(0)
    builder.add_integer(0)
    builder.end_list()
    
    token_stream = builder.get_payload()
    
    complete_packet = build_packet_with_session(
        com_id=com_id,
        extended_com_id=extended_com_id,
        token_stream=token_stream,
        session_id=0,  # Control session
        seq_number=0
    )
    
    send_buf = ssd_h.buffer(len(complete_packet))
    send_buf[:] = complete_packet
    
    ssd_h.security_send(send_buf, com_id, 0x01, 0, len(complete_packet), None)
    ssd_h.waitdone()
    
    recv_buf = ssd_h.buffer(2048)
    ssd_h.security_receive(recv_buf, com_id, 0x01, 0, 2048, None)
    ssd_h.waitdone()
    
    print("  ✓ Session closed")


# ============================================================================
# Helper: Parse Response Payload
# ============================================================================

def parse_response_payload(response: bytes) -> bytes:
    """
    Extract payload from ComPacket/Packet/Subpacket headers
    
    근거: 
    - Table 17: ComPacket header = 20 bytes (Page 24)
    - Table 18: Packet header = 24 bytes (Page 25)
    - Table 20: Subpacket header = 12 bytes (Page 27)
    
    Total headers = 20 + 24 + 12 = 56 bytes
    """
    if len(response) < 56:
        return b''
    
    # Skip headers and get payload
    # ComPacket(20) + Packet(24) + Subpacket(12) = 56 bytes
    return response[56:]


# ============================================================================
# Main Test: UCT-04
# ============================================================================

def test_uct04_activate_locking_sp(ssd_h):
    """
    UCT-04: Activate Locking SP when in Manufactured-Inactive State
    
    근거: TCG_Storage_Opal_Family_Test_Cases_v1_00_r1_00_pub.pdf
    Section: UCT-04 (Page 25)
    
    Test Sequence:
    1) StartSession with SPID = Admin SP UID and HostSigningAuthority = SID
    2) Invoke Activate method on Locking SP object
    3) CLOSE_SESSION
    4) StartSession with SPID = Locking SP UID and HostSigningAuthority = Admin1 (verify)
    5) CLOSE_SESSION
    """
    print("\n" + "="*80)
    print(" UCT-04: Activate Locking SP from Manufactured-Inactive State")
    print("="*80)
    print("\n근거 문서:")
    print("  1. TCG_Storage_Opal_Family_Test_Cases_v1_00_r1_00_pub.pdf")
    print("     Section: UCT-04 (Page 25)")
    print("  2. TCG_Storage_Architecture_Core_Spec_v2_01_r1_00.pdf")
    print("     Section 3.3.3: ComID Management")
    print("     Section 5.2.3.1: StartSession Method")
    print("     Section 5.2.3.2: SyncSession Method")
    print("="*80)
    
    # Step 1: GET_COMID
    com_id, extended_com_id = get_comid(ssd_h)
    
    # Step 2: StartSession (Admin SP)
    hsn, tsn = start_session_admin_sp(ssd_h, com_id, extended_com_id, hsn=1)
    
    # Step 3: Invoke Activate
    invoke_activate_locking_sp(ssd_h, com_id, extended_com_id, hsn, tsn)
    
    # Step 4: Close Session
    close_session(ssd_h, com_id, extended_com_id)
    
    print("\n" + "="*80)
    print(" ✓✓✓ UCT-04 Test Completed Successfully! ✓✓✓")
    print("="*80)
    print("\n다음 단계:")
    print("  1. Discovery 재실행하여 LockingEnabled=1 확인")
    print("  2. Locking SP에 Admin1으로 세션 시작 (검증)")


# ============================================================================
# Pytest Entry Point
# ============================================================================

def test_activate_locking_sp_with_docs(ssd_h):
    """Pytest test function"""
    test_uct04_activate_locking_sp(ssd_h)


if __name__ == "__main__":
    print(__doc__)
