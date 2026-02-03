"""
올바른 패킷 구조를 기존 코드에 통합하는 방법
===========================================
"""

from correct_packet_builder import build_complete_packet, SubpacketBuilder, PacketBuilder, ComPacketBuilder
from tcg_opal_codec import TCGPayloadBuilder, UID


# ============================================================================
# 방법 1: 간단한 방식 (권장)
# ============================================================================

def send_startsession_simple(ssd_h, host_session_id=1, sp_uid=None):
    """
    StartSession 전송 - 간단한 방식
    
    build_complete_packet()을 사용하여 자동으로 nested structure 생성
    """
    if sp_uid is None:
        sp_uid = UID.ADMIN_SP
    
    # 1. Token stream 생성 (기존 방식 그대로)
    builder = TCGPayloadBuilder()
    
    builder.add_call()
    builder.add_uid(UID.SM_UID)
    builder.add_uid(UID.START_SESSION)
    
    builder.start_list()
    builder.add_integer(host_session_id)
    builder.add_uid(sp_uid)
    builder.add_integer(1)  # Write
    builder.end_list()
    
    builder.add_end_of_data()
    
    # Status list
    builder.start_list()
    builder.add_integer(0)
    builder.add_integer(0)
    builder.add_integer(0)
    builder.end_list()
    
    payload = builder.get_payload()
    
    # 2. 올바른 nested packet 생성 ⭐ 핵심!
    complete_packet = build_complete_packet(payload)
    
    # 3. 전송
    send_buf = ssd_h.buffer(len(complete_packet))
    send_buf[:] = complete_packet
    
    ssd_h.security_send(
        send_buf,
        0x0001,
        1,  # SECURITY_PROTOCOL_TCG
        0,
        len(complete_packet),
        None
    )
    ssd_h.waitdone()
    
    print(f"✓ Sent StartSession: {len(complete_packet)} bytes")
    print(f"  Token stream: {len(payload)} bytes")
    print(f"  Complete packet structure: ComPacket(20) + Packet(24) + Subpacket(12+{len(payload)}+padding)")


# ============================================================================
# 방법 2: 세밀한 제어 (필요 시)
# ============================================================================

def send_startsession_detailed(ssd_h, host_session_id=1, sp_uid=None):
    """
    StartSession 전송 - 세밀한 제어
    
    각 레벨을 수동으로 제어해야 할 때 사용
    """
    if sp_uid is None:
        sp_uid = UID.ADMIN_SP
    
    # 1. Token stream 생성
    builder = TCGPayloadBuilder()
    # ... (동일)
    payload = builder.get_payload()
    
    # 2. Level 3: Subpacket 생성
    subpacket = SubpacketBuilder.build(payload)
    
    # 3. Level 2: Packet 생성
    packet = PacketBuilder.build(
        session=0,         # StartSession 전이므로 0
        seq_number=0,      # 첫 패킷
        subpackets=[subpacket]
    )
    
    # 4. Level 1: ComPacket 생성
    complete_packet = ComPacketBuilder.build(
        com_id=0x0001,
        packets=[packet]
    )
    
    # 5. 전송
    send_buf = ssd_h.buffer(len(complete_packet))
    send_buf[:] = complete_packet
    
    ssd_h.security_send(
        send_buf,
        0x0001,
        1,
        0,
        len(complete_packet),
        None
    )
    ssd_h.waitdone()


# ============================================================================
# 방법 3: 기존 함수 수정
# ============================================================================

def build_session_payload_corrected(
    host_session_id: int,
    sp_uid: bytes,
    write: bool = True,
    host_challenge: bytes = None,
    host_signing_authority: bytes = None
) -> bytes:
    """
    올바른 StartSession Payload 생성
    
    기존 build_session_payload() 함수를 수정한 버전
    """
    builder = TCGPayloadBuilder()
    
    # Call token
    builder.add_call()
    
    # InvokingID (Session Manager)
    builder.add_uid(UID.SM_UID)
    
    # MethodID (StartSession)
    builder.add_uid(UID.START_SESSION)
    
    # Parameters
    builder.start_list()
    
    # HostSessionID
    builder.add_integer(host_session_id)
    
    # SPID
    builder.add_uid(sp_uid)
    
    # Write
    builder.add_integer(1 if write else 0)
    
    # Optional: HostChallenge
    if host_challenge:
        builder.start_name()
        builder.add_integer(0)  # Parameter: HostChallenge
        builder.add_bytes(host_challenge)
        builder.end_name()
    
    # Optional: HostSigningAuthority
    if host_signing_authority:
        builder.start_name()
        builder.add_integer(3)  # Parameter: HostSigningAuthority
        builder.add_uid(host_signing_authority)
        builder.end_name()
    
    builder.end_list()
    
    # End of Data
    builder.add_end_of_data()
    
    # Status list
    builder.start_list()
    builder.add_integer(0)
    builder.add_integer(0)
    builder.add_integer(0)
    builder.end_list()
    
    # Token stream 생성
    payload = builder.get_payload()
    
    # ⭐ 올바른 nested packet 생성
    complete_packet = build_complete_packet(payload)
    
    return complete_packet


# ============================================================================
# 사용 예제
# ============================================================================

def usage_example():
    """사용 예제"""
    
    print("=" * 70)
    print("통합 예제")
    print("=" * 70)
    
    # 예제 1: 간단한 방식 (권장)
    print("\n[방법 1: 간단한 방식]")
    print("payload = builder.get_payload()")
    print("complete_packet = build_complete_packet(payload)")
    print("send_buf[:] = complete_packet")
    
    # 예제 2: 기존 함수 대체
    print("\n[방법 2: 기존 함수 수정]")
    print("# 기존:")
    print("com_packet = TCGComPacketBuilder.build(com_id=0x0001, payload=payload)")
    print()
    print("# 수정:")
    print("complete_packet = build_complete_packet(payload)")
    
    # 예제 3: 실제 코드 변경
    print("\n[실제 코드 수정 예시]")
    print("""
# test_tcg_opal_final.py의 test_start_session_admin_sp() 수정

def test_start_session_admin_sp(self, ssd_h):
    # Token stream 생성
    builder = TCGPayloadBuilder()
    builder.add_call()
    builder.add_uid(UID.SM_UID)
    builder.add_uid(UID.START_SESSION)
    # ... (나머지 동일)
    
    payload = builder.get_payload()
    
    # ❌ 잘못된 방식 (기존)
    # com_packet = TCGComPacketBuilder.build(com_id=0x0001, payload=payload)
    
    # ✅ 올바른 방식 (수정)
    from correct_packet_builder import build_complete_packet
    complete_packet = build_complete_packet(payload)
    
    # 전송
    send_buf = ssd_h.buffer(len(complete_packet))
    send_buf[:] = complete_packet
    ssd_h.security_send(send_buf, 0x0001, SECURITY_PROTOCOL_TCG, 0, len(complete_packet), None)
    """)


if __name__ == "__main__":
    usage_example()
    
    print("\n" + "=" * 70)
    print("요약")
    print("=" * 70)
    print("""
기존 코드 수정 방법:

1. correct_packet_builder.py 임포트:
   from correct_packet_builder import build_complete_packet

2. 기존 코드에서:
   payload = builder.get_payload()
   
   # 기존 (삭제)
   # com_packet = TCGComPacketBuilder.build(com_id=0x0001, payload=payload)
   
   # 새로운 방식
   complete_packet = build_complete_packet(payload)

3. 나머지는 동일:
   send_buf[:] = complete_packet
   ssd_h.security_send(...)

그게 전부입니다! 매우 간단합니다.
    """)
