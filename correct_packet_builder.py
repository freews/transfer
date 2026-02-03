"""
TCG Opal Correct Packet Structure
==================================

TCG Spec에 따른 정확한 패킷 구조 구현
"""

import struct
from typing import List, Optional


# ============================================================================
# Level 3: Subpacket (가장 안쪽)
# ============================================================================

class SubpacketBuilder:
    """
    Data Subpacket 생성
    
    TCG Spec Table 20 - Data SubPacket Format:
    - Bytes 0-5: Reserved (6 bytes)
    - Bytes 6-7: Kind (2 bytes)
    - Bytes 8-11: Length (4 bytes) = n (payload 길이, padding 제외)
    - Bytes 12 to (n+(-n modulo 4))+11: Payload
    
    Subpacket 전체 크기 = 12 + n + padding
    padding = (-n modulo 4)
    """
    
    @staticmethod
    def build(payload: bytes) -> bytes:
        """
        Subpacket 생성
        
        Args:
            payload: Token stream (실제 데이터)
            
        Returns:
            완전한 Subpacket (header + payload + padding)
        """
        n = len(payload)
        
        # Padding 계산: (-n modulo 4)
        # Python에서: (4 - (n % 4)) % 4
        padding_size = (4 - (n % 4)) % 4
        padding = bytes(padding_size)
        
        # Header (12 bytes)
        header = struct.pack(
            '>6s H I',
            bytes(6),    # Reserved: 6 bytes
            0x0000,      # Kind: 2 bytes (0x0000 = Data)
            n            # Length: 4 bytes (payload만, padding 제외!)
        )
        
        # 전체 Subpacket
        subpacket = header + payload + padding
        
        return subpacket


# ============================================================================
# Level 2: Packet
# ============================================================================

class PacketBuilder:
    """
    Packet 생성
    
    TCG Spec Table 18 - Packet Format:
    - Bytes 0-7: Session (8 bytes) = TSN(4) + HSN(4)
    - Bytes 8-11: SeqNumber (4 bytes)
    - Bytes 12-13: Reserved (2 bytes)
    - Bytes 14-15: AckType (2 bytes)
    - Bytes 16-19: Acknowledgement (4 bytes)
    - Bytes 20-23: Length (4 bytes) = n (subpacket들의 전체 크기)
    - Bytes 24 to n+23: Payload (하나 이상의 Subpacket)
    
    Packet 전체 크기 = 24 + n
    """
    
    @staticmethod
    def build(
        session: int = 0,
        seq_number: int = 0,
        subpackets: List[bytes] = None
    ) -> bytes:
        """
        Packet 생성
        
        Args:
            session: Session ID (8 bytes, TSN+HSN)
            seq_number: Sequence number
            subpackets: Subpacket 리스트
            
        Returns:
            완전한 Packet (header + subpackets)
        """
        if subpackets is None:
            subpackets = []
        
        # Subpacket들의 전체 크기
        payload = b''.join(subpackets)
        n = len(payload)
        
        # Header (24 bytes)
        header = struct.pack(
            '>Q I H H I I',
            session,     # Session: 8 bytes (TSN + HSN)
            seq_number,  # SeqNumber: 4 bytes
            0,           # Reserved: 2 bytes
            0,           # AckType: 2 bytes
            0,           # Acknowledgement: 4 bytes
            n            # Length: 4 bytes (subpacket들의 전체 크기)
        )
        
        # 전체 Packet
        packet = header + payload
        
        return packet


# ============================================================================
# Level 1: ComPacket (가장 바깥)
# ============================================================================

class ComPacketBuilder:
    """
    ComPacket 생성
    
    TCG Spec Table 17 - ComPacket Format:
    - Bytes 0-3: Reserved (4 bytes)
    - Bytes 4-5: ComID (2 bytes)
    - Bytes 6-7: ComID Extension (2 bytes)
    - Bytes 8-11: OutstandingData (4 bytes)
    - Bytes 12-15: MinTransfer (4 bytes)
    - Bytes 16-19: Length (4 bytes) = n (packet들의 전체 크기)
    - Bytes 20 to n+19: Payload (하나 이상의 Packet)
    
    ComPacket 전체 크기 = 20 + n
    """
    
    @staticmethod
    def build(
        com_id: int,
        packets: List[bytes],
        extended_com_id: int = 0
    ) -> bytes:
        """
        ComPacket 생성
        
        Args:
            com_id: ComID (보통 0x0001)
            packets: Packet 리스트
            extended_com_id: Extended ComID (보통 0)
            
        Returns:
            완전한 ComPacket (header + packets)
        """
        # Packet들의 전체 크기
        payload = b''.join(packets)
        n = len(payload)
        
        # Header (20 bytes)
        header = struct.pack(
            '>I H H I I I',
            0,                  # Reserved: 4 bytes
            com_id,             # ComID: 2 bytes
            extended_com_id,    # ComID Extension: 2 bytes
            0,                  # OutstandingData: 4 bytes
            0,                  # MinTransfer: 4 bytes
            n                   # Length: 4 bytes (packet들의 전체 크기)
        )
        
        # 전체 ComPacket
        com_packet = header + payload
        
        return com_packet


# ============================================================================
# 편의 함수: 전체 패킷 생성
# ============================================================================

def build_complete_packet(token_stream: bytes) -> bytes:
    """
    Token stream으로부터 완전한 TCG 패킷 생성
    
    Args:
        token_stream: TCG token들의 바이트 스트림
        
    Returns:
        완전한 ComPacket
    """
    # Level 3: Subpacket 생성
    subpacket = SubpacketBuilder.build(token_stream)
    
    # Level 2: Packet 생성
    packet = PacketBuilder.build(
        session=0,         # StartSession 전이므로 0
        seq_number=0,      # 첫 번째 패킷이므로 0
        subpackets=[subpacket]
    )
    
    # Level 1: ComPacket 생성
    com_packet = ComPacketBuilder.build(
        com_id=0x0001,     # Level 0 Discovery나 Session용
        packets=[packet]
    )
    
    return com_packet


# ============================================================================
# 예제 및 테스트
# ============================================================================

def example_usage():
    """사용 예제"""
    
    print("=" * 70)
    print("TCG Opal Correct Packet Structure Example")
    print("=" * 70)
    
    # 예제 token stream (StartSession의 일부)
    token_stream = bytes([
        0xF8,  # CALL
        0xA8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF,  # InvokingID
        0xA8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x02,  # MethodID
        0xF0,  # START_LIST
        0x01,  # HostSessionID = 1
        0xF1,  # END_LIST
        0xF9,  # END_OF_DATA
    ])
    
    print(f"\n1. Token stream: {len(token_stream)} bytes")
    print(f"   {token_stream.hex()}")
    
    # Subpacket 생성
    subpacket = SubpacketBuilder.build(token_stream)
    print(f"\n2. Subpacket: {len(subpacket)} bytes")
    print(f"   Header (12): {subpacket[:12].hex()}")
    print(f"   Payload ({len(token_stream)}): {subpacket[12:12+len(token_stream)].hex()}")
    padding_size = len(subpacket) - 12 - len(token_stream)
    if padding_size > 0:
        print(f"   Padding ({padding_size}): {subpacket[12+len(token_stream):].hex()}")
    
    # Subpacket 구조 분석
    reserved = subpacket[0:6]
    kind = struct.unpack('>H', subpacket[6:8])[0]
    length = struct.unpack('>I', subpacket[8:12])[0]
    print(f"\n   Subpacket.Reserved = {reserved.hex()}")
    print(f"   Subpacket.Kind = 0x{kind:04X}")
    print(f"   Subpacket.Length = {length}")
    
    # Packet 생성
    packet = PacketBuilder.build(
        session=0,
        seq_number=0,
        subpackets=[subpacket]
    )
    print(f"\n3. Packet: {len(packet)} bytes")
    print(f"   Header (24): {packet[:24].hex()}")
    print(f"   Payload ({len(subpacket)}): {packet[24:].hex()}")
    
    # Packet 구조 분석
    session = struct.unpack('>Q', packet[0:8])[0]
    seq_num = struct.unpack('>I', packet[8:12])[0]
    packet_length = struct.unpack('>I', packet[20:24])[0]
    print(f"\n   Packet.Session = 0x{session:016X}")
    print(f"   Packet.SeqNumber = {seq_num}")
    print(f"   Packet.Length = {packet_length}")
    
    # ComPacket 생성
    com_packet = ComPacketBuilder.build(
        com_id=0x0001,
        packets=[packet]
    )
    print(f"\n4. ComPacket: {len(com_packet)} bytes")
    print(f"   Header (20): {com_packet[:20].hex()}")
    print(f"   Payload ({len(packet)}): {com_packet[20:].hex()}")
    
    # ComPacket 구조 분석
    com_id = struct.unpack('>H', com_packet[4:6])[0]
    com_length = struct.unpack('>I', com_packet[16:20])[0]
    print(f"\n   ComPacket.ComID = 0x{com_id:04X}")
    print(f"   ComPacket.Length = {com_length}")
    
    # 검증
    print("\n" + "=" * 70)
    print("검증")
    print("=" * 70)
    
    expected_subpacket_size = 12 + len(token_stream) + padding_size
    expected_packet_size = 24 + expected_subpacket_size
    expected_compacket_size = 20 + expected_packet_size
    
    print(f"Expected Subpacket size: {expected_subpacket_size} bytes")
    print(f"Actual Subpacket size:   {len(subpacket)} bytes")
    print(f"Match: {len(subpacket) == expected_subpacket_size}")
    
    print(f"\nExpected Packet size: {expected_packet_size} bytes")
    print(f"Actual Packet size:   {len(packet)} bytes")
    print(f"Match: {len(packet) == expected_packet_size}")
    
    print(f"\nExpected ComPacket size: {expected_compacket_size} bytes")
    print(f"Actual ComPacket size:   {len(com_packet)} bytes")
    print(f"Match: {len(com_packet) == expected_compacket_size}")
    
    # Length 필드 검증
    print(f"\n" + "=" * 70)
    print("Length 필드 검증")
    print("=" * 70)
    
    print(f"Subpacket.Length = {length}")
    print(f"Token stream actual length = {len(token_stream)}")
    print(f"Match (padding 제외): {length == len(token_stream)}")
    
    print(f"\nPacket.Length = {packet_length}")
    print(f"Subpacket actual size = {len(subpacket)}")
    print(f"Match (header 제외): {packet_length == len(subpacket)}")
    
    print(f"\nComPacket.Length = {com_length}")
    print(f"Packet actual size = {len(packet)}")
    print(f"Match (header 제외): {com_length == len(packet)}")
    
    return com_packet


if __name__ == "__main__":
    result = example_usage()
    
    print("\n" + "=" * 70)
    print("최종 ComPacket")
    print("=" * 70)
    print(f"Total size: {len(result)} bytes")
    print(f"Hex dump:")
    
    # Hex dump with offsets
    for i in range(0, len(result), 16):
        hex_part = ' '.join(f'{b:02x}' for b in result[i:i+16])
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in result[i:i+16])
        print(f"{i:04x}:  {hex_part:<48}  {ascii_part}")
