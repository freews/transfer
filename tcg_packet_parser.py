"""
TCG Complete Packet Parser
==========================

ComPacket → Packet → SubPacket → Payload 전체 파싱 및 Detokenize
"""

import struct
from typing import Dict, Any, List, Optional, Tuple
from tcg_detokenizer import TCGDetokenizer


class TCGPacketParser:
    """TCG 전체 패킷 구조 파싱"""
    
    @staticmethod
    def parse_compacket(data: bytes) -> Dict[str, Any]:
        """
        ComPacket 헤더 파싱 (20 bytes)
        
        Structure:
        - Reserved: 4 bytes
        - ComID: 2 bytes (big-endian)
        - ComID Extension: 2 bytes (big-endian)
        - OutstandingData: 4 bytes (big-endian)
        - MinTransfer: 4 bytes (big-endian)
        - Length: 4 bytes (big-endian)
        """
        if len(data) < 20:
            return {'error': 'ComPacket too short', 'length': len(data)}
        
        # 헤더 파싱
        (reserved, com_id, com_id_ext, outstanding_data, 
         min_transfer, length) = struct.unpack('>IHHIII', data[:20])
        
        result = {
            'type': 'ComPacket',
            'header': {
                'reserved': f'0x{reserved:08X}',
                'com_id': f'0x{com_id:04X}',
                'com_id_extension': f'0x{com_id_ext:04X}',
                'outstanding_data': outstanding_data,
                'min_transfer': min_transfer,
                'length': length
            },
            'header_size': 20,
            'payload_size': length
        }
        
        # ComID 특별 값 체크
        if com_id == 0x0001:
            result['header']['com_id_info'] = 'Discovery/Stack Reset'
        elif 0x1000 <= com_id <= 0xFFFF:
            result['header']['com_id_info'] = 'Dynamic Session'
        
        # Payload 추출
        if len(data) >= 20 + length:
            result['payload'] = data[20:20+length]
        else:
            result['error'] = f'Incomplete payload: expected {length}, got {len(data)-20}'
        
        return result
    
    @staticmethod
    def parse_packet(data: bytes) -> Dict[str, Any]:
        """
        Packet 헤더 파싱 (24 bytes)
        
        Structure:
        - Session: 8 bytes (TSN:HSN, big-endian)
        - SeqNumber: 4 bytes (big-endian)
        - Reserved: 2 bytes
        - AckType: 2 bytes (big-endian)
        - Acknowledgement: 4 bytes (big-endian)
        - Length: 4 bytes (big-endian)
        """
        if len(data) < 24:
            return {'error': 'Packet too short', 'length': len(data)}
        
        # 헤더 파싱
        (session, seq_number, reserved, ack_type, 
         acknowledgement, length) = struct.unpack('>QIHHII', data[:24])
        
        # Session 분리 (TSN:HSN)
        tsn = (session >> 32) & 0xFFFFFFFF
        hsn = session & 0xFFFFFFFF
        
        result = {
            'type': 'Packet',
            'header': {
                'session': {
                    'raw': f'0x{session:016X}',
                    'tsn': tsn,
                    'hsn': hsn,
                    'tsn_hex': f'0x{tsn:08X}',
                    'hsn_hex': f'0x{hsn:08X}'
                },
                'seq_number': seq_number,
                'reserved': f'0x{reserved:04X}',
                'ack_type': f'0x{ack_type:04X}',
                'acknowledgement': acknowledgement,
                'length': length
            },
            'header_size': 24,
            'payload_size': length
        }
        
        # Session 상태 체크
        if tsn == 0 and hsn == 0:
            result['header']['session']['status'] = 'No active session'
        elif tsn == 0xFFFFFFFF:
            result['header']['session']['status'] = 'Session establishment failed'
        else:
            result['header']['session']['status'] = 'Active session'
        
        # Payload 추출
        if len(data) >= 24 + length:
            result['payload'] = data[24:24+length]
        else:
            result['error'] = f'Incomplete payload: expected {length}, got {len(data)-24}'
        
        return result
    
    @staticmethod
    def parse_subpacket(data: bytes) -> Dict[str, Any]:
        """
        Data SubPacket 헤더 파싱 (12 bytes)
        
        Structure:
        - Reserved: 6 bytes
        - Kind: 2 bytes (big-endian)
        - Length: 4 bytes (big-endian)
        """
        if len(data) < 12:
            return {'error': 'SubPacket too short', 'length': len(data)}
        
        # 헤더 파싱 (6 bytes reserved를 별도 처리)
        reserved = data[:6]
        kind, length = struct.unpack('>HI', data[6:12])
        
        result = {
            'type': 'SubPacket',
            'header': {
                'reserved': reserved.hex().upper(),
                'kind': f'0x{kind:04X}',
                'length': length
            },
            'header_size': 12,
            'payload_size': length
        }
        
        # Kind 해석
        if kind == 0x0000:
            result['header']['kind_info'] = 'Data'
        elif kind == 0x0001:
            result['header']['kind_info'] = 'Credit Control'
        
        # Payload 추출
        if len(data) >= 12 + length:
            result['payload'] = data[12:12+length]
        else:
            result['error'] = f'Incomplete payload: expected {length}, got {len(data)-12}'
        
        return result
    
    @staticmethod
    def parse_complete_packet(data: bytes) -> Dict[str, Any]:
        """
        전체 패킷 파싱: ComPacket → Packet → SubPacket → Payload → Detokenize
        """
        result = {
            'total_size': len(data),
            'layers': {}
        }
        
        offset = 0
        
        # 1. ComPacket 파싱
        compacket = TCGPacketParser.parse_compacket(data[offset:])
        result['layers']['compacket'] = compacket
        
        if 'error' in compacket:
            return result
        
        offset += compacket['header_size']
        compacket_payload = compacket['payload']
        
        # 2. Packet 파싱
        packet = TCGPacketParser.parse_packet(compacket_payload)
        result['layers']['packet'] = packet
        
        if 'error' in packet:
            return result
        
        packet_payload = packet['payload']
        
        # 3. SubPacket 파싱
        subpacket = TCGPacketParser.parse_subpacket(packet_payload)
        result['layers']['subpacket'] = subpacket
        
        if 'error' in subpacket:
            return result
        
        # 4. Payload 파싱 및 Detokenize
        from tcg_opal_codec import TCGPayloadParser
        
        payload_data = subpacket['payload']
        result['layers']['payload'] = {
            'raw_hex': payload_data.hex().upper(),
            'size': len(payload_data)
        }
        
        try:
            # 토큰 파싱
            parser = TCGPayloadParser(payload_data)
            parsed = parser.parse()
            result['layers']['payload']['parsed'] = parsed
            
            # Detokenize
            detokenized = TCGDetokenizer.auto_detokenize(parsed)
            result['layers']['payload']['detokenized'] = detokenized
            
        except Exception as e:
            result['layers']['payload']['parse_error'] = str(e)
        
        return result
    
    @staticmethod
    def create_summary(parsed: Dict[str, Any]) -> Dict[str, Any]:
        """
        파싱 결과 요약
        """
        summary = {
            'total_size': parsed.get('total_size', 0)
        }
        
        # ComPacket 정보
        if 'compacket' in parsed.get('layers', {}):
            cp = parsed['layers']['compacket']['header']
            summary['com_id'] = cp['com_id']
            
        # Session 정보
        if 'packet' in parsed.get('layers', {}):
            pkt = parsed['layers']['packet']['header']
            summary['session'] = {
                'tsn': pkt['session']['tsn'],
                'hsn': pkt['session']['hsn'],
                'status': pkt['session']['status']
            }
        
        # Detokenized 정보
        if 'payload' in parsed.get('layers', {}):
            if 'detokenized' in parsed['layers']['payload']:
                dt = parsed['layers']['payload']['detokenized']
                summary['method'] = dt.get('method', dt.get('type', 'Unknown'))
                if 'status' in dt:
                    summary['status'] = dt['status']['name']
        
        return summary


class TCGPacketBuilder:
    """TCG 완전한 패킷 생성"""
    
    @staticmethod
    def build_complete_packet(
        com_id: int,
        payload: bytes,
        tsn: int = 0,
        hsn: int = 0,
        seq_number: int = 0
    ) -> bytes:
        """
        완전한 패킷 생성: ComPacket + Packet + SubPacket + Payload
        """
        # SubPacket 생성
        subpacket_header = struct.pack('>6sHI',
            b'\x00' * 6,  # Reserved
            0x0000,       # Kind: Data
            len(payload)  # Length
        )
        subpacket = subpacket_header + payload
        
        # Packet 생성
        session = (tsn << 32) | hsn
        packet_header = struct.pack('>QIHHII',
            session,         # TSN:HSN
            seq_number,      # SeqNumber
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
    
    @staticmethod
    def build_discovery_packet() -> bytes:
        """Discovery 패킷 생성 (ComID 0x0001)"""
        # Discovery는 빈 payload
        return TCGPacketBuilder.build_complete_packet(
            com_id=0x0001,
            payload=b'',
            tsn=0,
            hsn=0
        )


# =====================================================
# 사용 예제
# =====================================================

if __name__ == "__main__":
    import json
    
    # 예제: SyncSession 실패 응답 패킷 (간단한 버전)
    # 실제로는 ComPacket + Packet + SubPacket + Payload 모두 포함
    
    # Payload 생성 (SyncSession 응답)
    from tcg_opal_codec import TCGPayloadBuilder, UID
    
    builder = TCGPayloadBuilder()
    builder.add_call()
    builder.add_uid(UID.SM_UID)
    builder.add_uid(UID.SYNC_SESSION)
    builder.start_list()
    builder.add_integer(105)  # HSN
    builder.add_integer(0xFFFFFFFF)  # TSN (failed)
    builder.end_list()
    builder.add_end_of_data()
    builder.start_list()
    builder.add_integer(7)  # Status: NO_SESSIONS_AVAILABLE
    builder.add_integer(0)
    builder.add_integer(0)
    builder.end_list()
    
    payload = builder.get_payload()
    
    # 완전한 패킷 생성
    complete_packet = TCGPacketBuilder.build_complete_packet(
        com_id=0x1000,
        payload=payload,
        tsn=0,
        hsn=105
    )
    
    print("=" * 70)
    print("Complete Packet Hex:")
    print("=" * 70)
    print(complete_packet.hex().upper())
    print()
    
    # 패킷 파싱
    print("=" * 70)
    print("Parsed Packet Structure:")
    print("=" * 70)
    parsed = TCGPacketParser.parse_complete_packet(complete_packet)
    print(json.dumps(parsed, indent=2, default=str))
    print()
    
    # 요약
    print("=" * 70)
    print("Summary:")
    print("=" * 70)
    summary = TCGPacketParser.create_summary(parsed)
    print(json.dumps(summary, indent=2))
