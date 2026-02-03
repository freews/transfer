"""
TCG Detokenizer
===============

파싱된 TCG 응답을 사람이 읽기 쉬운 형태로 변환
"""

from typing import Any, Dict, List, Optional, Union
import json


class TCGDetokenizer:
    """TCG 토큰을 사람이 읽기 쉬운 형태로 변환"""
    
    # UID → 이름 매핑
    UID_NAMES = {
        # Session Manager
        bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF]): 'SMUID',
        
        # Methods
        bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x01]): 'PROPERTIES',
        bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x02]): 'START_SESSION',
        bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x03]): 'SYNC_SESSION',
        
        # SPs
        bytes([0x00, 0x00, 0x02, 0x05, 0x00, 0x00, 0x00, 0x01]): 'AdminSP',
        bytes([0x00, 0x00, 0x02, 0x05, 0x00, 0x00, 0x00, 0x02]): 'LockingSP',
        
        # Authorities
        bytes([0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x06]): 'SID',
        bytes([0x00, 0x00, 0x00, 0x09, 0x00, 0x01, 0x00, 0x01]): 'Admin1',
        bytes([0x00, 0x00, 0x00, 0x09, 0x00, 0x03, 0x00, 0x01]): 'User1',
        bytes([0x00, 0x00, 0x00, 0x09, 0x00, 0x03, 0x00, 0x02]): 'User2',
        
        # Tables
        bytes([0x00, 0x00, 0x00, 0x0B, 0x00, 0x00, 0x00, 0x00]): 'C_PIN_Table',
        bytes([0x00, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00, 0x00]): 'LockingInfo_Table',
        
        # Methods
        bytes([0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x02]): 'REVERT',
        bytes([0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x03]): 'ACTIVATE',
        bytes([0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x16]): 'GET',
        bytes([0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x17]): 'SET',
        bytes([0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x0C]): 'AUTHENTICATE',
    }
    
    # Status Code → 이름/설명 매핑
    STATUS_INFO = {
        0x00: {
            'name': 'SUCCESS',
            'description': 'Method processed completely without error'
        },
        0x01: {
            'name': 'NOT_AUTHORIZED',
            'description': 'No authorization to invoke this method'
        },
        0x03: {
            'name': 'SP_BUSY',
            'description': 'SP is busy with another session'
        },
        0x04: {
            'name': 'SP_FAILED',
            'description': 'SP is in Failed life cycle state'
        },
        0x05: {
            'name': 'SP_DISABLED',
            'description': 'SP is in IssuedDisabled state'
        },
        0x06: {
            'name': 'SP_FROZEN',
            'description': 'SP is in Frozen state'
        },
        0x07: {
            'name': 'NO_SESSIONS_AVAILABLE',
            'description': 'Maximum number of concurrent sessions in use'
        },
        0x08: {
            'name': 'UNIQUENESS_CONFLICT',
            'description': 'Unique column combination already exists'
        },
        0x09: {
            'name': 'INSUFFICIENT_SPACE',
            'description': 'Not enough space to complete operation'
        },
        0x0A: {
            'name': 'INSUFFICIENT_ROWS',
            'description': 'Cannot create required metadata rows'
        },
        0x0C: {
            'name': 'INVALID_PARAMETER',
            'description': 'Method invocation has invalid parameters'
        },
        0x0F: {
            'name': 'TPER_MALFUNCTION',
            'description': 'TPer operational failure'
        },
        0x10: {
            'name': 'TRANSACTION_FAILURE',
            'description': 'Method failed due to transactional context'
        },
        0x11: {
            'name': 'RESPONSE_OVERFLOW',
            'description': 'Response data too large'
        },
        0x12: {
            'name': 'AUTHORITY_LOCKED_OUT',
            'description': 'Authority is locked out'
        },
        0x3F: {
            'name': 'FAIL',
            'description': 'General failure'
        }
    }
    
    @staticmethod
    def uid_to_string(uid: bytes) -> str:
        """UID를 문자열로 변환"""
        if uid in TCGDetokenizer.UID_NAMES:
            name = TCGDetokenizer.UID_NAMES[uid]
            hex_str = ':'.join(f'{b:02X}' for b in uid)
            return f"{name} ({hex_str})"
        else:
            return ':'.join(f'{b:02X}' for b in uid)
    
    @staticmethod
    def bytes_to_int(data: Any) -> int:
        """bytes를 int로 변환"""
        if isinstance(data, int):
            return data
        elif isinstance(data, bytes):
            if len(data) == 0:
                return 0
            return int.from_bytes(data, 'big')
        else:
            return 0
    
    @staticmethod
    def format_value(value: Any) -> Any:
        """값을 포맷팅"""
        if isinstance(value, bytes):
            # 8 bytes면 UID일 가능성
            if len(value) == 8:
                return TCGDetokenizer.uid_to_string(value)
            # 그 외는 hex
            elif len(value) <= 32:
                return f"0x{value.hex().upper()}"
            else:
                return f"<{len(value)} bytes>"
        elif isinstance(value, int):
            if value > 255:
                return f"{value} (0x{value:X})"
            else:
                return value
        elif isinstance(value, list):
            return [TCGDetokenizer.format_value(v) for v in value]
        elif isinstance(value, dict):
            return {k: TCGDetokenizer.format_value(v) for k, v in value.items()}
        else:
            return value
    
    @staticmethod
    def detokenize_sync_session(parsed: List[Any]) -> Dict[str, Any]:
        """
        SyncSession 응답 Detokenize
        
        구조:
        [0]: {'type': 'CALL'}
        [1]: SMUID (8 bytes)
        [2]: SYNC_SESSION method UID (8 bytes)
        [3]: [HSN, TSN, ...] parameter list
        [4]: [status_code, 0, 0] status list
        """
        result = {
            'type': 'SyncSession Response',
            'method': 'SYNC_SESSION',
        }
        
        # Skip CALL token (parsed[0])
        start_idx = 1 if (len(parsed) > 0 and isinstance(parsed[0], dict) and parsed[0].get('type') == 'CALL') else 0
        
        if len(parsed) >= start_idx + 2:
            # SMUID
            if isinstance(parsed[start_idx], bytes) and len(parsed[start_idx]) == 8:
                result['invoking_uid'] = TCGDetokenizer.uid_to_string(parsed[start_idx])
            
            # Method UID
            if isinstance(parsed[start_idx + 1], bytes) and len(parsed[start_idx + 1]) == 8:
                result['method_uid'] = TCGDetokenizer.uid_to_string(parsed[start_idx + 1])
        
        # Parameters list [HSN, TSN, ...]
        if len(parsed) >= start_idx + 3 and isinstance(parsed[start_idx + 2], list):
            params = parsed[start_idx + 2]
            if len(params) >= 2:
                # HSN
                hsn = TCGDetokenizer.bytes_to_int(params[0])
                result['host_session_id'] = hsn
                
                # TSN
                tsn = TCGDetokenizer.bytes_to_int(params[1])
                result['tper_session_id'] = tsn
                
                # TSN 특별 값 체크
                if tsn == 0xFFFFFFFF:
                    result['session_status'] = 'FAILED (Invalid TSN)'
                else:
                    result['session_status'] = 'SUCCESS'
        
        # Status
        if len(parsed) >= start_idx + 4 and isinstance(parsed[start_idx + 3], list):
            status_code = TCGDetokenizer.bytes_to_int(parsed[start_idx + 3][0]) if len(parsed[start_idx + 3]) > 0 else 0
            
            status_info = TCGDetokenizer.STATUS_INFO.get(status_code, {
                'name': f'UNKNOWN_{status_code:02X}',
                'description': 'Unknown status code'
            })
            
            result['status'] = {
                'code': status_code,
                'hex': f'0x{status_code:02X}',
                'name': status_info['name'],
                'description': status_info['description']
            }
        
        return result
    
    @staticmethod
    def detokenize_method_response(parsed: List[Any]) -> Dict[str, Any]:
        """
        일반 Method 응답 Detokenize
        
        구조:
        [0]: [status_code, ...]
        [1]: [result_data, ...]
        """
        result = {
            'type': 'Method Response',
        }
        
        # Status
        if len(parsed) >= 1 and isinstance(parsed[0], list):
            status_list = parsed[0]
            if len(status_list) > 0:
                status_code = TCGDetokenizer.bytes_to_int(status_list[0])
                
                status_info = TCGDetokenizer.STATUS_INFO.get(status_code, {
                    'name': f'UNKNOWN_{status_code:02X}',
                    'description': 'Unknown status code'
                })
                
                result['status'] = {
                    'code': status_code,
                    'hex': f'0x{status_code:02X}',
                    'name': status_info['name'],
                    'description': status_info['description']
                }
        
        # Result Data
        if len(parsed) >= 2 and isinstance(parsed[1], list):
            result['data'] = TCGDetokenizer.format_value(parsed[1])
        
        return result
    
    @staticmethod
    def auto_detokenize(parsed: List[Any]) -> Dict[str, Any]:
        """
        자동으로 응답 타입 감지하여 Detokenize
        """
        # Skip CALL token if present
        start_idx = 1 if (len(parsed) > 0 and isinstance(parsed[0], dict) and parsed[0].get('type') == 'CALL') else 0
        
        # SyncSession 감지: [CALL, UID, UID, [params], [status]]
        if (len(parsed) >= start_idx + 3 and 
            isinstance(parsed[start_idx], bytes) and len(parsed[start_idx]) == 8 and
            isinstance(parsed[start_idx + 1], bytes) and len(parsed[start_idx + 1]) == 8):
            
            # SYNC_SESSION UID 체크
            if parsed[start_idx + 1] == bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x03]):
                return TCGDetokenizer.detokenize_sync_session(parsed)
        
        # 일반 Method 응답: [[status...], [data...]]
        if len(parsed) >= 1 and isinstance(parsed[0], list):
            return TCGDetokenizer.detokenize_method_response(parsed)
        
        # 알 수 없는 형식
        return {
            'type': 'Unknown',
            'raw': TCGDetokenizer.format_value(parsed)
        }
    
    @staticmethod
    def pretty_print(detokenized: Dict[str, Any], indent: int = 2) -> str:
        """보기 좋게 출력"""
        return json.dumps(detokenized, indent=indent, ensure_ascii=False)


# =====================================================
# 사용 예제
# =====================================================

if __name__ == "__main__":
    # 예제: SyncSession 실패 응답
    parsed_data = [
        bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF]),  # SMUID
        bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x03]),  # SYNC_SESSION
        105,  # HSN
        0xFFFFFFFF,  # TSN (failed)
        [7, 0, 0]  # Status: NO_SESSIONS_AVAILABLE
    ]
    
    # Detokenize
    result = TCGDetokenizer.auto_detokenize(parsed_data)
    
    # 출력
    print(TCGDetokenizer.pretty_print(result))
    
    """
    예상 출력:
    {
      "type": "SyncSession Response",
      "method": "SYNC_SESSION",
      "invoking_uid": "SMUID (00:00:00:00:00:00:00:FF)",
      "method_uid": "SYNC_SESSION (00:00:00:00:00:00:00:FF:03)",
      "host_session_id": 105,
      "tper_session_id": 4294967295,
      "session_status": "FAILED (Invalid TSN)",
      "status": {
        "code": 7,
        "hex": "0x07",
        "name": "NO_SESSIONS_AVAILABLE",
        "description": "Maximum number of concurrent sessions in use"
      }
    }
    """
