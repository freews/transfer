"""
TCG Payload Token Stream Parser
================================
SubPacket payload (token stream) 을 파싱하여
offset + hex + indent + remark 형태로 출력.

사용법:
    from tcg_payload_parser import parse_payload

    parse_payload(buf)          # buf: bytes (SubPacket payload 부분)
"""

# ============================================================================
# UID Name Mapping
# ============================================================================

# bytes(8) → human-readable name
UID_NAMES: dict[bytes, str] = {

    # ── Table 239: Special Purpose UIDs ─────────────────────────────────────
    bytes([0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00]): "NULL_UID",
    bytes([0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x01]): "ThisSP (SPUID)",
    bytes([0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0xFF]): "SMUID (Session Manager)",
    bytes([0x00,0x00,0x00,0x0B, 0x00,0x00,0x00,0x01]): "GenKey_CharSet_Unrestricted",

    # ── Table 241: Session Manager Methods ──────────────────────────────────
    bytes([0x00,0x00,0x00,0x00, 0x00,0x00,0xFF,0x01]): "SM_Properties",
    bytes([0x00,0x00,0x00,0x00, 0x00,0x00,0xFF,0x02]): "SM_StartSession",
    bytes([0x00,0x00,0x00,0x00, 0x00,0x00,0xFF,0x03]): "SM_SyncSession",
    bytes([0x00,0x00,0x00,0x00, 0x00,0x00,0xFF,0x04]): "SM_StartTrustedSession",
    bytes([0x00,0x00,0x00,0x00, 0x00,0x00,0xFF,0x05]): "SM_SyncTrustedSession",
    bytes([0x00,0x00,0x00,0x00, 0x00,0x00,0xFF,0x06]): "SM_CloseSession",

    # ── Table 242: MethodID UIDs ─────────────────────────────────────────────
    bytes([0x00,0x00,0x00,0x06, 0x00,0x00,0x00,0x00]): "DeleteSP",
    bytes([0x00,0x00,0x00,0x06, 0x00,0x00,0x00,0x01]): "CreateTable",
    bytes([0x00,0x00,0x00,0x06, 0x00,0x00,0x00,0x02]): "Delete",
    bytes([0x00,0x00,0x00,0x06, 0x00,0x00,0x00,0x03]): "CreateRow",
    bytes([0x00,0x00,0x00,0x06, 0x00,0x00,0x00,0x04]): "DeleteRow",
    bytes([0x00,0x00,0x00,0x06, 0x00,0x00,0x00,0x05]): "Next",
    bytes([0x00,0x00,0x00,0x06, 0x00,0x00,0x00,0x06]): "GetFreeSpace",
    bytes([0x00,0x00,0x00,0x06, 0x00,0x00,0x00,0x07]): "GetFreeRows",
    bytes([0x00,0x00,0x00,0x06, 0x00,0x00,0x00,0x08]): "DeleteMethod",
    bytes([0x00,0x00,0x00,0x06, 0x00,0x00,0x00,0x09]): "GetACL",
    bytes([0x00,0x00,0x00,0x06, 0x00,0x00,0x00,0x0A]): "AddACE",
    bytes([0x00,0x00,0x00,0x06, 0x00,0x00,0x00,0x0B]): "RemoveACE",
    bytes([0x00,0x00,0x00,0x06, 0x00,0x00,0x00,0x0C]): "GenKey",
    bytes([0x00,0x00,0x00,0x06, 0x00,0x00,0x00,0x0D]): "GetPackage",
    bytes([0x00,0x00,0x00,0x06, 0x00,0x00,0x00,0x0E]): "SetPackage",
    bytes([0x00,0x00,0x00,0x06, 0x00,0x00,0x00,0x0F]): "Get",
    bytes([0x00,0x00,0x00,0x06, 0x00,0x00,0x00,0x10]): "Set",
    bytes([0x00,0x00,0x00,0x06, 0x00,0x00,0x00,0x11]): "Authenticate",
    bytes([0x00,0x00,0x00,0x06, 0x00,0x00,0x00,0x12]): "Obsolete",
    bytes([0x00,0x00,0x00,0x06, 0x00,0x00,0x00,0x13]): "Obsolete",
    bytes([0x00,0x00,0x00,0x06, 0x00,0x00,0x00,0x14]): "Obsolete",
    bytes([0x00,0x00,0x00,0x06, 0x00,0x00,0x00,0x15]): "Obsolete",
    bytes([0x00,0x00,0x00,0x06, 0x00,0x00,0x00,0x16]): "Get",          # alias (per some SSC docs)
    bytes([0x00,0x00,0x00,0x06, 0x00,0x00,0x00,0x17]): "Set",          # alias
    bytes([0x00,0x00,0x00,0x06, 0x00,0x00,0x00,0x1C]): "Revert",
    bytes([0x00,0x00,0x00,0x06, 0x00,0x00,0x00,0x1D]): "Activate",
    bytes([0x00,0x00,0x00,0x06, 0x00,0x00,0x00,0x1E]): "Obsolete",
    bytes([0x00,0x00,0x00,0x06, 0x00,0x00,0x00,0x1F]): "Obsolete",
    bytes([0x00,0x00,0x00,0x06, 0x00,0x00,0x00,0x20]): "Obsolete",
    bytes([0x00,0x00,0x00,0x06, 0x00,0x00,0x02,0x01]): "RevertSP",
    bytes([0x00,0x00,0x00,0x06, 0x00,0x00,0x08,0x03]): "Erase",
    bytes([0x00,0x00,0x00,0x06, 0x00,0x00,0x08,0x04]): "WriteLock",
    bytes([0x00,0x00,0x00,0x06, 0x00,0x00,0x08,0x05]): "ReadLock",

    # ── Table 240: Table UIDs (Actual Table UID ends 00 00 00 00) ───────────
    # Table table
    bytes([0x00,0x00,0x00,0x01, 0x00,0x00,0x00,0x00]): "Table_Table (actual)",
    bytes([0x00,0x00,0x00,0x01, 0x00,0x00,0x00,0x01]): "Table_Table (descriptor)",
    # SPInfo
    bytes([0x00,0x00,0x00,0x02, 0x00,0x00,0x00,0x00]): "SPInfo_Table (actual)",
    bytes([0x00,0x00,0x00,0x02, 0x00,0x00,0x00,0x01]): "SPInfo_Table (descriptor)",
    # SPTemplates
    bytes([0x00,0x00,0x00,0x03, 0x00,0x00,0x00,0x00]): "SPTemplates_Table (actual)",
    bytes([0x00,0x00,0x00,0x03, 0x00,0x00,0x00,0x01]): "SPTemplates_Table (descriptor)",
    # Column
    bytes([0x00,0x00,0x00,0x04, 0x00,0x00,0x00,0x00]): "Column_Table (actual)",
    bytes([0x00,0x00,0x00,0x04, 0x00,0x00,0x00,0x01]): "Column_Table (descriptor)",
    # Type
    bytes([0x00,0x00,0x00,0x05, 0x00,0x00,0x00,0x00]): "Type_Table (actual)",
    bytes([0x00,0x00,0x00,0x05, 0x00,0x00,0x00,0x01]): "Type_Table (descriptor)",
    # MethodID
    bytes([0x00,0x00,0x00,0x06, 0x00,0x00,0x00,0x00]): "MethodID_Table (actual)",
    bytes([0x00,0x00,0x00,0x06, 0x00,0x00,0x00,0x01]): "MethodID_Table (descriptor)",
    # AccessControl
    bytes([0x00,0x00,0x00,0x07, 0x00,0x00,0x00,0x00]): "AccessControl_Table (actual)",
    bytes([0x00,0x00,0x00,0x07, 0x00,0x00,0x00,0x01]): "AccessControl_Table (descriptor)",
    # ACE
    bytes([0x00,0x00,0x00,0x08, 0x00,0x00,0x00,0x00]): "ACE_Table (actual)",
    bytes([0x00,0x00,0x00,0x08, 0x00,0x00,0x00,0x01]): "ACE_Table (descriptor)",
    # Authority
    bytes([0x00,0x00,0x00,0x09, 0x00,0x00,0x00,0x00]): "Authority_Table (actual)",
    bytes([0x00,0x00,0x00,0x09, 0x00,0x00,0x00,0x01]): "Authority_Table (descriptor)",
    # Certificates
    bytes([0x00,0x00,0x00,0x0A, 0x00,0x00,0x00,0x00]): "Certificates_Table (actual)",
    # C_PIN
    bytes([0x00,0x00,0x00,0x0B, 0x00,0x00,0x00,0x00]): "C_PIN_Table (actual)",
    bytes([0x00,0x00,0x00,0x0B, 0x00,0x00,0x00,0x01]): "C_PIN_Table (descriptor)",
    # C_RSA_1024
    bytes([0x00,0x00,0x00,0x0C, 0x00,0x00,0x00,0x00]): "C_RSA_1024_Table (actual)",
    # C_RSA_2048
    bytes([0x00,0x00,0x00,0x0D, 0x00,0x00,0x00,0x00]): "C_RSA_2048_Table (actual)",
    # C_AES_128
    bytes([0x00,0x00,0x00,0x0E, 0x00,0x00,0x00,0x00]): "C_AES_128_Table (actual)",
    # C_AES_256
    bytes([0x00,0x00,0x00,0x0F, 0x00,0x00,0x00,0x00]): "C_AES_256_Table (actual)",
    # C_EC_160
    bytes([0x00,0x00,0x00,0x10, 0x00,0x00,0x00,0x00]): "C_EC_160_Table (actual)",
    # C_EC_192
    bytes([0x00,0x00,0x00,0x11, 0x00,0x00,0x00,0x00]): "C_EC_192_Table (actual)",
    # C_EC_224
    bytes([0x00,0x00,0x00,0x12, 0x00,0x00,0x00,0x00]): "C_EC_224_Table (actual)",
    # C_EC_256
    bytes([0x00,0x00,0x00,0x13, 0x00,0x00,0x00,0x00]): "C_EC_256_Table (actual)",
    # C_EC_384
    bytes([0x00,0x00,0x00,0x14, 0x00,0x00,0x00,0x00]): "C_EC_384_Table (actual)",
    # C_EC_521
    bytes([0x00,0x00,0x00,0x15, 0x00,0x00,0x00,0x00]): "C_EC_521_Table (actual)",
    # C_HMAC_160
    bytes([0x00,0x00,0x00,0x16, 0x00,0x00,0x00,0x00]): "C_HMAC_160_Table (actual)",
    # C_HMAC_256
    bytes([0x00,0x00,0x00,0x17, 0x00,0x00,0x00,0x00]): "C_HMAC_256_Table (actual)",
    # SecretProtect
    bytes([0x00,0x00,0x00,0x1C, 0x00,0x00,0x00,0x00]): "SecretProtect_Table (actual)",

    # ── Table 244: Single Row Tables ─────────────────────────────────────────
    bytes([0x00,0x00,0x02,0x01, 0x00,0x00,0x00,0x00]): "TPerInfo_Table (actual)",
    bytes([0x00,0x00,0x02,0x01, 0x00,0x00,0x00,0x01]): "TPerInfo_Table (descriptor/default row)",
    bytes([0x00,0x00,0x04,0x01, 0x00,0x00,0x00,0x00]): "LockingInfo_Table (actual)",
    bytes([0x00,0x00,0x04,0x01, 0x00,0x00,0x00,0x01]): "LockingInfo (default row)",

    # ── Opal/Locking SP: SP UIDs ─────────────────────────────────────────────
    bytes([0x00,0x00,0x02,0x05, 0x00,0x00,0x00,0x01]): "Admin_SP",
    bytes([0x00,0x00,0x02,0x05, 0x00,0x00,0x00,0x02]): "Locking_SP",

    # ── Opal: Locking Table + Ranges ─────────────────────────────────────────
    bytes([0x00,0x00,0x08,0x02, 0x00,0x00,0x00,0x00]): "Locking_Table (actual)",
    bytes([0x00,0x00,0x08,0x02, 0x00,0x00,0x00,0x01]): "Locking_Table (descriptor)",
    bytes([0x00,0x00,0x08,0x02, 0x00,0x03,0x00,0x00]): "GlobalRange",
    bytes([0x00,0x00,0x08,0x02, 0x00,0x03,0x00,0x01]): "Range1",
    bytes([0x00,0x00,0x08,0x02, 0x00,0x03,0x00,0x02]): "Range2",
    bytes([0x00,0x00,0x08,0x02, 0x00,0x03,0x00,0x03]): "Range3",
    bytes([0x00,0x00,0x08,0x02, 0x00,0x03,0x00,0x04]): "Range4",
    bytes([0x00,0x00,0x08,0x02, 0x00,0x03,0x00,0x05]): "Range5",
    bytes([0x00,0x00,0x08,0x02, 0x00,0x03,0x00,0x06]): "Range6",
    bytes([0x00,0x00,0x08,0x02, 0x00,0x03,0x00,0x07]): "Range7",
    bytes([0x00,0x00,0x08,0x02, 0x00,0x03,0x00,0x08]): "Range8",

    # ── Opal: MBR Table ──────────────────────────────────────────────────────
    bytes([0x00,0x00,0x08,0x03, 0x00,0x00,0x00,0x00]): "MBR_Table (actual)",
    bytes([0x00,0x00,0x08,0x03, 0x00,0x00,0x00,0x01]): "MBR_Table (descriptor)",

    # ── Opal: MBRControl ────────────────────────────────────────────────────
    bytes([0x00,0x00,0x08,0x03, 0x00,0x00,0x00,0x00]): "MBRControl_Table (actual)",
    bytes([0x00,0x00,0x08,0x03, 0x00,0x00,0x00,0x01]): "MBRControl (default row)",

    # ── Opal: DataStore Table ────────────────────────────────────────────────
    bytes([0x00,0x00,0x10,0x01, 0x00,0x00,0x00,0x00]): "DataStore_Table (actual)",
    bytes([0x00,0x00,0x10,0x01, 0x00,0x00,0x00,0x01]): "DataStore_Table (descriptor)",

    # ── Authority UIDs (Table 243 / Admin SP default) ────────────────────────
    bytes([0x00,0x00,0x00,0x09, 0x00,0x00,0x00,0x01]): "Anybody",
    bytes([0x00,0x00,0x00,0x09, 0x00,0x00,0x00,0x02]): "Admins (class)",
    bytes([0x00,0x00,0x00,0x09, 0x00,0x00,0x00,0x03]): "Makers (class)",
    bytes([0x00,0x00,0x00,0x09, 0x00,0x00,0x00,0x04]): "MakerSymK",
    bytes([0x00,0x00,0x00,0x09, 0x00,0x00,0x00,0x05]): "MakerPuK",
    bytes([0x00,0x00,0x00,0x09, 0x00,0x00,0x00,0x06]): "SID",
    bytes([0x00,0x00,0x00,0x09, 0x00,0x00,0x00,0x07]): "TPerSign",
    bytes([0x00,0x00,0x00,0x09, 0x00,0x00,0x00,0x08]): "TPerExch",
    bytes([0x00,0x00,0x00,0x09, 0x00,0x00,0x00,0x09]): "AdminExch",

    # Opal Locking SP Authorities
    bytes([0x00,0x00,0x00,0x09, 0x00,0x01,0x00,0x01]): "Admin1",
    bytes([0x00,0x00,0x00,0x09, 0x00,0x01,0x00,0x02]): "Admin2",
    bytes([0x00,0x00,0x00,0x09, 0x00,0x01,0x00,0x03]): "Admin3",
    bytes([0x00,0x00,0x00,0x09, 0x00,0x01,0x00,0x04]): "Admin4",
    bytes([0x00,0x00,0x00,0x09, 0x00,0x03,0x00,0x01]): "User1",
    bytes([0x00,0x00,0x00,0x09, 0x00,0x03,0x00,0x02]): "User2",
    bytes([0x00,0x00,0x00,0x09, 0x00,0x03,0x00,0x03]): "User3",
    bytes([0x00,0x00,0x00,0x09, 0x00,0x03,0x00,0x04]): "User4",
    bytes([0x00,0x00,0x00,0x09, 0x00,0x03,0x00,0x05]): "User5",
    bytes([0x00,0x00,0x00,0x09, 0x00,0x03,0x00,0x06]): "User6",
    bytes([0x00,0x00,0x00,0x09, 0x00,0x03,0x00,0x07]): "User7",
    bytes([0x00,0x00,0x00,0x09, 0x00,0x03,0x00,0x08]): "User8",
    bytes([0x00,0x00,0x00,0x09, 0x00,0x04,0xFF,0x01]): "PSID",

    # ── C_PIN UIDs ───────────────────────────────────────────────────────────
    bytes([0x00,0x00,0x00,0x0B, 0x00,0x00,0x00,0x01]): "C_PIN_Table (descriptor)",
    bytes([0x00,0x00,0x00,0x0B, 0x00,0x00,0x84,0x01]): "C_PIN_SID",
    bytes([0x00,0x00,0x00,0x0B, 0x00,0x00,0x84,0x02]): "C_PIN_MSID",
    bytes([0x00,0x00,0x00,0x0B, 0x00,0x01,0x00,0x01]): "C_PIN_Admin1",
    bytes([0x00,0x00,0x00,0x0B, 0x00,0x01,0x00,0x02]): "C_PIN_Admin2",
    bytes([0x00,0x00,0x00,0x0B, 0x00,0x01,0x00,0x03]): "C_PIN_Admin3",
    bytes([0x00,0x00,0x00,0x0B, 0x00,0x01,0x00,0x04]): "C_PIN_Admin4",
    bytes([0x00,0x00,0x00,0x0B, 0x00,0x03,0x00,0x01]): "C_PIN_User1",
    bytes([0x00,0x00,0x00,0x0B, 0x00,0x03,0x00,0x02]): "C_PIN_User2",
    bytes([0x00,0x00,0x00,0x0B, 0x00,0x03,0x00,0x03]): "C_PIN_User3",
    bytes([0x00,0x00,0x00,0x0B, 0x00,0x03,0x00,0x04]): "C_PIN_User4",
    bytes([0x00,0x00,0x00,0x0B, 0x00,0x03,0x00,0x05]): "C_PIN_User5",
    bytes([0x00,0x00,0x00,0x0B, 0x00,0x03,0x00,0x06]): "C_PIN_User6",
    bytes([0x00,0x00,0x00,0x0B, 0x00,0x03,0x00,0x07]): "C_PIN_User7",
    bytes([0x00,0x00,0x00,0x0B, 0x00,0x03,0x00,0x08]): "C_PIN_User8",

    # ── ACE UIDs ─────────────────────────────────────────────────────────────
    bytes([0x00,0x00,0x00,0x08, 0x00,0x03,0xE0,0x00]): "ACE_Locking_GlobalRange_Set_RdLocked",
    bytes([0x00,0x00,0x00,0x08, 0x00,0x03,0xE0,0x01]): "ACE_Locking_GlobalRange_Set_WrLocked",
    bytes([0x00,0x00,0x00,0x08, 0x00,0x03,0xE8,0x00]): "ACE_Locking_Range1_Set_RdLocked",
    bytes([0x00,0x00,0x00,0x08, 0x00,0x03,0xE8,0x01]): "ACE_Locking_Range1_Set_WrLocked",
    bytes([0x00,0x00,0x00,0x08, 0x00,0x03,0xF0,0x00]): "ACE_Locking_Range2_Set_RdLocked",
    bytes([0x00,0x00,0x00,0x08, 0x00,0x03,0xF0,0x01]): "ACE_Locking_Range2_Set_WrLocked",
}

# ── Status code mapping ──────────────────────────────────────────────────────
STATUS_CODES = {
    0x00: "SUCCESS",
    0x01: "NOT_AUTHORIZED",
    0x02: "OBSOLETE",
    0x03: "SP_BUSY",
    0x04: "SP_FAILED",
    0x05: "SP_DISABLED",
    0x06: "SP_FROZEN",
    0x07: "NO_SESSIONS_AVAILABLE",
    0x08: "UNIQUENESS_CONFLICT",
    0x09: "INSUFFICIENT_SPACE",
    0x0A: "INSUFFICIENT_ROWS",
    0x0C: "INVALID_PARAMETER",
    0x0D: "OBSOLETE",
    0x0E: "OBSOLETE",
    0x0F: "TPER_MALFUNCTION",
    0x10: "TRANSACTION_FAILURE",
    0x11: "RESPONSE_OVERFLOW",
    0x12: "AUTHORITY_LOCKED_OUT",
    0x3F: "FAIL",
}


def _uid_name(data: bytes) -> str:
    return UID_NAMES.get(data, "")


def _status_name(code: int) -> str:
    return STATUS_CODES.get(code, f"UNKNOWN(0x{code:02X})")


# ============================================================================
# Token Stream Parser
# ============================================================================

# Token byte constants
TOK_CALL        = 0xF8
TOK_END_OF_DATA = 0xF9
TOK_END_OF_SESSION = 0xFA
TOK_START_TRANSACTION = 0xFB
TOK_END_TRANSACTION   = 0xFC
TOK_START_LIST  = 0xF0
TOK_END_LIST    = 0xF1
TOK_START_NAME  = 0xF2
TOK_END_NAME    = 0xF3
TOK_EMPTY_ATOM  = 0xFF


class _ParserState:
    """Parser 내부 상태"""

    def __init__(self, data: bytes):
        self.data   = data
        self.pos    = 0
        self.depth  = 0          # List / Name 중첩 depth
        self.lines  = []         # 출력 라인 (offset, hex_str, indent, remark)

        # F8 이후 상태
        self._after_call        = False   # 다음 8바이트 → InvokingUID
        self._after_invoking    = False   # 다음 8바이트 → MethodUID

        # EndOfData 직후 status list 감지
        self._eod_seen          = False
        self._status_list_depth = None    # status list 시작 depth

    # ── helpers ────────────────────────────────────────────────────────────
    def _indent(self) -> str:
        return "  " * self.depth

    def _peek(self, n: int = 1) -> bytes:
        return self.data[self.pos: self.pos + n]

    def _read(self, n: int) -> bytes:
        chunk = self.data[self.pos: self.pos + n]
        self.pos += n
        return chunk

    def _emit(self, offset: int, raw: bytes, remark: str):
        hex_str = " ".join(f"{b:02X}" for b in raw)
        indent  = self._indent()
        self.lines.append((offset, hex_str, indent, remark))

    # ── Atom parsing ───────────────────────────────────────────────────────
    def _parse_atom(self):
        """
        Atom 하나를 파싱하고 emit.
        리턴: (atom_bytes, int_value_or_None, bytes_value)
        """
        offset = self.pos
        first  = self.data[self.pos]

        # ── Tiny Atom: 0b0xxxxxxx (0x00 ~ 0x7F)
        if (first & 0x80) == 0x00:
            raw = self._read(1)
            signed_bit = (first & 0x40) != 0
            val = first & 0x3F
            if signed_bit and (val & 0x20):
                val -= 0x40
            remark = f"Tiny Atom  int={val}"
            self._emit(offset, raw, remark)
            return raw, val, None

        # ── Short Atom: 0b10xxxxxx (0x80 ~ 0xBF)
        if (first & 0xC0) == 0x80:
            byte_flag   = (first & 0x20) != 0  # B-bit
            sign_flag   = (first & 0x10) != 0  # S-bit (continued)
            length      = first & 0x0F
            header      = self._read(1)
            data_bytes  = self._read(length)
            raw = header + data_bytes

            if byte_flag:
                val_str = data_bytes.hex().upper()
                remark = f"Short Atom  bytes len={length}  val={val_str}"
                # UID 인식 (8바이트)
                if length == 8:
                    name = _uid_name(data_bytes)
                    if name:
                        remark += f"  [{name}]"
                self._emit(offset, raw, remark)
                return raw, None, data_bytes
            else:
                val = int.from_bytes(data_bytes, "big")
                remark = f"Short Atom  int len={length}  val={val}"
                self._emit(offset, raw, remark)
                return raw, val, None

        # ── Medium Atom: 0b110xxxxx (0xC0 ~ 0xDF)
        if (first & 0xE0) == 0xC0:
            byte_flag  = (first & 0x10) != 0
            sign_flag  = (first & 0x08) != 0
            len_hi     = first & 0x07
            second     = self.data[self.pos + 1]
            length     = (len_hi << 8) | second
            header     = self._read(2)
            data_bytes = self._read(length)
            raw = header + data_bytes

            if byte_flag:
                val_str = data_bytes[:16].hex().upper() + ("..." if length > 16 else "")
                remark = f"Medium Atom  bytes len={length}  val={val_str}"
                if length == 8:
                    name = _uid_name(data_bytes)
                    if name:
                        remark += f"  [{name}]"
            else:
                val = int.from_bytes(data_bytes, "big")
                remark = f"Medium Atom  int len={length}  val={val}"
            self._emit(offset, raw, remark)
            return raw, None, data_bytes if byte_flag else None

        # ── Long Atom: 0b111000xx (0xE0 ~ 0xE3)
        if (first & 0xFC) == 0xE0:
            byte_flag  = (first & 0x02) != 0
            sign_flag  = (first & 0x01) != 0
            b1 = self.data[self.pos + 1]
            b2 = self.data[self.pos + 2]
            b3 = self.data[self.pos + 3]
            length = (b1 << 16) | (b2 << 8) | b3
            header = self._read(4)
            data_bytes = self._read(length)
            raw = header + data_bytes

            if byte_flag:
                val_str = data_bytes[:16].hex().upper() + ("..." if length > 16 else "")
                remark = f"Long Atom  bytes len={length}  val={val_str}"
            else:
                val = int.from_bytes(data_bytes, "big")
                remark = f"Long Atom  int len={length}  val={val}"
            self._emit(offset, raw, remark)
            return raw, None, data_bytes if byte_flag else None

        # ── Continued Token 처리 (S=1 segments) — 비정상이지만 대비
        raw = self._read(1)
        self._emit(offset, raw, f"Unknown byte 0x{first:02X}")
        return raw, None, None

    # ── Main parse loop ────────────────────────────────────────────────────
    def parse(self):
        while self.pos < len(self.data):
            b      = self.data[self.pos]
            offset = self.pos

            # ── Special Tokens ────────────────────────────────────────────
            if b == TOK_EMPTY_ATOM:
                raw = self._read(1)
                self._emit(offset, raw, "Empty Atom (padding)")
                continue

            if b == TOK_CALL:
                raw = self._read(1)
                self._emit(offset, raw, "Call Token")
                self._after_call     = True
                self._after_invoking = False
                continue

            if b == TOK_END_OF_DATA:
                raw = self._read(1)
                self._emit(offset, raw, "EndOfData Token")
                self._eod_seen = True
                continue

            if b == TOK_END_OF_SESSION:
                raw = self._read(1)
                self._emit(offset, raw, "EndOfSession Token")
                continue

            if b == TOK_START_TRANSACTION:
                raw = self._read(1)
                self._emit(offset, raw, "StartTransaction Token")
                continue

            if b == TOK_END_TRANSACTION:
                raw = self._read(1)
                # peek next byte: status code
                status_byte = self.data[self.pos] if self.pos < len(self.data) else None
                if status_byte is not None and status_byte <= 0x7F:
                    status_name = _status_name(status_byte)
                    self._emit(offset, raw, f"EndTransaction Token  → status next byte: {status_name}")
                else:
                    self._emit(offset, raw, "EndTransaction Token")
                continue

            if b == TOK_START_LIST:
                raw = self._read(1)
                if self._eod_seen and self._status_list_depth is None:
                    self._status_list_depth = self.depth
                    remark = "StartList  ← status list begin"
                else:
                    remark = f"StartList  (depth→{self.depth + 1})"
                self._emit(offset, raw, remark)
                self.depth += 1
                continue

            if b == TOK_END_LIST:
                self.depth -= 1
                raw = self._read(1)
                if self._status_list_depth is not None and self.depth == self._status_list_depth:
                    self._emit(offset, raw, "EndList  ← status list end")
                    self._status_list_depth = None
                else:
                    self._emit(offset, raw, f"EndList  (depth→{self.depth})")
                continue

            if b == TOK_START_NAME:
                raw = self._read(1)
                self._emit(offset, raw, f"StartName  (depth→{self.depth + 1})")
                self.depth += 1
                continue

            if b == TOK_END_NAME:
                self.depth -= 1
                raw = self._read(1)
                self._emit(offset, raw, f"EndName  (depth→{self.depth})")
                continue

            # ── Atom ─────────────────────────────────────────────────────
            # F8 직후 InvokingUID / MethodUID 처리
            if self._after_call:
                # InvokingUID: Short Atom bytes, len=8 (A8 + 8 bytes) 가 오는 게 정상
                atom_raw, _, atom_bytes = self._parse_atom()
                self._after_call     = False
                self._after_invoking = True
                # remark 마지막 줄 수정: InvokingUID 태그 추가
                off, hs, ind, rem = self.lines[-1]
                if atom_bytes and len(atom_bytes) == 8:
                    name = _uid_name(atom_bytes)
                    tag  = f"  [{name}]" if name else ""
                    self.lines[-1] = (off, hs, ind, f"InvokingUID{tag}")
                else:
                    self.lines[-1] = (off, hs, ind, f"InvokingUID  (unusual: {rem})")
                continue

            if self._after_invoking:
                atom_raw, _, atom_bytes = self._parse_atom()
                self._after_invoking = False
                off, hs, ind, rem = self.lines[-1]
                if atom_bytes and len(atom_bytes) == 8:
                    name = _uid_name(atom_bytes)
                    tag  = f"  [{name}]" if name else ""
                    self.lines[-1] = (off, hs, ind, f"MethodUID{tag}")
                else:
                    self.lines[-1] = (off, hs, ind, f"MethodUID  (unusual: {rem})")
                continue

            # status list 안 Tiny Atom 3개 → status code 해석
            if (self._status_list_depth is not None
                    and self.depth == self._status_list_depth + 1
                    and (b & 0x80) == 0x00):
                atom_raw, val, _ = self._parse_atom()
                if val is not None:
                    off, hs, ind, rem = self.lines[-1]
                    # 첫 번째 Tiny Atom이 status code
                    status_name = _status_name(val)
                    self.lines[-1] = (off, hs, ind, f"Tiny Atom  int={val}  [{status_name}]")
                continue

            # 일반 Atom
            self._parse_atom()


# ============================================================================
# Public API
# ============================================================================

def parse_payload(data: bytes, title: str = "TCG Payload Token Stream") -> None:
    """
    SubPacket payload bytes를 파싱하여 stdout에 출력.

    Args:
        data : SubPacket payload (token stream) bytes
        title: 출력 헤더 제목
    """
    state = _ParserState(data)
    state.parse()

    # ── 출력 포매팅 ──────────────────────────────────────────────────────
    print(f"\n{'=' * 72}")
    print(f"  {title}  ({len(data)} bytes)")
    print(f"{'=' * 72}")

    # 컬럼 너비 계산
    max_hex = max((len(hs) for _, hs, _, _ in state.lines), default=23)
    max_hex = max(max_hex, 23)

    for offset, hex_str, indent, remark in state.lines:
        # indent 포함 hex 출력 너비
        indented_hex = indent + hex_str
        print(f"[{offset:04X}]  {indented_hex:<{max_hex + 12}}  ← {remark}")

    print(f"{'=' * 72}\n")


# ============================================================================
# Self-test
# ============================================================================

if __name__ == "__main__":
    # StartSession 예제 payload
    sample = bytes([
        0xF8,                                                      # Call
        0xA8, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0xFF,           # InvokingUID (SMUID)
        0xA8, 0x00,0x00,0x00,0x00, 0x00,0x00,0xFF,0x02,           # MethodUID  (SM_StartSession)
        0xF0,                                                      # StartList
          0x01,                                                    # HostSessionID = 1
          0xA8, 0x00,0x00,0x02,0x05, 0x00,0x00,0x00,0x02,         # SPID = Locking_SP
          0x01,                                                    # Write = 1
          0xF2,                                                    # StartName
            0x00,                                                  # param[0] = HostChallenge
            0xD0, 0x20,                                            # Medium Atom bytes len=32
            *([0xAA]*32),
          0xF3,                                                    # EndName
          0xF2,                                                    # StartName
            0x03,                                                  # param[3] = HostSigningAuthority
            0xA8, 0x00,0x00,0x00,0x09, 0x00,0x01,0x00,0x01,       # Admin1
          0xF3,                                                    # EndName
        0xF1,                                                      # EndList
        0xF9,                                                      # EndOfData
        0xF0,                                                      # StartList (status)
          0x00,                                                    # status = SUCCESS
          0x00,
          0x00,
        0xF1,                                                      # EndList
    ])

    parse_payload(sample, "StartSession (self-test)")

    # Get 응답 예제
    get_response = bytes([
        0xF8,
        0xA8, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x01,           # InvokingUID = ThisSP
        0xA8, 0x00,0x00,0x00,0x06, 0x00,0x00,0x00,0x0F,           # MethodUID  = Get
        0xF0,
          0xF0,
            0xF2, 0x00, 0xA8,0x00,0x00,0x00,0x0B, 0x00,0x00,0x84,0x01, 0xF3,  # StartColumn=C_PIN_SID
            0xF2, 0x01, 0xA8,0x00,0x00,0x00,0x0B, 0x00,0x00,0x84,0x01, 0xF3,  # EndColumn
          0xF1,
        0xF1,
        0xF9,
        0xF0, 0x00, 0x00, 0x00, 0xF1,
    ])

    parse_payload(get_response, "Get (C_PIN_SID) self-test")
