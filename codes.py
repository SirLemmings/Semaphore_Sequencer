from enum import Enum

# make an enum that maps colors to bytes
class op:
    MINT = b"\x00"
    UPDATE = b"\x01"
    BLUE = b"\x02"


class msg:
    QUERY_RESPONSE = b"\x00"
    REQUEST_ALIAS = b"\x01"
    REQUEST_ALIAS_UPDATE = b"\x02"
    REQUEST_NYM_UPDATE = b"\x03"
    REQUEST_BLOCK_I = b"\x04"
    REQUEST_CHAIN_SYNC_I = b"\x05"
    PUSH_BLOCK_I = b"\x06"
    REQUEST_BLOCK_S = b"\x07"
    REQUEST_CHAIN_SYNC_S = b"\x08"
    PUSH_BLOCK_S = b"\x09"
    REQUEST_BC = b"\x0A"
