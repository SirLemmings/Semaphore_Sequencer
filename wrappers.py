import params as pm
from typing import NamedTuple
class Basic:
    def __init__(self, value: bytes, length: int):
        if len(value) != length:
            raise Exception("Invalid bytes length", len(value))
        self.value = value
    def __bytes__(self) -> bytes:
        return self.value
    
    def __str__(self) -> str:
        return self.value.hex()
    
    def __eq__(self, other: 'Basic | bytes') -> bool:
        if isinstance(other, Basic):
            return self.value == other.value
        elif isinstance(other, bytes):
            return self.value == other
    
    def __hash__(self) -> int:
        return hash(self.value)
    
    def __len__(self) -> int:
        return len(self.value)
    
    def __lt__(self, other: 'Basic') -> bool:
        return self.value < other.value
    
    def __le__(self, other: 'Basic') -> bool:
        return self.value <= other.value
    
    def __gt__(self, other: 'Basic') -> bool:
        return self.value > other.value
    
    def __ge__(self, other: 'Basic') -> bool:
        return self.value >= other.value
    
    def hex(self) -> str:
        return self.value.hex()
    
    
class Alias(Basic):
    def __init__(self, value: bytes):
        super().__init__(value, pm.ALIAS_LENGTH)

class Pubkey(Basic):
    def __init__(self, value: bytes):
        super().__init__(value, pm.PUBKEY_LENGTH)

class Sig(Basic):
    def __init__(self, value: bytes):
        super().__init__(value, pm.SIG_LENGTH)

class Hash32(Basic):
    def __init__(self, value: bytes):
        super().__init__(value, 32)

class ChainCommit(Basic):
    def __init__(self, value: bytes):
        super().__init__(value, 33)
class Nym(Basic):
    def __init__(self, value: bytes):
        self.value = value
        if len(value) > pm.NYM_MAX_LENGTH:
            raise Exception("Invalid bytes length", len(value))

        def __str__(self) -> str:
            return bytes(self).decode("utf-8")
    
class Code(Basic):
    def __init__(self, value: bytes):
        super().__init__(value, 1)

class BCPointer(Basic):
    def __init__(self, value: bytes):
        super().__init__(value, pm.ALIAS_LENGTH+pm.DB_INT_LENGTH)
        self.epoch = Alias(value[:pm.DB_INT_LENGTH])
        self.alias = int.from_bytes(value[pm.DB_INT_LENGTH:], 'big')

class Index(Basic):
    def __init__(self, value: bytes | int):
        if isinstance(value, bytes):
            self.value = int.from_bytes(value, 'big')
        else:
            self.value = value
    
    def __int__(self) -> int:
        return self.value
    
    def __bytes__(self) -> bytes:
        return self.value.to_bytes(pm.DB_INT_LENGTH, 'big')
    
    def __str__(self) -> str:
        return str(self.value)

    def __add__(self, other: "int | Index") -> 'Index':
        if isinstance(other, int):
            return Index(self.value + other)
        elif isinstance(other, Index):
            return Index(self.value + other.value)

    def __sub__(self, other: int) -> 'Index':
        return Index(self.value - other)
    
    def __eq__(self, other: 'Index | int | bytes') -> bool:
        if isinstance(other, Index):
            return self.value == other.value
        elif isinstance(other, int):
            return self.value == other
        elif isinstance(other, bytes):
            return self.value == int.from_bytes(other, 'big')
        else:
            raise Exception("Invalid type for comparison", type(other))
        
    def __ne__(self, other: 'Index | int | bytes') -> bool:
        if isinstance(other, Index):
            return self.value != other.value
        elif isinstance(other, int):
            return self.value != other
        elif isinstance(other, bytes):
            return self.value != int.from_bytes(other, 'big')
        else:
            raise Exception("Invalid type for comparison", type(other))
    
    def __lt__(self, other: 'Index | int | bytes') -> bool:
        if isinstance(other, Index):
            return self.value < other.value
        elif isinstance(other, int):
            return self.value < other
        elif isinstance(other, bytes):
            return self.value < int.from_bytes(other, 'big')
        else:
            raise Exception("Invalid type for comparison", type(other))
        
    def __le__(self, other: 'Index | int | bytes') -> bool:
        if isinstance(other, Index):
            return self.value <= other.value
        elif isinstance(other, int):
            return self.value <= other
        elif isinstance(other, bytes):
            return self.value <= int.from_bytes(other, 'big')
        else:
            raise Exception("Invalid type for comparison", type(other))
        
    def __gt__(self, other: 'Index | int | bytes') -> bool:
        if isinstance(other, Index):
            return self.value > other.value
        elif isinstance(other, int):
            return self.value > other
        elif isinstance(other, bytes):
            return self.value > int.from_bytes(other, 'big')
        else:
            raise Exception("Invalid type for comparison", type(other))
        
    def __ge__(self, other: 'Index | int | bytes') -> bool:
        if isinstance(other, Index):
            return self.value >= other.value
        elif isinstance(other, int):
            return self.value >= other
        elif isinstance(other, bytes):
            return self.value >= int.from_bytes(other, 'big')
        else:
            raise Exception("Invalid type for comparison", type(other))
        
class Broadcast(NamedTuple):
    alias: Alias
    parent: BCPointer
    message: bytes
    chain_commit: ChainCommit
    signature: Sig

class StrippedBroadcast(NamedTuple):
    alias: Alias
    parent: BCPointer
    message: bytes