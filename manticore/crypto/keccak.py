try:
    from eth_hash.auto import keccak
except ImportError as e:
    raise RuntimeError("eth-hash is required for keccak support") from e


def keccak256(data: bytes) -> bytes:
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("keccak256 expects bytes")
    return keccak(data)
