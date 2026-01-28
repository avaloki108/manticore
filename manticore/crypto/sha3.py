from eth_hash.auto import keccak


def keccak_256(data=b""):
    return keccak(data)
