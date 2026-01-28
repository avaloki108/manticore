from manticore.crypto.keccak import keccak256

def test_keccak_matches_known():
    assert keccak256(b"") == bytes.fromhex(
        "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    )
    assert keccak256(b"hello") == bytes.fromhex(
        "1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8"
    )

