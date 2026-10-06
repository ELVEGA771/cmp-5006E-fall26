import sys
from pathlib import Path

HW1 = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(HW1 / "duel-1-crypto"))

from duel1_targets import _xor, ctr_log_entries


def crib_drag(ciphertext_xor: bytes, crib: str):
    crib_bytes = crib.encode("ascii")
    crib_len = len(crib_bytes)

    for offset in range(len(ciphertext_xor) - crib_len + 1):
        target_slice = ciphertext_xor[offset : offset + crib_len]
        revealed_fragment = _xor(target_slice, crib_bytes)
        printable_text = "".join(
            chr(b) if 32 <= b <= 126 else "." for b in revealed_fragment
        )

        print(f"Offset {offset:2d}: {printable_text}")


def recover_entry(c_known: bytes, c_target: bytes, known_plaintext: str) -> bytes:
    # Same nonce -> same keystream, so c_known ^ c_target == p_known ^ p_target.
    return _xor(_xor(c_known, c_target), known_plaintext.encode("ascii"))
