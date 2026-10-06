import sys
from pathlib import Path

HW1 = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(HW1 / "duel-1-crypto"))

from duel1_targets import _xor, reused_pad_ciphertexts


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
