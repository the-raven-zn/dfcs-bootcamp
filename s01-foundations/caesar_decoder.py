#!/usr/bin/env python3
"""Caesar cipher brute-forcer: prints all 25 possible decodings of a shifted string."""
import sys


def shift_text(text: str, shift: int) -> str:
    """Shift letters backwards by `shift`; keep case, leave non-letters untouched."""
    out = []
    for ch in text:
        if ch.isupper():
            out.append(chr((ord(ch) - 65 - shift) % 26 + 65))
        elif ch.islower():
            out.append(chr((ord(ch) - 97 - shift) % 26 + 97))
        else:
            out.append(ch)
    return "".join(out)


def main() -> None:
    if len(sys.argv) < 2:
        text = input("Enter the shifted text: ")
    else:
        text = " ".join(sys.argv[1:])
    print(f"Ciphertext: {text}\n")
    for shift in range(1, 26):  # shift 0 is the ciphertext itself
        print(f"Shift {shift:2d}: {shift_text(text, shift)}")


if __name__ == "__main__":
    main()
