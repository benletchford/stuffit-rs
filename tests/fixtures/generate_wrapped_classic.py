"""Regenerate wrapped_classic.sit.bin from the classic StuffIt fixture."""

from pathlib import Path


fixtures = Path(__file__).parent
archive = (fixtures / "test_m3_huffman.sit").read_bytes()
header = bytearray(128)
name = b"wrapped.sit"
header[1] = len(name)
header[2 : 2 + len(name)] = name
header[65:69] = b"SIT5"  # MacBinary file type
header[69:73] = b"SIT!"  # MacBinary creator
header[83:87] = len(archive).to_bytes(4, "big")

wrapped = header + archive + bytes((-len(archive)) % 128)
(fixtures / "wrapped_classic.sit.bin").write_bytes(wrapped)
