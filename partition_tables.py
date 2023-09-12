import struct
import uuid


def parse_mbr(mbr_bytes: bytes) -> list[dict]:
    """parses the mbr format data from a given
    byte array, iterates through each position and
    if a valid type is found return the type and
    position data"""
    partition_start = 446
    res = []
    number = 0
    for i in range(0, 4):
        partition_start = 446 + (16 * i)
        type = mbr_bytes[partition_start + 4]
        if type != 0:
            start = struct.unpack("<I", mbr_bytes[(partition_start + 8) : (partition_start + 12)])[0]
            end = struct.unpack("<I", mbr_bytes[(partition_start + 12) : (partition_start + 16)])[0]
            res.append(
                {
                    "number": number,
                    "start": start,
                    "end": (end + start) - 1,
                    "type": hex(type),
                }
            )
            number += 1
    return res


def parse_gpt(gpt_file, sector_size: int = 512) -> list[dict]:
    """parses the gpt format data from a given
    byte array, iterates through each position and
    if a valid uuid is found return the uuid and
    position data and name"""
    res = []
    gpt_file.seek(0)
    entry_size = 128
    number = 0
    num_entries = 10
    entry = gpt_file.read(sector_size)
    entry = gpt_file.read(entry_size)
    for i in range(0, num_entries):
        entry = gpt_file.read(entry_size)
        if len(entry) == entry_size:
            id = uuid.UUID(bytes_le=struct.unpack("16s", entry[0:16])[0])
            if (
                struct.unpack("<16s", entry[0:16])[0]
                != b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            ):
                start = struct.unpack("Q", entry[32:40])[0]
                end = struct.unpack("Q", entry[40:48])[0]
                name = struct.unpack("72s", entry[56:128])[0].decode("utf-16le")
                res.append(
                    {
                        "type": id,
                        "number": number,
                        "start": start,
                        "end": end,
                        "name": name.split("\x00")[0],
                    }
                )
                number += 1
    return res
