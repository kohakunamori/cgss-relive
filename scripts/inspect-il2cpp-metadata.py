#!/usr/bin/env python3
"""Inspect Unity IL2CPP global-metadata.dat using only the Python stdlib.

Currently implements the Unity/IL2CPP metadata v31 layout used by the final
CGSS Android 11.6.3 client. It emits structural facts and selected protocol
indicators; it does not dump proprietary code or all string literals.
"""
from __future__ import annotations

import argparse
import json
import re
import struct
from pathlib import Path

MAGIC = 0xFAB11BAF
HEADER_PAIRS = [
    "stringLiteral", "stringLiteralData", "string", "events", "properties", "methods",
    "parameterDefaultValues", "fieldDefaultValues", "fieldAndParameterDefaultValueData",
    "fieldMarshaledSizes", "parameters", "fields", "genericParameters",
    "genericParameterConstraints", "genericContainers", "nestedTypes", "interfaces",
    "vtableMethods", "interfaceOffsets", "typeDefinitions", "images", "assemblies",
    "fieldRefs", "referencedAssemblies", "attributeData", "attributeDataRange",
    "unresolvedVirtualCallParameterTypes", "unresolvedVirtualCallParameterRanges",
    "windowsRuntimeTypeNames", "windowsRuntimeStrings", "exportedTypeDefinitions",
]
TYPE_SIZE_V31 = 88
METHOD_SIZE_V31 = 36
IMAGE_SIZE_V31 = 40
FIELD_SIZE_V31 = 12

SELECTED_HEADERS = {
    "APP-VER", "RES-VER", "PARAM", "SID", "UDID", "USER-ID", "DEVICE", "DEVICE-ID",
    "DEVICE-NAME", "GRAPHICS-DEVICE-NAME", "IP-ADDRESS", "PLATFORM-OS-VERSION",
    "CARRIER", "KEYCHAIN", "PROCESSOR-TYPE", "RETRY-FLAG", "X-Unity-Version",
}
INTERESTING_TYPE_NAMES = {
    "Cute.NetworkManager", "Cute.NetworkTask", "Cute.DeviceManager", "Cute.AES256Crypt",
    "Cute.Certification", "Cute.CryptAES", "Cute.Cryptographer", "Cute.Header",
    "Cute.PostParams", "Cute.LoginResponse", "Cute.LoginTask", "Cute.VersionCheckTask",
    "Cute.BootNetwork", "Cute.CustomPreference", "Cute.NetworkSeed", "Cute.SocketIOManager",
    "Cute.AssetManager", "Cute.AssetHandle", "Stage.NetworkUtil", "LibNative.Network",
}
RESOURCE_LITERALS = {
    "all_dbmanifest", "master.mdb", "manifests", "resources/Generic/", "Generic/Blob", "Generic/Master",
}
HOST_RE = re.compile(r"(?i)^(?:https?://)?(?:[a-z0-9-]+\.)+(?:jp|net|com|ca)(?:/)?$")
ENDPOINT_RE = re.compile(r"^[a-z][a-z0-9_]*(?:/[a-z0-9_{}?=&.-]+)+/?$")
ENDPOINT_HINTS = (
    "load/", "home/", "profile/", "live/", "story/", "friend/", "room/", "gacha/", "mission", "event/",
)


def parse(path: Path) -> dict:
    data = path.read_bytes()
    if len(data) < 256:
        raise ValueError("metadata file is too small")

    values = struct.unpack_from("<64I", data, 0)
    sanity, version = values[:2]
    if sanity != MAGIC:
        raise ValueError(f"bad metadata magic: 0x{sanity:08x}")
    if version != 31:
        raise ValueError(f"unsupported metadata version {version}; this parser currently supports v31")

    header = {
        name: (values[2 + index * 2], values[3 + index * 2])
        for index, name in enumerate(HEADER_PAIRS)
    }

    string_offset, string_size = header["string"]
    string_heap = data[string_offset:string_offset + string_size]

    def get_string(index: int) -> str:
        if index < 0 or index >= len(string_heap):
            return f"<bad-string-index:{index}>"
        end = string_heap.find(b"\0", index)
        if end < 0:
            end = len(string_heap)
        return string_heap[index:end].decode("utf-8", "replace")

    literal_offset, literal_size = header["stringLiteral"]
    literal_data_offset, literal_data_size = header["stringLiteralData"]
    literals: list[str] = []
    for index in range(literal_size // 8):
        length, data_index = struct.unpack_from("<II", data, literal_offset + index * 8)
        if data_index + length > literal_data_size:
            continue
        raw = data[literal_data_offset + data_index:literal_data_offset + data_index + length]
        literals.append(raw.decode("utf-8", "replace"))

    methods_offset, methods_size = header["methods"]
    if methods_size % METHOD_SIZE_V31:
        raise ValueError("unexpected v31 method table size")
    methods = []
    for index in range(methods_size // METHOD_SIZE_V31):
        offset = methods_offset + index * METHOD_SIZE_V31
        name_index, declaring_type, _return_type, _return_parameter_token, _parameter_start, _generic, token = struct.unpack_from(
            "<IiiiiiI", data, offset
        )
        parameter_count = struct.unpack_from("<HHHH", data, offset + 28)[3]
        methods.append(
            {
                "name": get_string(name_index),
                "declaring_type": declaring_type,
                "token": token,
                "parameter_count": parameter_count,
            }
        )

    types_offset, types_size = header["typeDefinitions"]
    if types_size % TYPE_SIZE_V31:
        raise ValueError("unexpected v31 type table size")
    types = []
    for index in range(types_size // TYPE_SIZE_V31):
        offset = types_offset + index * TYPE_SIZE_V31
        name_index, namespace_index, *_ = struct.unpack_from("<IIiiiiiI", data, offset)
        starts = struct.unpack_from("<iiiiiiii", data, offset + 32)
        counts = struct.unpack_from("<HHHHHHHH", data, offset + 64)
        full_name = (get_string(namespace_index) + "." + get_string(name_index)).strip(".")
        types.append(
            {
                "index": index,
                "name": full_name,
                "field_start": starts[0],
                "method_start": starts[1],
                "method_count": counts[0],
                "field_count": counts[2],
            }
        )

    fields_offset, fields_size = header["fields"]
    if fields_size % FIELD_SIZE_V31:
        raise ValueError("unexpected v31 field table size")
    fields = []
    for index in range(fields_size // FIELD_SIZE_V31):
        name_index, type_index, token = struct.unpack_from("<IiI", data, fields_offset + index * FIELD_SIZE_V31)
        fields.append({"name": get_string(name_index), "type_index": type_index, "token": token})

    images_offset, images_size = header["images"]
    if images_size % IMAGE_SIZE_V31:
        raise ValueError("unexpected v31 image table size")
    images = []
    for index in range(images_size // IMAGE_SIZE_V31):
        offset = images_offset + index * IMAGE_SIZE_V31
        name_index, _assembly_index, type_start, type_count = struct.unpack_from("<IiiI", data, offset)
        images.append({"name": get_string(name_index), "type_start": type_start, "type_count": type_count})

    selected_types = []
    for type_info in types:
        if type_info["name"] not in INTERESTING_TYPE_NAMES:
            continue
        method_start, method_count = type_info["method_start"], type_info["method_count"]
        field_start, field_count = type_info["field_start"], type_info["field_count"]
        selected_types.append(
            {
                "name": type_info["name"],
                "fields": [fields[i]["name"] for i in range(field_start, field_start + field_count)]
                if field_start >= 0 else [],
                "methods": [methods[i]["name"] for i in range(method_start, method_start + method_count)]
                if method_start >= 0 else [],
            }
        )

    hosts = sorted(
        {
            literal.rstrip("/")
            for literal in literals
            if HOST_RE.match(literal) and ("starlight" in literal.lower() or "akamaized" in literal.lower())
        }
    )
    headers = sorted(SELECTED_HEADERS.intersection(literals))
    resources = sorted(RESOURCE_LITERALS.intersection(literals))
    endpoints = sorted(
        {
            literal
            for literal in literals
            if len(literal) <= 120
            and ENDPOINT_RE.match(literal)
            and any(literal.startswith(prefix) for prefix in ENDPOINT_HINTS)
        }
    )
    resource_versions = sorted({literal for literal in literals if re.fullmatch(r"10\d{6}", literal)})

    return {
        "metadata_version": version,
        "counts": {
            "string_literals": len(literals),
            "types": len(types),
            "methods": len(methods),
            "images": len(images),
        },
        "images": images,
        "protocol_indicators": {
            "hosts": hosts,
            "headers": headers,
            "messagepack_present": any(type_info["name"].startswith("MessagePack.") for type_info in types),
            "aes_types_present": any(
                type_info["name"] in {"Cute.CryptAES", "Cute.AES256Crypt", "Cute.Cryptographer"}
                for type_info in types
            ),
            "selected_endpoints": endpoints,
        },
        "resource_indicators": {
            "version_like_literals": resource_versions,
            "literals": resources,
        },
        "selected_types": selected_types,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("metadata", type=Path)
    parser.add_argument("-o", "--output", type=Path)
    args = parser.parse_args()

    result = parse(args.metadata)
    text = json.dumps(result, ensure_ascii=False, indent=2)
    if args.output:
        args.output.write_text(text + "\n", encoding="utf-8")
    else:
        print(text)


if __name__ == "__main__":
    main()
