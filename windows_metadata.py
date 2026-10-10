"""Read Windows file tags from the Shell property system."""
from __future__ import annotations

import ctypes
import os
from ctypes import wintypes

_VT_VECTOR_LPWSTR = 0x101F
_VT_LPWSTR = 0x001F
_GPS_DEFAULT = 0
_RPC_E_CHANGED_MODE = -2147417850
_IID_IPROPERTY_STORE = (
    0x886D8EEB,
    0x8CF2,
    0x4446,
    (0x8D, 0x02, 0xCD, 0xBA, 0x1D, 0xBD, 0xCF, 0x99),
)
_PKEY_SYSTEM_KEYWORDS = (
    0xF29F85E0,
    0x4FF9,
    0x1068,
    (0xAB, 0x91, 0x08, 0x00, 0x2B, 0x27, 0xB3, 0xD9),
    5,
)


class _GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", ctypes.c_ubyte * 8),
    ]


class _PROPERTYKEY(ctypes.Structure):
    _fields_ = [("fmtid", _GUID), ("pid", wintypes.DWORD)]


class _COUNTED_ARRAY(ctypes.Structure):
    _fields_ = [("count", wintypes.ULONG), ("values", ctypes.c_void_p)]


class _PROPVARIANT_UNION(ctypes.Union):
    _fields_ = [("pointer", ctypes.c_void_p), ("vector", _COUNTED_ARRAY)]


class _PROPVARIANT(ctypes.Structure):
    _anonymous_ = ("value",)
    _fields_ = [
        ("vt", wintypes.USHORT),
        ("reserved1", wintypes.USHORT),
        ("reserved2", wintypes.USHORT),
        ("reserved3", wintypes.USHORT),
        ("value", _PROPVARIANT_UNION),
    ]


def _guid(parts: tuple) -> _GUID:
    first, second, third, tail = parts[:4]
    return _GUID(first, second, third, (ctypes.c_ubyte * 8)(*tail))


def _split_tags(values: list[str]) -> list[str]:
    return [
        tag
        for value in values
        for tag in (part.strip() for part in value.split(";"))
        if tag
    ]


def _tags_from_variant(variant: _PROPVARIANT) -> list[str]:
    if variant.vt == _VT_VECTOR_LPWSTR and variant.vector.values:
        values = ctypes.cast(variant.vector.values, ctypes.POINTER(ctypes.c_void_p))
        raw_tags = [
            ctypes.wstring_at(values[index])
            for index in range(variant.vector.count)
            if values[index]
        ]
    elif variant.vt == _VT_LPWSTR and variant.pointer:
        raw_tags = [ctypes.wstring_at(variant.pointer)]
    else:
        return []
    return _split_tags(raw_tags)


def read_windows_metadata(path: str) -> dict[str, list[str]]:
    """Return available Windows Keywords tags; files without tags return {}."""
    if os.name != "nt":
        return {}

    shell32 = ctypes.WinDLL("shell32", use_last_error=True)
    ole32 = ctypes.WinDLL("ole32", use_last_error=True)
    get_store = shell32.SHGetPropertyStoreFromParsingName
    get_store.argtypes = [
        wintypes.LPCWSTR,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(_GUID),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    get_store.restype = ctypes.HRESULT

    co_initialize = ole32.CoInitializeEx
    co_initialize.argtypes = [ctypes.c_void_p, wintypes.DWORD]
    co_initialize.restype = ctypes.HRESULT
    co_uninitialize = ole32.CoUninitialize
    co_uninitialize.argtypes = []
    co_uninitialize.restype = None
    try:
        co_initialize(None, 2)
        initialized_here = True
    except OSError as exc:
        if exc.winerror != _RPC_E_CHANGED_MODE:
            raise
        initialized_here = False

    store = ctypes.c_void_p()
    iid = _guid(_IID_IPROPERTY_STORE)
    try:
        try:
            hr = get_store(path, None, _GPS_DEFAULT, ctypes.byref(iid), ctypes.byref(store))
        except OSError:
            return {}
        if hr < 0:
            return {}
        propvariant_clear = ole32.PropVariantClear
        propvariant_clear.argtypes = [ctypes.POINTER(_PROPVARIANT)]
        propvariant_clear.restype = ctypes.HRESULT

        try:
            key = _PROPERTYKEY(_guid(_PKEY_SYSTEM_KEYWORDS[:4]), _PKEY_SYSTEM_KEYWORDS[4])
            variant = _PROPVARIANT()
            get_value = ctypes.cast(
                ctypes.cast(store, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p)))[0][5],
                ctypes.WINFUNCTYPE(
                    ctypes.c_long,
                    ctypes.c_void_p,
                    ctypes.POINTER(_PROPERTYKEY),
                    ctypes.POINTER(_PROPVARIANT),
                ),
            )
            try:
                hr = get_value(store, ctypes.byref(key), ctypes.byref(variant))
            except OSError:
                return {}
            if hr < 0:
                return {}
            try:
                tags = _tags_from_variant(variant)
                return {"windows_tags": tags} if tags else {}
            finally:
                propvariant_clear(ctypes.byref(variant))
        finally:
            release = ctypes.cast(
                ctypes.cast(store, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p)))[0][2],
                ctypes.WINFUNCTYPE(ctypes.c_ulong, ctypes.c_void_p),
            )
            release(store)
    finally:
        if initialized_here:
            co_uninitialize()
