"""Read-only native Windows process provider."""

from __future__ import annotations

import ctypes
import sys
from datetime import datetime, timezone
from typing import Any


class _ProcessEntry32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", ctypes.c_ulong),
        ("cntUsage", ctypes.c_ulong),
        ("th32ProcessID", ctypes.c_ulong),
        ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
        ("th32ModuleID", ctypes.c_ulong),
        ("cntThreads", ctypes.c_ulong),
        ("th32ParentProcessID", ctypes.c_ulong),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", ctypes.c_ulong),
        ("szExeFile", ctypes.c_wchar * 260),
    ]


class _SidAndAttributes(ctypes.Structure):
    _fields_ = [
        ("Sid", ctypes.c_void_p),
        ("Attributes", ctypes.c_ulong),
    ]


class _TokenUser(ctypes.Structure):
    _fields_ = [("User", _SidAndAttributes)]


class SystemWindowsProcessProvider:
    """Enumerate process facts through read-only Windows APIs."""

    def __init__(self) -> None:
        if sys.platform != "win32":
            raise OSError("Windows process provider requires Windows.")
        self._kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self._advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
        self._advapi32.ConvertSidToStringSidW.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_wchar_p),
        ]
        self._advapi32.ConvertSidToStringSidW.restype = ctypes.c_bool

    def collect_processes(self) -> list[dict[str, Any]]:
        snapshot = self._kernel32.CreateToolhelp32Snapshot(0x00000002, 0)
        invalid_handle = ctypes.c_void_p(-1).value
        if snapshot == invalid_handle:
            raise OSError(ctypes.get_last_error(), "Unable to enumerate Windows processes.")

        try:
            entry = _ProcessEntry32W()
            entry.dwSize = ctypes.sizeof(entry)
            records: list[dict[str, Any]] = []
            if not self._kernel32.Process32FirstW(snapshot, ctypes.byref(entry)):
                return records
            while True:
                records.append(self._record_for_entry(entry))
                if not self._kernel32.Process32NextW(snapshot, ctypes.byref(entry)):
                    break
            return records
        finally:
            self._kernel32.CloseHandle(snapshot)

    def _record_for_entry(self, entry: _ProcessEntry32W) -> dict[str, Any]:
        process_id = int(entry.th32ProcessID)
        record: dict[str, Any] = {
            "process_id": process_id,
            "process_name": entry.szExeFile,
            "parent_process_id": int(entry.th32ParentProcessID) or None,
            "observed_at": datetime.now(timezone.utc),
        }
        handle = self._kernel32.OpenProcess(0x1000, False, process_id)
        if not handle:
            record["collection_status"] = "PERMISSION_DENIED"
            return record
        try:
            record["executable_path"] = self._executable_path(handle)
            record["user_identity"] = self._user_identity(handle)
        except PermissionError:
            record["collection_status"] = "PERMISSION_DENIED"
        except LookupError:
            record["collection_status"] = "UNVERIFIABLE"
        finally:
            self._kernel32.CloseHandle(handle)
        return record

    def _executable_path(self, handle) -> str:
        buffer = ctypes.create_unicode_buffer(32768)
        size = ctypes.c_ulong(len(buffer))
        if not self._kernel32.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)):
            raise PermissionError("Executable path could not be read.")
        return buffer.value

    def _user_identity(self, handle) -> str:
        token = ctypes.c_void_p()
        if not self._advapi32.OpenProcessToken(handle, 0x0008, ctypes.byref(token)):
            raise PermissionError("Process user identity could not be read.")
        try:
            required = ctypes.c_ulong()
            self._advapi32.GetTokenInformation(token, 1, None, 0, ctypes.byref(required))
            buffer = ctypes.create_string_buffer(required.value)
            if not self._advapi32.GetTokenInformation(
                token, 1, buffer, required, ctypes.byref(required)
            ):
                raise LookupError("Process token user could not be read.")
            token_user = ctypes.cast(buffer, ctypes.POINTER(_TokenUser)).contents
            sid_string = ctypes.c_wchar_p()
            if not self._advapi32.ConvertSidToStringSidW(
                token_user.User.Sid, ctypes.byref(sid_string)
            ):
                raise LookupError("Process SID could not be converted.")
            try:
                return sid_string.value
            finally:
                self._kernel32.LocalFree(sid_string)
        finally:
            self._kernel32.CloseHandle(token)
