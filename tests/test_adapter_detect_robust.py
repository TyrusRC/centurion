import subprocess

from centurion.adapters.android.adb import AdbAdapter


class _HangRunner:
    def __init__(self, which_result):
        self._which = which_result

    def run(self, args, *, timeout=None):
        raise subprocess.TimeoutExpired(args, timeout or 10)

    def which(self, binary):
        return self._which


class _PermRunner(_HangRunner):
    def run(self, args, *, timeout=None):
        raise PermissionError("not executable")


def test_detect_survives_version_timeout():
    assert AdbAdapter(_HangRunner("/usr/bin/adb")).detect().installed is True
    assert AdbAdapter(_HangRunner(None)).detect().installed is False


def test_detect_survives_permission_error():
    assert AdbAdapter(_PermRunner(None)).detect().installed is False
