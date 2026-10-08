from centurion.adapters.android.apksigner import ApksignerAdapter, SignatureInfo
from centurion.process import FakeRunner

SAMPLE = """\
Verified using v1 scheme (JAR signing): true
Verified using v2 scheme (APK Signature Scheme v2): true
Verified using v3 scheme (APK Signature Scheme v3): false
Verified using v4 scheme (APK Signature Scheme v4): false
"""


def test_apksigner_detect():
    runner = FakeRunner()
    runner.register("apksigner --version", stdout="0.9\n", path="/usr/bin/apksigner")
    status = ApksignerAdapter(runner).detect()
    assert status.installed is True
    assert status.platform == "android"
    assert status.category == "static"


def test_apksigner_verify_command():
    assert ApksignerAdapter().verify_command("/tmp/app.apk") == [
        "apksigner", "verify", "--print-certs", "-v", "/tmp/app.apk",
    ]


def test_apksigner_parse_verify():
    info = ApksignerAdapter().parse_verify(SAMPLE)
    assert info == SignatureInfo(v1=True, v2=True, v3=False)


def test_apksigner_verify_runs_and_parses():
    runner = FakeRunner()
    runner.register("apksigner verify", stdout=SAMPLE)
    info = ApksignerAdapter(runner).verify("/tmp/app.apk")
    assert info.to_dict() == {"v1": True, "v2": True, "v3": False}


def test_parse_verify_robust_to_trailing_text_and_missing_scheme():
    from centurion.adapters.android.apksigner import ApksignerAdapter
    out = ("Verified using v1 scheme (JAR signing): false\n"
           "Verified using v2 scheme (APK Signature Scheme v2): true\n"
           "Verified using v3 scheme (APK Signature Scheme v3): false\n"
           "Number of signers: 1\n")
    info = ApksignerAdapter().parse_verify(out)
    assert info.v1 is False and info.v2 is True and info.v3 is False
    # no scheme lines -> all False, no crash
    assert ApksignerAdapter().parse_verify("DOES NOT VERIFY\n").v2 is False
