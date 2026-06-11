from centurion.adapters.generic.tcpdump import TcpdumpAdapter
from centurion.process import FakeRunner


def test_tcpdump_detect():
    runner = FakeRunner()
    runner.register("tcpdump --version", stdout="tcpdump version 4.99.4\n", path="/usr/sbin/tcpdump")
    status = TcpdumpAdapter(runner).detect()
    assert status.installed is True
    assert status.platform == "generic"
    assert status.category == "network"


def test_tcpdump_capture_command_default():
    assert TcpdumpAdapter().capture_command("/tmp/cap.pcap") == [
        "tcpdump", "-i", "any", "-w", "/tmp/cap.pcap",
    ]


def test_tcpdump_capture_command_with_iface_and_count():
    assert TcpdumpAdapter().capture_command("/tmp/cap.pcap", iface="wlan0", count=100) == [
        "tcpdump", "-i", "wlan0", "-w", "/tmp/cap.pcap", "-c", "100",
    ]
