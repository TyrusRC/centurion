from centurion.adapters.generic.mitmproxy import MitmproxyAdapter
from centurion.process import FakeRunner


def test_mitmproxy_detect():
    runner = FakeRunner()
    runner.register("mitmdump --version", stdout="Mitmproxy: 10.2.4\n", path="/usr/bin/mitmdump")
    status = MitmproxyAdapter(runner).detect()
    assert status.installed is True
    assert status.platform == "generic"
    assert status.category == "network"
    assert status.mastg_id is None


def test_mitmproxy_start_command_default():
    assert MitmproxyAdapter().start_command() == ["mitmdump", "-p", "8080"]


def test_mitmproxy_start_command_with_flow_out():
    assert MitmproxyAdapter().start_command(port=9090, flow_out="/tmp/flows") == [
        "mitmdump", "-p", "9090", "-w", "/tmp/flows",
    ]


def test_mitmproxy_read_command():
    assert MitmproxyAdapter().read_command("/tmp/flows") == [
        "mitmdump", "-nr", "/tmp/flows", "--flow-detail", "1",
    ]


def test_parse_flows_extracts_method_and_url():
    from centurion.adapters.generic.mitmproxy import MitmproxyAdapter
    dump = (
        "GET https://api.acme.com/login\n"
        "    << 200 OK 1.2k\n"
        "POST https://api.acme.com/pay\n"
        "    << 403 Forbidden 0b\n"
    )
    flows = MitmproxyAdapter().parse_flows(dump)
    assert flows == [
        {"method": "GET", "url": "https://api.acme.com/login"},
        {"method": "POST", "url": "https://api.acme.com/pay"},
    ]
