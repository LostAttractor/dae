#!/usr/bin/env python3
"""Exercise same-PID daemon exec in private PID/network/mount namespaces.

Usage: sudo python3 scripts/test-process-replacement.py /absolute/path/to/dae [--wan]
--wan adds a private WAN veth and upstream namespace for daemon identity checks.
Uses only the standard library and local fixtures; never contacts the Internet.
"""
import base64
import http.client
import http.server
import json
import os
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from pathlib import Path


def tool(name):
    # NixOS /run symlinks disappear after mounting the fixture's private /run.
    path = os.environ["PATH"].replace("/run/wrappers/bin:", "")
    return os.path.realpath(shutil.which(name, path=path))


TOOLS = {name: tool(name) for name in ("mount", "ip", "unshare", "nft")}


def run(*args, **kwargs):
    return subprocess.run(args, check=True, text=True, **kwargs)


def wait_for(predicate, timeout=20):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.02)
    raise AssertionError("timed out waiting for fixture")


def children(parent):
    result = set()
    for task in Path(f"/proc/{parent}/task").glob("*/children"):
        try:
            result.update(int(child) for child in task.read_text().split())
        except (FileNotFoundError, ProcessLookupError):
            pass
    return result


def process_tree(parent):
    pending, seen = [parent], set()
    while pending:
        process = pending.pop()
        if process not in seen:
            seen.add(process)
            pending.extend(children(process))
    return seen


def process_tree_memory(parent):
    processes = []
    for process in sorted(process_tree(parent)):
        try:
            fields = dict(line.split(":", 1) for line in Path(f"/proc/{process}/smaps_rollup").read_text().splitlines() if ":" in line)
        except (FileNotFoundError, ProcessLookupError):
            continue
        pss = int(fields["Pss"].split()[0])
        private = sum(int(fields[name].split()[0]) for name in ("Private_Clean", "Private_Dirty"))
        processes.append({"pid": process, "pss_kb": pss, "private_kb": private})
    return {"pss_kb": sum(p["pss_kb"] for p in processes), "private_kb": sum(p["private_kb"] for p in processes), "processes": processes}


class MemorySampler:
    def __init__(self, parent):
        self.parent = parent
        self.stop = threading.Event()
        self.samples = []
        self.errors = []
        self.thread = threading.Thread(target=self.sample, daemon=True)
        self.thread.start()

    def sample(self):
        try:
            while not self.stop.is_set():
                self.samples.append(process_tree_memory(self.parent()))
                self.stop.wait(0.02)
        except BaseException as error:
            self.errors.append(error)

    def finish(self, stable):
        self.stop.set()
        self.thread.join()
        assert not self.errors, self.errors
        # Exec can briefly make smaps_rollup unreadable without changing the PID.
        self.samples = [sample for sample in self.samples if sample["processes"]]
        assert self.samples
        peak = {name: max(sample[name] for sample in self.samples) for name in ("pss_kb", "private_kb")}
        peak["process_count"] = max(len(sample["processes"]) for sample in self.samples)
        print("Process-tree memory (kB): " + json.dumps({"stable": stable, "replacement_suite_peak": peak, "sample_interval_ms": 20, "samples": len(self.samples)}, sort_keys=True))


def duration_seconds(value):
    units = {"ns": 1e-9, "us": 1e-6, "µs": 1e-6, "μs": 1e-6, "ms": 1e-3, "s": 1, "m": 60, "h": 3600}
    parts = re.findall(r"([0-9]+(?:\.[0-9]+)?)(ns|us|µs|μs|ms|s|m|h)", value)
    assert parts and "".join(number + unit for number, unit in parts) == value, value
    return sum(float(number) * units[unit] for number, unit in parts)


def log_message(line, message):
    return re.search(r'\bmsg="?' + re.escape(message) + r'"?(?= |$)', line) is not None


def phase_durations(log, message, field):
    durations = []
    for line in log.splitlines():
        if not log_message(line, message):
            continue
        match = re.search(r'\b' + re.escape(field) + r'=(?:"([^"]+)"|(\S+))', line)
        assert match, line
        durations.append(duration_seconds(match[1] or match[2]))
    return durations


def main(binary, wan=False):
    assert os.getpid() == 1, "fixture must run as init inside private PID/network/mount namespaces"
    run(TOOLS["mount"], "--make-rprivate", "/")
    cgroup = os.environ.pop("DAE_REPLACEMENT_TEST_CGROUP", None)
    if cgroup is not None:
        (Path(cgroup) / "cgroup.procs").write_text("0\n")
        run(TOOLS["mount"], "--bind", cgroup, "/sys/fs/cgroup")
    else:
        assert os.environ.get("DAE_TEST_ISOLATED") == "1", "a dedicated test cgroup is required"
    run(TOOLS["mount"], "-t", "tmpfs", "tmpfs", "/run")
    run(TOOLS["mount"], "-t", "bpf", "bpf", "/sys/fs/bpf")
    ip = TOOLS["ip"]
    run(ip, "link", "set", "lo", "up")
    # Keep IPv4/IPv6 conntrack enabled only in this disposable host namespace.
    run(TOOLS["nft"], "-f", "-", input="""table inet dae_fixture_ct {
        chain output {
            type filter hook output priority filter; policy accept;
            ct state new counter
        }
    }
    """)
    run(ip, "netns", "add", "fixture")
    run(ip, "link", "add", "lan0", "type", "veth", "peer", "name", "client0")
    run(ip, "link", "set", "client0", "netns", "fixture")
    run(ip, "addr", "add", "192.0.2.1/24", "dev", "lan0")
    run(ip, "link", "set", "lan0", "up")
    run(ip, "-n", "fixture", "addr", "add", "192.0.2.2/24", "dev", "client0")
    run(ip, "-n", "fixture", "link", "set", "client0", "up")
    run(ip, "-n", "fixture", "link", "set", "lo", "up")
    if wan:
        run(ip, "netns", "add", "upstream")
        run(ip, "link", "add", "wan0", "type", "veth", "peer", "name", "wanpeer")
        run(ip, "link", "set", "wanpeer", "netns", "upstream")
        run(ip, "addr", "add", "198.51.100.1/24", "dev", "wan0")
        run(ip, "link", "set", "wan0", "up")
        run(ip, "-n", "upstream", "addr", "add", "198.51.100.2/24", "dev", "wanpeer")
        run(ip, "-n", "upstream", "link", "set", "wanpeer", "up")
        run(ip, "-n", "upstream", "link", "set", "lo", "up")
    subscription_host = "198.51.100.2" if wan else "127.0.0.1"
    print("Fixture mode: LAN + private WAN" if wan else "Fixture mode: LAN")

    def identity():
        host = json.loads(run(ip, "-j", "link", "show", "dae0", capture_output=True).stdout)[0]
        peer = json.loads(run(ip, "-n", "daens", "-j", "link", "show", "dae0peer", capture_output=True).stdout)[0]
        return host["ifindex"], peer["ifindex"], os.stat("/run/netns/daens").st_ino, os.stat("/run/dae.sock").st_ino

    def listener_identity(ports):
        listeners = set()
        for table in ("tcp", "tcp6"):
            for line in Path(f"/proc/net/{table}").read_text().splitlines()[1:]:
                fields = line.split()
                port = int(fields[1].rsplit(":", 1)[1], 16)
                if fields[3] == "0A" and port in ports:
                    listeners.add((port, fields[9]))
        assert {port for port, _ in listeners} == set(ports), listeners
        return listeners

    # Router-source queries prove that DNS traverses userspace, not direct delivery.
    dns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dns.bind(("192.0.2.1", 53))
    sources, arrivals = [], []

    def answer():
        while True:
            query, source = dns.recvfrom(65535)
            sources.append(source[0])
            arrivals.append(time.monotonic())
            response = query[:2] + b"\x81\x80" + query[4:]
            dns.sendto(response, source)

    threading.Thread(target=answer, daemon=True).start()
    dns_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    dns_tcp.bind(("192.0.2.1", 53))
    dns_tcp.listen()

    def answer_tcp():
        while True:
            conn, _ = dns_tcp.accept()

            def serve(conn):
                with conn, conn.makefile("rb") as stream:
                    while header := stream.read(2):
                        wire = stream.read(struct.unpack("!H", header)[0])
                        response = wire[:2] + b"\x81\x80" + wire[4:]
                        conn.sendall(struct.pack("!H", len(response)) + response)

            threading.Thread(target=serve, args=(conn,), daemon=True).start()

    threading.Thread(target=answer_tcp, daemon=True).start()
    original_ns = os.open("/proc/self/ns/net", os.O_RDONLY)
    client_ns = os.open("/run/netns/fixture", os.O_RDONLY)
    os.setns(client_ns, 0)
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("192.0.2.2", 0))
    flood_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    flood_socket.bind(("192.0.2.2", 0))
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.bind(("192.0.2.2", 0))
    tcp.settimeout(2)
    os.setns(original_ns, 0)
    os.close(client_ns)
    os.close(original_ns)
    udp.settimeout(2)
    query_id = 0
    stop_flood = threading.Event()

    def query():
        nonlocal query_id
        query_id += 1
        return struct.pack("!6H", query_id, 0x100, 1, 0, 0, 0) + b"\x07fixture\x04test\x00\x00\x01\x00\x01"

    def flood():
        wire = struct.pack("!6H", 65535, 0x100, 1, 0, 0, 0) + b"\x07fixture\x04test\x00\x00\x01\x00\x01"
        while not stop_flood.wait(0.002):
            flood_socket.sendto(wire, ("192.0.2.1", 53))

    def traffic():
        wire = query()
        udp.sendto(wire, ("192.0.2.1", 53))
        response, _ = udp.recvfrom(65535)
        assert response[:2] == wire[:2] and response[2] & 0x80
        assert sources[-1] == "192.0.2.1", sources[-1]

    def assert_blocked_traffic():
        udp.settimeout(0.2)
        try:
            for _ in range(3):
                udp.sendto(query(), ("192.0.2.1", 53))
                try:
                    response, _ = udp.recvfrom(65535)
                except socket.timeout:
                    continue
                raise AssertionError(f"captured DNS was forwarded while blocked: {response!r}")
        finally:
            udp.settimeout(2)
        assert all(source == "192.0.2.1" for source in sources), "captured DNS leaked directly to the destination"

    blocked, release, served = threading.Event(), threading.Event(), threading.Event()
    probe_paths = []
    download_requests = []
    download_path = "/nodes/" + os.urandom(8).hex()
    subscription_body = b"http://127.0.0.1:9#fixture"

    class Subscription(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path.startswith("/probe/"):
                probe_paths.append(self.path)
                self.send_response(204)
                self.end_headers()
                return
            assert self.path == download_path, self.path
            download_requests.append(time.monotonic())
            blocked.set()
            if not release.wait(20):
                self.send_error(504, "fixture release timed out")
                return
            try:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(subscription_body)
            except BrokenPipeError:
                pass
            finally:
                served.set()

        def log_message(self, *args):
            pass

    if wan:
        original_ns = os.open("/proc/self/ns/net", os.O_RDONLY)
        upstream_ns = os.open("/run/netns/upstream", os.O_RDONLY)
        try:
            os.setns(upstream_ns, 0)
            subscriptions = http.server.ThreadingHTTPServer((subscription_host, 0), Subscription)
        finally:
            os.setns(original_ns, 0)
            os.close(upstream_ns)
            os.close(original_ns)
    else:
        subscriptions = http.server.ThreadingHTTPServer((subscription_host, 0), Subscription)
    threading.Thread(target=subscriptions.serve_forever, daemon=True).start()

    def probe_subscription(expect_blocked):
        path = "/probe/" + os.urandom(8).hex()
        code = "import http.client,sys; c=http.client.HTTPConnection(sys.argv[1], int(sys.argv[2]), timeout=0.4); c.request('GET', sys.argv[3]); r=c.getresponse(); assert r.status == 204; r.read()"
        result = subprocess.run([sys.executable, "-I", "-c", code, subscription_host, str(subscriptions.server_port), path], capture_output=True, text=True, timeout=3)
        assert (result.returncode != 0) == expect_blocked, result.stdout + result.stderr
        assert (path not in probe_paths) == expect_blocked, probe_paths

    if wan:
        probe_subscription(False)
    with tempfile.TemporaryDirectory(prefix="dae-replacement-") as directory:
        directory = Path(directory)
        config = directory / "config.dae"
        log = directory / "daemon.log"
        settings_path = directory / "cache" / "runtime-state.json"
        env = dict(os.environ, DAE_LOCATION_CACHE=str(directory / "cache"))
        env.pop("NOTIFY_SOCKET", None)
        text = "global { disable_waiting_network:true auto_config_kernel_parameter:true lan_interface:lan0 api_key:fixture-key api_port:18080 metrics_port:18081 pprof_port:18082 }\nclient { fixture { nftset:'inet/dae_replacement/clients' } }\nrouting { fallback:direct }\n"
        if wan:
            text = text.replace("lan_interface:lan0", "lan_interface:lan0 wan_interface:wan0").replace("routing { fallback:direct }", f"routing {{ dip({subscription_host}) && dport({subscriptions.server_port}) -> block\n fallback:direct }}")
        ports = (18080, 18081, 18082)
        exec_dns_gaps = []

        def write_config(value):
            config.write_text(value)
            config.chmod(0o600)

        def main_identity():
            stat = Path(f"/proc/{master.pid}/stat").read_text()
            return master.pid, stat.rsplit(") ", 1)[1].split()[19]

        def assert_image(executable, preparing=False):
            assert master.poll() is None and main_identity() == main_initial
            assert os.path.samefile(f"/proc/{master.pid}/exe", executable)
            assert Path(f"/proc/{master.pid}/cmdline").read_bytes().split(b"\0")[1:2] == [b"run"]
            helpers = 0
            for child in process_tree(master.pid) - {master.pid}:
                try:
                    args = Path(f"/proc/{child}/cmdline").read_bytes().split(b"\0")
                    daemon_child = args[1:2] == [b"run"] and os.path.samefile(f"/proc/{child}/exe", executable)
                except (FileNotFoundError, ProcessLookupError):
                    continue
                if daemon_child and preparing and args[0] == b"/proc/self/fd/3":
                    assert "memfd:dae-prepared-inputs" in os.readlink(f"/proc/{child}/fd/6")
                    helpers += 1
                    continue
                assert not daemon_child, f"unexpected resident daemon/supervisor child: {child} {args!r}"
            assert helpers == int(preparing), (helpers, preparing)

        def pins():
            return [path for path in Path("/sys/fs/bpf/dae").rglob("*") if not path.is_dir()]

        persistent_maps = ("tcp_flow_map", "tcp_handshake_gate_map", "socket_owner_map",
                           "daemon_identity_map", "fallback_sequence_map", "device_routes_map")

        def pin_identity():
            return {name: (Path("/sys/fs/bpf/dae") / name).stat().st_ino for name in persistent_maps}

        def assert_running_pins():
            pinned = pins()
            assert not any(path.is_relative_to("/sys/fs/bpf/dae/guards") for path in pinned), pinned
            assert not any(path.name.endswith("_next") for path in pinned), pinned
            assert Path("/sys/fs/bpf/dae/links/exit").is_file(), pinned
            assert any(path.parent.name == "links" and path.name.startswith("tcx_") for path in pinned), pinned
            timer_pins = [path for path in pinned if path.parent.name.startswith("runtime_")]
            assert len(timer_pins) == 2 and len({path.parent for path in timer_pins}) == 1, timer_pins
            return pin_identity()

        def stable_fd_count():
            counts = []

            def stable():
                counts.append(len(list(Path(f"/proc/{master.pid}/fd").iterdir())))
                return len(counts) >= 3 and len(set(counts[-3:])) == 1

            wait_for(stable, timeout=5)  # Let closed API probe connections drain.
            return counts[-1]

        def assert_guards():
            pinned = pins()
            assert any(path.name == "link" for path in pinned), pinned
            for guard in Path("/sys/fs/bpf/dae/guards").glob("*/link"):
                for name in ("udp_conn_state_map", "udp_routing_cache_map", "exit"):
                    assert (guard.parent / name).is_file(), (guard, name, pinned)
            if wan:
                assert any(path.name == "daemon_identity_map" and path.parent.parent.name == "guards" for path in pinned), pinned

        def api_request(method, path, body=None, management=False, timeout=2):
            connection = http.client.HTTPConnection("127.0.0.1", ports[0], timeout=timeout)
            try:
                if not management:
                    connection.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    connection.sock.settimeout(timeout)
                    connection.sock.connect("/run/dae.sock")
                connection.request(method, path, body=body, headers={
                    "Authorization": "Bearer fixture-key",
                    "Content-Type": "application/json",
                    "X-Dae-API": "1",
                })
                response = connection.getresponse()
                return response.status, response.read()
            finally:
                connection.close()

        def generation():
            status, body = api_request("GET", "/api/status")
            assert status == 200, (status, body)
            started = json.loads(body)["started_at"]
            assert started and not started.startswith("0001-"), body
            return started

        def startups():
            return sum(log_message(line, "Startup completed") for line in log.read_text().splitlines())

        def exported_members(name):
            result = run(TOOLS["nft"], "-j", "list", "set", "inet", "dae_replacement", name, capture_output=True)
            exported = next(item["set"] for item in json.loads(result.stdout)["nftables"] if "set" in item)
            return set(exported.get("elem", []))

        def listeners():
            for port, path in zip(ports, ("/api/status", "/metrics", "/debug/pprof/")):
                headers = {"Authorization": "Bearer fixture-key"} if port == ports[0] else {}
                request = urllib.request.Request(f"http://127.0.0.1:{port}{path}", headers=headers)
                with urllib.request.urlopen(request, timeout=2) as response:
                    assert response.status == 200

        def ready():
            try:
                listeners()
                return True
            except (OSError, http.client.HTTPException):
                return False

        def reload(executable, *flags, success=True, replacement=False):
            if success:
                previous, count = generation(), startups()
                arrival_start = max(0, len(arrivals) - 1)
            result = subprocess.run([executable, "reload", *flags], capture_output=True, text=True, timeout=30, env=env)
            assert (result.returncode == 0) == success, result.stdout + result.stderr
            if success:
                expected = replacement or "--replace" in flags
                assert (generation() != previous) == expected, "StartedAt did not match the expected generation change"
                assert startups() == count + int(expected), "unexpected number of daemon startups"
                assert_image(executable)
                assert identity() == initial
                if ports == (18080, 18081, 18082):
                    assert listener_identity(ports) == initial_listeners
                if expected:
                    traffic()
                    window = arrivals[arrival_start:]
                    exec_dns_gaps.append({"kind": "forced" if "--replace" in flags else "different-ELF", "dns_max_gap_ms": round(max(right - left for left, right in zip(window, window[1:])) * 1000, 1)})
            return result.stdout

        write_config(text)
        memory_sampler = None
        with log.open("w") as output:
            master = subprocess.Popen([binary, "run", "--disable-sudo", "-c", str(config)], stdout=output, stderr=output, env=env)
            try:
                wait_for(lambda: ready() or master.poll() is not None)
                assert master.poll() is None, log.read_text()
                main_initial = main_identity()
                initial = identity()
                initial_listeners = listener_identity(ports)
                assert_image(binary)
                member = "02:00:00:00:00:42"
                status, body = api_request("PUT", f"/api/clients/fixture/members/{member}")
                assert status == 200, (status, body)
                assert settings_path.is_file() and exported_members("clients") == {member}

                def duplicate_run():
                    # Detect the live owner before even loading a second config.
                    for args in ([], ["-c", str(directory / "missing.dae")]):
                        result = subprocess.run([binary, "run", "--disable-sudo", *args], capture_output=True, text=True, timeout=10, env=env)
                        assert result.returncode != 0 and "already running" in result.stderr and "dae reload" in result.stderr, result.stdout + result.stderr
                        assert main_identity() == main_initial and identity() == initial

                duplicate_run()
                threading.Thread(target=flood, daemon=True).start()
                tcp.connect(("192.0.2.1", 53))
                wire = query()
                tcp.sendall(struct.pack("!H", len(wire)) + wire)
                received = b""
                while len(received) < len(wire) + 2:
                    chunk = tcp.recv(65535)
                    assert chunk, "captured TCP connection closed before its first reply"
                    received += chunk
                traffic()
                listeners()
                assert "No changes" in reload(binary), "cold preparation omitted a host interface from routing inputs"
                traffic()
                memory_stable = {"initial": process_tree_memory(master.pid)}
                memory_sampler = MemorySampler(lambda: master.pid)
                if wan:
                    probe_subscription(True)
                original_generation = generation()
                original_startups = startups()
                for invalid in ("invalid configuration", text.replace("lan_interface:lan0", "lan_interface:lan1"), text.replace("metrics_port:18081", "metrics_port:18080")):
                    write_config(invalid)
                    reload(binary, "--replace", success=False)
                    assert_image(binary)
                    assert identity() == initial and listener_identity(ports) == initial_listeners
                    assert generation() == original_generation and startups() == original_startups
                    assert exported_members("clients") == {member}
                    assert_running_pins()
                    traffic()
                # Target input preparation runs while the old dataplane still serves.
                # The successor must not rediscover configuration or download again.
                replacement_text = text.replace("dae_replacement/clients", "dae_replacement/successor")
                subscription_url = f"http://{subscription_host}:{subscriptions.server_port}{download_path}"
                subscription_cache = directory / "cache" / "resources" / "subscriptions"
                assert not list(subscription_cache.glob("*.json")), "download fixture unexpectedly has a usable cache"
                write_config(replacement_text + f"subscription {{ fixture:'{subscription_url}' }}\n")
                arrival_start = max(0, len(arrivals) - 1)
                pending = subprocess.Popen([binary, "reload", "--replace"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
                assert blocked.wait(10), log.read_text()
                assert_image(binary, preparing=True)
                assert identity() == initial and listener_identity(ports) == initial_listeners
                assert_running_pins()
                assert generation() == original_generation and startups() == original_startups
                listeners()
                if wan:
                    probe_subscription(True)
                assert exported_members("clients") == {member}
                assert subprocess.run([TOOLS["nft"], "list", "set", "inet", "dae_replacement", "successor"], capture_output=True).returncode != 0
                duplicate_run()
                traffic()
                write_config("invalid after input capture")
                release.set()
                stdout, stderr = pending.communicate(timeout=30)
                assert pending.returncode == 0, stdout + stderr + log.read_text()
                assert served.wait(5)
                assert len(download_requests) == 1, "successor performed another resource request"
                assert config.read_text() == "invalid after input capture"
                if wan:
                    probe_subscription(True)
                    snapshots = [json.loads(path.read_text()) for path in subscription_cache.glob("*.json")]
                    assert len(snapshots) == 1 and snapshots[0]["key"] == subscription_url, snapshots
                    cached_body = snapshots[0]["resources"][subscription_url]["data"]
                    assert base64.b64decode(cached_body, validate=True) == subscription_body, snapshots
                assert generation() != original_generation and startups() == original_startups + 1
                assert_image(binary)
                assert identity() == initial and listener_identity(ports) == initial_listeners
                assert exported_members("successor") == {member}
                assert exported_members("clients") == {member}, "retiring runtime erased the old exported set"
                status, body = api_request("PUT", "/api/clients/fixture/members/02:00:00:00:00:99")
                assert status == 200, (status, body)
                assert exported_members("successor") == {member, "02:00:00:00:00:99"}
                status, body = api_request("DELETE", "/api/clients/fixture/members/02:00:00:00:00:99")
                assert status == 200, (status, body)
                assert exported_members("successor") == {member}
                try:
                    received = tcp.recv(1)
                    raise AssertionError(f"idle captured TCP peer did not receive RST: {received!r}")
                except ConnectionResetError:
                    pass
                tcp.close()
                traffic()
                window = arrivals[arrival_start:]
                exec_dns_gaps.append({"kind": "controlled-download", "dns_max_gap_ms": round(max(right - left for left, right in zip(window, window[1:])) * 1000, 1)})
                assert_running_pins()
                # A distinct ELF with the same version string selects replace.
                different = directory / "dae-different"
                shutil.copyfile(binary, different)
                with different.open("ab") as changed:
                    changed.write(b"different-build-same-version")
                different.chmod(0o755)
                write_config(text)
                reload(str(different), replacement=True)
                traffic()
                reload(str(different))
                fd_counts = []
                for _ in range(3):
                    reload(str(different), "--replace")
                    traffic()
                    listeners()
                    fd_counts.append(stable_fd_count())
                    assert_running_pins()
                changed_text = text.replace("global {", "global { tproxy_port:12346 so_mark_from_dae:512").replace("api_port:18080", "api_port:18081").replace("metrics_port:18081", "metrics_port:18080").replace("pprof_port:18082", "pprof_port:18085")
                write_config(changed_text)
                ports = (18081, 18080, 18085)
                reload(str(different), "--replace")
                traffic()
                listeners()
                try:
                    with socket.create_connection(("127.0.0.1", 18082), timeout=2):
                        raise AssertionError("old pprof listener remains open")
                except ConnectionRefusedError:
                    pass
                assert len(set(fd_counts)) == 1, fd_counts
                time.sleep(1)  # Match the baseline's post-replacement settling interval.
                memory_stable["after_replacements"] = process_tree_memory(master.pid)
                memory_sampler.finish(memory_stable)
                durations = phase_durations(log.read_text(), "Replacement datapath ready", "cutover")
                preparations = phase_durations(log.read_text(), "Replacement inputs prepared", "duration")
                assert len(durations) == len(preparations) == len(exec_dns_gaps) == 6 and all(duration > 0 for duration in durations), durations
                print(f"Same-PID exec: PID/starttime={main_initial}, FD={fd_counts}, resource_requests={len(download_requests)}")
                print("Successful exec measurements (preparation, final cutover and DNS inter-arrival are distinct): " + json.dumps([dict(dns_gap, preparation_ms=round(preparation * 1000, 1), cutover_ms=round(duration * 1000, 1)) for dns_gap, preparation, duration in zip(exec_dns_gaps, preparations, durations)]))

                def cold_restart():
                    nonlocal master, main_initial, initial
                    master = subprocess.Popen([binary, "run", "--disable-sudo", "-c", str(config)], stdout=output, stderr=output, env=env)
                    wait_for(lambda: ready() or master.poll() is not None)
                    assert master.poll() is None, log.read_text()
                    main_initial, initial = main_identity(), identity()
                    assert_image(binary)
                    traffic()
                    listeners()
                    assert exported_members("clients") == {member}
                    assert_running_pins()

                # These pass preflight and fail only after the old runtime is retired.
                for failure in ("settings", "port"):
                    saved_settings = settings_path.read_bytes()
                    if failure == "settings":
                        settings_path.write_text("invalid settings")
                    else:
                        write_config(changed_text.replace("api_port:18081", "api_port:53"))  # The fixture's host TCP DNS listener already owns this port.
                    before_startups = startups()
                    failed_reload = subprocess.Popen([binary, "reload", "--replace"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
                    assert master.wait(timeout=20) != 0, f"{failure} failure unexpectedly kept the retired daemon alive"
                    assert startups() == before_startups, f"{failure} failure reported a successful startup"
                    assert identity() == initial, "failed exec deleted fixed network objects"
                    assert_guards()
                    assert exported_members("clients") == {member}
                    assert_blocked_traffic()
                    settings_path.write_bytes(saved_settings)
                    write_config(changed_text)
                    cold_restart()
                    # A failed exec cannot answer the old operation; cold startup makes its ID explicitly stale.
                    stdout, stderr = failed_reload.communicate(timeout=30)
                    assert failed_reload.returncode != 0, stdout + stderr
                stop_flood.set()
                gaps = [right - left for left, right in zip(arrivals, arrivals[1:])]
                print(f"Maximum DNS inter-arrival gap (includes controlled download and failure/recovery windows, not pure Block time): {max(gaps, default=0) * 1000:.1f} ms")
                assert sources and all(source == "192.0.2.1" for source in sources), "captured DNS leaked directly to the destination"
                # A crash retains canonical state; a normal restart reuses compatible maps.
                for _ in range(3):
                    previous_pins = assert_running_pins()
                    previous = master.pid
                    os.kill(previous, 9)
                    assert master.wait(timeout=20) != 0, "a daemon crash must not exit successfully"
                    assert not Path(f"/proc/{previous}").exists()
                    assert assert_running_pins() == previous_pins
                    cold_restart()
                    assert assert_running_pins() == previous_pins
                master.terminate()
                assert master.wait(timeout=20) == 0, log.read_text()
                assert not pins(), pins()
                if wan:
                    print("PASS: private WAN denied another PID before/during/after exec while the target prepared an uncached resource before Block")
                print("PASS: single resident daemon, stable PID/starttime across exec, input preparation failures, old API and traffic during downloads, sealed configuration replay after source changes without another request, successor-owned exports, no direct DNS leakage, content-based replacement, forced same-ELF generations, stable FDs and fixed identities, TCP abort, listener changes, post-Block failures and cold recovery, crash restarts retaining compatible canonical pins and normal-stop cleanup")
            except BaseException:
                print(log.read_text(), file=sys.stderr)
                raise
            finally:
                stop_flood.set()
                release.set()
                if memory_sampler is not None:
                    memory_sampler.stop.set()
                    memory_sampler.thread.join()
                if master.poll() is None:
                    master.terminate()
                    try:
                        master.wait(timeout=20)
                    except subprocess.TimeoutExpired:
                        master.kill()
                        master.wait(timeout=5)


if __name__ == "__main__":
    if len(sys.argv) < 2 or os.geteuid() != 0:
        sys.exit(__doc__)
    binary = str(Path(sys.argv[1]).resolve())
    options = sys.argv[2:]
    if any(option not in ("--isolated", "--wan") for option in options):
        sys.exit(__doc__)
    if "--isolated" not in options:
        cgroup = Path("/sys/fs/cgroup") / f"dae-replacement-test-{os.getpid()}"
        cgroup.mkdir()
        try:
            env = dict(os.environ, DAE_REPLACEMENT_TEST_CGROUP=str(cgroup))
            run(TOOLS["unshare"], "--mount", "--net", "--pid", "--fork", "--mount-proc",
                os.path.realpath(sys.executable), "-I", str(Path(__file__).resolve()),
                binary, *options, "--isolated", env=env)
        finally:
            cgroup.rmdir()
    else:
        main(binary, wan="--wan" in options)
