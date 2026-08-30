# run_barrage_simulation.py
# Solomon TRL-4 Zero-Cost Asynchronous Barrage Orchestrator
# Executes the entire container-less topology on Windows, replicating
# Toxiproxy noise (120ms latency + 30ms jitter) and running the concurrent load test.

import os
import sys
import time
import socket
import random
import threading
import subprocess
import urllib.request
from http.server import SimpleHTTPRequestHandler
from socketserver import ThreadingTCPServer

sys.stdout.reconfigure(encoding='utf-8')
sys.stderr.reconfigure(encoding='utf-8')

class Color:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    END = '\033[0m'
    GRAY = '\033[90m'

PORT_CHAOS = 8080
PORT_PROXY = 8082
PORT_BACKEND = 8081
PORT_CONTROL = 9000

processes = {}

def kill_process_by_port(port):
    try:
        cmd = f"netstat -ano | findstr LISTENING | findstr :{port}"
        output = subprocess.check_output(cmd, shell=True).decode()
        for line in output.strip().split('\n'):
            if not line:
                continue
            parts = line.split()
            if len(parts) >= 5:
                pid = parts[-1]
                subprocess.run(f"taskkill /F /PID {pid}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass

def start_topology():
    print(f"{Color.CYAN}🚀 Booting containerless infrastructure...{Color.END}")
    for port in [PORT_CONTROL, PORT_BACKEND, PORT_PROXY, PORT_CHAOS]:
        kill_process_by_port(port)

    # 1. Boot Control Plane
    processes['control'] = subprocess.Popen(
        ["python", "mock_control_plane.py"],
        cwd="solomon-core",
        stdout=open("control_plane_barrage.log", "w", encoding="utf-8"),
        stderr=open("control_plane_barrage_err.log", "w", encoding="utf-8")
    )
    
    # 2. Boot Backend
    processes['backend'] = subprocess.Popen(
        ["python", "mock_banking_backend.py"],
        cwd="solomon-core",
        stdout=open("banking_backend_barrage.log", "w", encoding="utf-8"),
        stderr=open("banking_backend_barrage_err.log", "w", encoding="utf-8")
    )
    time.sleep(1.5)

    # 3. Boot Solomon PQ Proxy
    env = os.environ.copy()
    env["PROXY_LISTEN_ADDR"] = f"127.0.0.1:{PORT_PROXY}"
    env["BACKEND_URL"] = f"http://127.0.0.1:{PORT_BACKEND}"
    env["CONTROL_PLANE_URL"] = f"http://127.0.0.1:{PORT_CONTROL}"
    env["LICENSE_ID"] = "ENT-5821"

    processes['proxy'] = subprocess.Popen(
        ["cargo", "run", "--release", "--features", "proxy", "--target-dir", "C:\\Users\\usman\\AppData\\Local\\Temp\\solomon_chaos_target"],
        cwd="solomon-core",
        env=env,
        stdout=open("solomon_proxy_barrage.log", "w", encoding="utf-8"),
        stderr=open("solomon_proxy_barrage_err.log", "w", encoding="utf-8")
    )

    print(f"{Color.GRAY}  [Scheduler] Compiling Rust binary and waiting for proxy to listen on port {PORT_PROXY}...{Color.END}")
    start_wait = time.time()
    listening = False
    while time.time() - start_wait < 120:
        if processes['proxy'].poll() is not None:
            print(f"{Color.RED}❌ Solomon Proxy failed to compile or boot! Check logs.{Color.END}")
            sys.exit(1)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            s.connect(('127.0.0.1', PORT_PROXY))
            s.close()
            listening = True
            break
        except Exception:
            time.sleep(1.0)

    if not listening:
        print(f"{Color.RED}❌ Solomon Proxy timeout listening on {PORT_PROXY}!{Color.END}")
        sys.exit(1)
    print(f"{Color.GREEN}✅ Infrastructure ready.{Color.END}\n")

# Threaded HTTP Proxy Interceptor with 120ms baseline + 30ms Jitter
class JitterChaosHandler(SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        pass
        
    def handle_request(self, method):
        # 120ms baseline latency + 30ms jitter -> random between 90ms and 150ms
        delay = (120.0 + random.uniform(-30.0, 30.0)) / 1000.0
        time.sleep(delay)

        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length) if content_length > 0 else b""

        url = f"http://127.0.0.1:{PORT_PROXY}{self.path}"
        headers = {k: v for k, v in self.headers.items() if k.lower() != 'host'}
        
        req = urllib.request.Request(url, data=body if body else None, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=5.0) as response:
                self.send_response(response.getcode())
                for k, v in response.getheaders():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(response.read())
        except urllib.error.HTTPError as e:
            self.send_response(e.code)
            for k, v in e.headers.items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(e.read())
        except Exception as e:
            self.send_error(502, f"Bad Gateway: {e}")

    def do_GET(self): self.handle_request("GET")
    def do_POST(self): self.handle_request("POST")

class ThreadedHTTPServer(ThreadingTCPServer):
    allow_reuse_address = True

def run_chaos_proxy():
    server = ThreadedHTTPServer(('127.0.0.1', PORT_CHAOS), JitterChaosHandler)
    server.serve_forever()

def run_simulation():
    # Phase 3
    start_topology()

    # Phase 4
    print(f"{Color.CYAN}🌪️ Injecting network chaos (120ms latency + 30ms jitter)...{Color.END}")
    threading.Thread(target=run_chaos_proxy, daemon=True).start()
    time.sleep(1)
    print(f"{Color.GREEN}✅ Toxiproxy emulator running on port {PORT_CHAOS}.{Color.END}\n")

    # Phase 5
    print(f"{Color.CYAN}🔥 Firing asynchronous payload barrage (100 concurrent requests)...{Color.END}")
    time.sleep(1)
    
    # Run load_test.py and stream output
    proc = subprocess.Popen(["python", "load_test.py"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    
    success_count = 0
    fail_count = 0
    
    for line in proc.stdout:
        print(line, end="")
        if "[SUCCESS]" in line:
            success_count += 1
        elif "[FAIL-CLOSED]" in line:
            fail_count += 1
            
    proc.wait()
    print(f"\n{Color.BOLD}📊 Barrage Summary:{Color.END}")
    print(f"  - Successfully Signed (ML-DSA-65) & Compressed (ZK-SNARK): {Color.GREEN}{success_count}{Color.END}")
    print(f"  - Failed/Dropped:                                            {Color.RED if fail_count > 0 else Color.GRAY}{fail_count}{Color.END}")
    print("")

def cleanup():
    # Phase 6
    print(f"{Color.CYAN}🧹 Tearing down simulation environment...{Color.END}")
    for name, proc in processes.items():
        try:
            proc.terminate()
            proc.wait(timeout=2)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
    print(f"{Color.GREEN}✅ TRL-4 Simulation Complete. Telemetry ready for IIEC grant submission.{Color.END}")

if __name__ == "__main__":
    try:
        run_simulation()
    except KeyboardInterrupt:
        print("\nInterrupted.")
    finally:
        cleanup()
