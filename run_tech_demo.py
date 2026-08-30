# run_tech_demo.py
# Project Solomon: Master Demo Orchestrator Pipeline
# Automatically boots mock control plane, banking backend, and ZK proxy,
# executes the full feature demo client, and gracefully cleans up background services.

import os
import sys
import time
import socket
import subprocess
import threading

sys.stdout.reconfigure(encoding='utf-8')
sys.stderr.reconfigure(encoding='utf-8')

def resolve_python_executable():
    """
    Dynamically searches the current environment and system PATH for a Python interpreter
    that has the required dependencies (fastapi, uvicorn, cryptography, pydantic) installed.
    """
    try:
        import fastapi
        import uvicorn
        import cryptography
        return sys.executable
    except ImportError:
        pass

    import shutil
    candidates = []
    
    # Try finding Python paths via 'where python' under Windows
    try:
        output = subprocess.check_output("where python", shell=True).decode().strip().split('\n')
        for line in output:
            path = line.strip()
            if path and os.path.isfile(path) and path not in candidates:
                candidates.append(path)
    except Exception:
        pass

    for p in ["python", "python3"]:
        resolved = shutil.which(p)
        if resolved and resolved not in candidates:
            candidates.append(resolved)

    for candidate in candidates:
        try:
            cmd = [candidate, "-c", "import fastapi, uvicorn, cryptography, pydantic"]
            res = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if res.returncode == 0:
                print(f"💡 Dynamic Environment Resolution: Current Python interpreter ({sys.executable}) lacks dependencies.")
                print(f"   Spawning background services using: {candidate}\n")
                return candidate
        except Exception:
            pass

    return sys.executable

PYTHON_EXE = resolve_python_executable()

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

PORT_PROXY = 8080
PORT_BACKEND = 8081
PORT_CONTROL = 9000

processes = {}

# Absolute path resolution based on script location
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CORE_DIR = os.path.join(SCRIPT_DIR, "solomon-core")

def kill_process_by_port(port):
    """Kills any process listening on the specified port on Windows."""
    try:
        cmd = f"netstat -ano | findstr LISTENING | findstr :{port}"
        output = subprocess.check_output(cmd, shell=True).decode()
        for line in output.strip().split('\n'):
            if not line:
                continue
            parts = line.split()
            if len(parts) >= 5:
                pid = parts[-1]
                # Force taskkill
                subprocess.run(f"taskkill /F /PID {pid}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass

def check_port_listening(port):
    """Checks if a local port is listening."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.3)
        s.connect(('127.0.0.1', port))
        s.close()
        return True
    except Exception:
        return False

def bootstrap_infrastructure():
    print(f"{Color.HEADER}{Color.BOLD}========================================================================{Color.END}")
    print(f"{Color.HEADER}{Color.BOLD}            PROJECT SOLOMON: DEMO ORCHESTRATION PIPELINE                {Color.END}")
    print(f"{Color.HEADER}{Color.BOLD}========================================================================{Color.END}")
    
    print(f"\n{Color.CYAN}[Step 1: Cleaning Port Conflicts & Environment]{Color.END}")
    for p in [PORT_CONTROL, PORT_BACKEND, PORT_PROXY]:
        kill_process_by_port(p)
    print(f"  ✅ Environment ports {PORT_CONTROL}, {PORT_BACKEND}, {PORT_PROXY} cleaned.")

    print(f"\n{Color.CYAN}[Step 2: Spawning Secure Network Topology]{Color.END}")
    
    # 1. Start Control Plane
    print(f"  ☁️  Starting AWS Control Plane (FastAPI on Port {PORT_CONTROL})...")
    processes['control'] = subprocess.Popen(
        [PYTHON_EXE, "mock_control_plane.py"],
        cwd=CORE_DIR,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    # 2. Start Banking Backend
    print(f"  🏦 Starting Legacy Banking Backend (FastAPI on Port {PORT_BACKEND})...")
    processes['backend'] = subprocess.Popen(
        [PYTHON_EXE, "mock_banking_backend.py"],
        cwd=CORE_DIR,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    
    # Wait for Control Plane and Backend to bind to their ports
    print(f"  ⏳ Waiting for AWS Control Plane to start listening on port {PORT_CONTROL}...")
    start_wait = time.time()
    while time.time() - start_wait < 30:
        if check_port_listening(PORT_CONTROL):
            break
        time.sleep(0.5)

    print(f"  ⏳ Waiting for Banking Backend to start listening on port {PORT_BACKEND}...")
    start_wait = time.time()
    while time.time() - start_wait < 30:
        if check_port_listening(PORT_BACKEND):
            break
        time.sleep(0.5)

    # 3. Start ZK Gateway Proxy
    print(f"  🛡️  Booting Solomon Post-Quantum Proxy (Port {PORT_PROXY})...")
    env = os.environ.copy()
    env["PROXY_LISTEN_ADDR"] = f"127.0.0.1:{PORT_PROXY}"
    env["BACKEND_URL"] = f"http://127.0.0.1:{PORT_BACKEND}"
    env["CONTROL_PLANE_URL"] = f"http://127.0.0.1:{PORT_CONTROL}"
    env["LICENSE_ID"] = "ENT-5821"

    # Use cargo run --release to execute
    processes['proxy'] = subprocess.Popen(
        ["cargo", "run", "--release", "--features", "proxy"],
        cwd=CORE_DIR,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    print(f"  ⏳ Waiting for Edge Proxy to establish memory maps and start listening...")
    start_wait = time.time()
    active = False
    while time.time() - start_wait < 60:
        if check_port_listening(PORT_PROXY):
            active = True
            break
        time.sleep(0.5)

    if not active:
        print(f"  ❌ {Color.RED}Solomon Proxy failed to start or listen in time.{Color.END}")
        teardown()
        sys.exit(1)
        
    print(f"  ✅ {Color.GREEN}Secure network topology fully active.{Color.END}\n")

def execute_demo():
    print(f"{Color.CYAN}[Step 3: Running Complete Feature Demonstration Script]{Color.END}")
    time.sleep(0.5)
    
    # Run single_success.py and stream its output live
    demo_script = os.path.join(CORE_DIR, "single_success.py")
    proc = subprocess.Popen(
        [PYTHON_EXE, demo_script],
        cwd=CORE_DIR,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding='utf-8'
    )
    
    for line in proc.stdout:
        print(line, end="")
        
    proc.wait()
    print(f"\n{Color.GREEN}✅ Demonstration script completed execution.{Color.END}\n")

def teardown():
    print(f"{Color.CYAN}[Step 4: Graceful Teardown & Environment Cleanup]{Color.END}")
    for name, proc in processes.items():
        try:
            print(f"  Stopping background service: {name}...")
            proc.terminate()
            proc.wait(timeout=2)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
    
    # Double check clean ports
    for p in [PORT_CONTROL, PORT_BACKEND, PORT_PROXY]:
        kill_process_by_port(p)
        
    print(f"  ✅ Cleanup complete. All processes terminated.{Color.END}")
    print(f"{Color.HEADER}{Color.BOLD}========================================================================{Color.END}\n")

if __name__ == "__main__":
    try:
        bootstrap_infrastructure()
        execute_demo()
    except KeyboardInterrupt:
        print(f"\n{Color.YELLOW}Demo execution interrupted by user.{Color.END}")
    finally:
        teardown()
