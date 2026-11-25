"""How much delay artex-shield-proxy adds to each request.

    python examples/bench_proxy.py [--requests 20000] [--concurrency 32]

Starts a minimal HTTP origin and the proxy in their own processes on
127.0.0.1, then times the same requests sent straight to the origin and sent
through the proxy: one at a time over one kept-alive connection, then
`concurrency` connections at once. The difference is what the proxy costs.

Each request carries a different X-Forwarded-For address (the proxy trusts
127.0.0.1), so the shield scores it fully as a visitor's first requests, the
way ordinary traffic arrives, instead of piling everything onto one address
that the flood sensor would then flag. Standard library only.
"""
import argparse
import asyncio
import os
import re
import statistics
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ORIGIN = r'''
import asyncio, sys
BODY = b"x" * 1024
async def serve(reader, writer):
    try:
        while True:
            await reader.readuntil(b"\r\n\r\n")
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 1024\r\n\r\n" + BODY)
            await writer.drain()
    except (asyncio.IncompleteReadError, ConnectionError):
        writer.close()
async def main():
    server = await asyncio.start_server(serve, "127.0.0.1", 0)
    print(server.sockets[0].getsockname()[1], flush=True)
    await server.serve_forever()
asyncio.run(main())
'''


def request(n: int) -> bytes:
    a, b = divmod(n % 60000, 250)
    return (b"GET /blog/2026/11/post-%d?page=%d HTTP/1.1\r\nHost: www.example\r\nX-Forwarded-For: 198.18.%d.%d\r\n"
            b"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
            b"Chrome/131.0 Safari/537.36\r\nAccept: text/html,*/*;q=0.8\r\nAccept-Language: en-GB,en;q=0.9\r\n"
            b"Accept-Encoding: gzip, br\r\nCookie: session=abc123; theme=dark\r\n\r\n" % (n, n % 7, a, b + 1))


async def one_connection(port: int, start: int, count: int, times: list) -> None:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    for n in range(start, start + count):
        t = time.perf_counter()
        writer.write(request(n))
        head = await reader.readuntil(b"\r\n\r\n")
        length = int(re.search(rb"(?i)content-length: *(\d+)", head).group(1))
        await reader.readexactly(length)
        times.append(time.perf_counter() - t)
        if not head.startswith(b"HTTP/1.1 200"):
            raise SystemExit(f"unexpected answer: {head[:60]!r}")
    writer.close()


async def run(port: int, requests: int, concurrency: int) -> tuple:
    times: list = []
    per = requests // concurrency
    started = time.perf_counter()
    await asyncio.gather(*(one_connection(port, i * per, per, times) for i in range(concurrency)))
    return times, len(times) / (time.perf_counter() - started)


def pct(times, p):
    return sorted(times)[min(len(times) - 1, int(len(times) * p))] * 1000


def start(cmd, env=None) -> subprocess.Popen:
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, text=True)
    return proc


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--requests", type=int, default=20000)
    ap.add_argument("--concurrency", type=int, default=32)
    args = ap.parse_args()

    origin = start([sys.executable, "-c", ORIGIN])
    origin_port = int(origin.stdout.readline())
    env = dict(os.environ, PYTHONPATH=os.path.join(ROOT, "src"), ARTEX_SHIELD_TRUSTED_PROXIES="127.0.0.1/32")
    proxy = start([sys.executable, "-m", "artex_shield.proxy", "--backend", f"http://127.0.0.1:{origin_port}",
                   "--listen", "127.0.0.1:0"], env)
    try:
        proxy_port = int(re.search(r"listening on 127\.0\.0\.1:(\d+)", proxy.stderr.readline()).group(1))
        rows = []
        for label, concurrency in (("one at a time", 1), (f"{args.concurrency} connections", args.concurrency)):
            result = {}
            for target, port in (("direct", origin_port), ("proxy", proxy_port)):
                asyncio.run(run(port, 2000, concurrency))                 # warm up
                result[target] = asyncio.run(run(port, args.requests, concurrency))
            (d, d_rate), (p, p_rate) = result["direct"], result["proxy"]
            rows.append((label, statistics.median(d) * 1000, statistics.median(p) * 1000, pct(d, 0.99), pct(p, 0.99),
                         d_rate, p_rate))
        print(f"{args.requests} requests, Python {sys.version.split()[0]}, {os.cpu_count()} CPUs\n")
        print("| | p50 direct | p50 proxy | added p50 | p99 direct | p99 proxy | req/s direct | req/s proxy |")
        print("| --- | --- | --- | --- | --- | --- | --- | --- |")
        for label, d50, p50, d99, p99, dr, pr in rows:
            print(f"| {label} | {d50:.3f} ms | {p50:.3f} ms | **{p50 - d50:.3f} ms** | {d99:.3f} ms | {p99:.3f} ms "
                  f"| {dr:,.0f} | {pr:,.0f} |")
    finally:
        for proc in (proxy, origin):
            proc.terminate()
            try:
                proc.wait(10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
            for stream in (proc.stdout, proc.stderr):
                stream.close()


if __name__ == "__main__":
    main()
