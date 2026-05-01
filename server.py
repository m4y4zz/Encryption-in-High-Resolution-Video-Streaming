import socket
import threading
import time
import os
import sys
import psutil
import signal
from datetime import datetime
import cv2 
import encrypt 
import csv
import queue
from secrets import token_bytes


HOST = '127.0.0.1'  
PORT = 65432        
FRAME_BUFFER_SIZE = 4096 

# Choose one of the video options.
####################################################
#VIDEO_FILE = 'bbb_sunflower_2160p_60fps_normal.mp4' 
VIDEO_FILE = 'test_video.mp4'
####################################################

KEY_SIZE = 32

GLOBAL_KEY = token_bytes(KEY_SIZE)
SERVER_RUNNING = True
CLIENT_THREADS = []
SERVER_SOCKET = None

HEADER_SIZE = 8
AVAILABLE_CIPHERS = ["AES-CTR-LIB", "CHACHA20-LIB", "SALSA20-LIB", "BLOWFISH-LIB", "CAMELLIA-LIB"]

SERVER_METRICS_LOG = []
METRICS_LOCK = threading.Lock()

def monitor_system_load(process):
    cpu_percent = process.cpu_percent(interval=None) 
    memory_info = process.memory_info()
    return cpu_percent, memory_info.rss / (1024 * 1024) 
    
def export_metrics_to_csv():
    if not SERVER_METRICS_LOG:
        print("[METRIC] No data to export.")
        return
    
    filename = f"server_metrics_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    keys = SERVER_METRICS_LOG[0].keys()
    
    with open(filename, 'w', newline='') as f:
        dict_writer = csv.DictWriter(f, fieldnames=keys)
        dict_writer.writeheader()
        dict_writer.writerows(SERVER_METRICS_LOG)
    print(f"\n[METRIC] Data was successfully exported to: {filename}")

def producer_thread(cap: cv2.VideoCapture, frame_queue: queue.Queue, cipher_mode: str, running_event: threading.Event):
    """
    Producer thread: reads frames from the video, encrypts them with the
    cipher chosen by the client, and puts them in the per-client queue.
    """
    fps = cap.get(cv2.CAP_PROP_FPS)
    sleep_time = 1 / fps if fps > 0 else 1 / 30
    total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
    encode_param = [int(cv2.IMWRITE_JPEG_QUALITY), 90]
    server_process = psutil.Process(os.getpid())
    frame_sent_count = 0

    conf = encrypt.CIPHER_CONFIG.get(cipher_mode)
    if conf is None:
        print(f"[PRODUCER] Unknown cipher mode: {cipher_mode}")
        running_event.clear()
        cap.release()
        return

    nonce_size = conf['NONCE_SIZE']

    print(f"\n[PRODUCER] Started. Cipher: {cipher_mode} | Nonce: {nonce_size}B | FPS: {fps:.2f} | Frames: {total_frames}")

    try:
        while running_event.is_set() and cap.isOpened():
            frame_start = time.monotonic()
            ret, frame = cap.read()

            if not ret:
                print("[PRODUCER] End of video. Stopping producer...")
                break

            _, encoded_frame = cv2.imencode('.jpg', frame, encode_param)
            frame_data = encoded_frame.tobytes()

            frame_nonce = os.urandom(nonce_size)
            encrypted_data = encrypt.encrypt_dataA(GLOBAL_KEY, frame_data, cipher_mode, frame_nonce)

            try:
                frame_queue.put((frame_nonce, encrypted_data), timeout=0.5)
                frame_sent_count += 1
            except queue.Full:
                pass  

            time_spent = time.monotonic() - frame_start
            wait_time = sleep_time - time_spent
            if wait_time > 0:
                time.sleep(wait_time)

            if frame_sent_count % 50 == 0:
                cpu_load, memory_usage = monitor_system_load(server_process)
                print(f" | [PRODUCER] Encrypted Frames: {frame_sent_count} | Queue: {frame_queue.qsize()}/{frame_queue.maxsize} | CPU: {cpu_load:.1f}% | RAM: {memory_usage:.1f}MB")

    except Exception as e:
        print(f"[PRODUCER] Exception: {e}")
    finally:
        cap.release()
        running_event.clear()  
        print("[PRODUCER] Production thread closed.")

def handle_client(conn: socket.socket, addr):
    """
    Handles a single client connection end-to-end:
      1. Receive cipher choice
      2. Send key
      3. Start a dedicated producer thread for this client
      4. Stream encrypted frames
    """
    global SERVER_RUNNING
    print(f"Connection accepted from {addr}")

    bytes_sent = 0
    start_time = time.monotonic()
    frame_count = 0
    server_process = psutil.Process(os.getpid())

    try:
        # Handshake: receive cipher choice
        mode_choice = conn.recv(1024).decode('utf-8').strip()
        if mode_choice not in AVAILABLE_CIPHERS:
            conn.sendall(b"ERROR: Invalid Mode")
            raise ValueError(f"Client {addr} requested invalid cipher: {mode_choice}")

        cipher_mode = mode_choice
        conf = encrypt.CIPHER_CONFIG[cipher_mode]
        nonce_size = conf['NONCE_SIZE']
        print(f"Client {addr} selected cipher: {cipher_mode} (nonce={nonce_size}B)")

        # Send key
        conn.sendall(b"KEY_START")
        time.sleep(0.01)
        conn.sendall(GLOBAL_KEY)
        print(f"Key sent to {addr}.")

        # Open video and start per-client producer
        cap = cv2.VideoCapture(VIDEO_FILE)
        if not cap.isOpened():
            conn.sendall(b"ERROR: Video not found")
            raise RuntimeError(f"Cannot open video file: {VIDEO_FILE}")

        fps = cap.get(cv2.CAP_PROP_FPS)
        conn.sendall(f"STREAM_START:{fps}".encode('utf-8'))
        time.sleep(0.01)

        frame_queue = queue.Queue(maxsize=10)
        running_event = threading.Event()
        running_event.set()

        producer = threading.Thread(
            target=producer_thread,
            args=(cap, frame_queue, cipher_mode, running_event),
            name=f"Producer-{addr[1]}",
            daemon=True
        )
        producer.start()

        # Stream loop
        while SERVER_RUNNING:
            try:
                frame_nonce, encrypted_data = frame_queue.get(timeout=0.5)
                frame_queue.task_done()
            except queue.Empty:
                # Stop when producer is done and queue is empty
                if not producer.is_alive() and frame_queue.empty():
                    break
                continue

            send_start = time.monotonic()

            conn.sendall(frame_nonce)
            frame_size = len(encrypted_data)
            conn.sendall(frame_size.to_bytes(HEADER_SIZE, 'big'))
            conn.sendall(encrypted_data)

            send_time = time.monotonic() - send_start
            bytes_sent += nonce_size + HEADER_SIZE + frame_size
            frame_count += 1

            cpu_load, memory_usage = monitor_system_load(server_process)

            with METRICS_LOCK:
                SERVER_METRICS_LOG.append({
                    'client': f"{addr[0]}:{addr[1]}",
                    'frame': frame_count,
                    'send_time_ms': send_time * 1000,
                    'cpu': cpu_load,
                    'ram': memory_usage,
                    'frame_size_bytes': frame_size,
                    'cipher_mode': cipher_mode,
                })

            print(f"Client {addr} | Frame {frame_count} | Send: {send_time*1000:.3f}ms | CPU: {cpu_load:.1f}% | RAM: {memory_usage:.1f}MB")

        conn.sendall(b"STREAM_END")

        total_time = time.monotonic() - start_time
        throughput = (bytes_sent / total_time) * 8 / (1024 * 1024)
        print(f"\nClient {addr} stream finished. Time: {total_time:.4f}s | Throughput: {throughput:.2f} Mbps")

    except ConnectionResetError:
        print(f"Client {addr} disconnected unexpectedly.")
    except Exception as e:
        print(f"Error handling client {addr}: {e}")
    finally:
        conn.close()
        export_metrics_to_csv()
        print(f"Connection with {addr} closed.")

def shutdown_handler(signum, frame):
    global SERVER_RUNNING, SERVER_SOCKET
    print("\nInterrupt signal received. Shutting down...")
    SERVER_RUNNING = False
    if SERVER_SOCKET:
        try:
            SERVER_SOCKET.close()
        except Exception as e:
            print(f"Warning closing socket: {e}")

def start_server():
    global SERVER_SOCKET, CLIENT_THREADS, SERVER_RUNNING

    signal.signal(signal.SIGINT, shutdown_handler)

    if not os.path.exists(VIDEO_FILE):
        print(f"CRITICAL ERROR: Video file not found: {VIDEO_FILE}")
        return

    SERVER_SOCKET = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    SERVER_SOCKET.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        SERVER_SOCKET.bind((HOST, PORT))
        SERVER_SOCKET.listen(5)
        SERVER_SOCKET.settimeout(1)
        print(f"Server listening at {HOST}:{PORT}")
        print(f"Available ciphers: {AVAILABLE_CIPHERS}")

        while SERVER_RUNNING:
            try:
                conn, addr = SERVER_SOCKET.accept()
                client_handler = threading.Thread(
                    target=handle_client,
                    args=(conn, addr),
                    name=f"Client-{addr[1]}",
                    daemon=True
                )
                client_handler.start()
                CLIENT_THREADS.append(client_handler)
            except socket.timeout:
                continue
            except Exception as e:
                if SERVER_RUNNING:
                    print(f"Error in accept loop: {e}")
                break

    except Exception as e:
        print(f"Critical error during server init: {e}")
    finally:
        print("Main loop ended. Waiting for client threads...")
        for thread in CLIENT_THREADS:
            if thread.is_alive():
                thread.join(timeout=2)
        print("Server shut down.")

if __name__ == '__main__':
    start_server()