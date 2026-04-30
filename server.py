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
#########################
#VIDEO_FILE = 'bbb_sunflower_2160p_60fps_normal.mp4' 
VIDEO_FILE = 'test_video.mp4'
#########################

# Choose the key size and nonce values that correspond to the cipher that will be tested, confirm Table I. on the readme file.
#########################
#NONCE_SIZE=8
#NONCE_SIZE=12
NONCE_SIZE = 16

KEY_SIZE = 16
#KEY_SIZE = 32
#########################

GLOBAL_KEY = token_bytes(KEY_SIZE)
SERVER_RUNNING = True
CLIENT_THREADS = []
SERVER_SOCKET = None

HEADER_SIZE = 8
AVAILABLE_CIPHERS = ["AES-128-CTR-MAN", "AES-CTR-LIB", "CHACHA20-LIB", "SALSA20-LIB", "BLOWFISH-LIB", "CAMELLIA-LIB"]
FRAME_QUEUE = queue.Queue(maxsize=10)

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

def handle_client_consumer(conn: socket.socket, addr):
    global SERVER_RUNNING
    print(f"[*] Connection Accepted from {addr}")
    
    bytes_sent = 0
    start_time = time.monotonic()
    frame_count = 0
    server_process = psutil.Process(os.getpid())
    
    try:
        mode_choice = conn.recv(1024).decode('utf-8').strip() 
        if mode_choice not in AVAILABLE_CIPHERS:
            conn.sendall(b"ERROR: Invalid Mode")
            raise ValueError(f"Client requested an invalid mode: {mode_choice}")
            
        print(f" | Client {addr} selected cipher: {mode_choice}")

        conn.sendall(b"KEY_START")
        time.sleep(0.01) 
        conn.sendall(GLOBAL_KEY)
        print(f" | Client {addr}: Key was sent. Starting...")
        
        fps = 60.0 
        conn.sendall(f"STREAM_START:{fps}".encode('utf-8'))
        time.sleep(0.01)

        while SERVER_RUNNING:
            
            try:
                frame_nonce, encrypted_data = FRAME_QUEUE.get(timeout=0.5) 
                FRAME_QUEUE.task_done() 
            
            except queue.Empty:
                if not PRODUCER_THREAD.is_alive() and FRAME_QUEUE.empty(): 
                    break
                continue
            
            frame_encrypt_start = time.monotonic() 
            
            conn.sendall(frame_nonce)
            frame_size = len(encrypted_data)
            size_header = frame_size.to_bytes(HEADER_SIZE, 'big') 
            
            conn.sendall(size_header)  
            conn.sendall(encrypted_data)
            
            frame_encrypt_time = time.monotonic() - frame_encrypt_start 
            bytes_sent += len(frame_nonce) + len(size_header) + frame_size
            frame_count += 1
            cpu_load, memory_usage = monitor_system_load(server_process)
            frame_io_start = time.monotonic()
            frame_io_time = time.monotonic() - frame_io_start
            with METRICS_LOCK:
                SERVER_METRICS_LOG.append({
                    'client': f"{addr[0]}:{addr[1]}",
                    'frame': frame_count,
                    'io_time_ms': frame_io_time * 1000,
                    'cpu': cpu_load,
                    'ram': memory_usage,
                    'frame_size_bytes': frame_size,
                    'cipher_mode': mode_choice
                })
            
            print(f" | Client {addr} | Frame {frame_count} | Sending I/O: {frame_encrypt_time*1000:.3f}ms | CPU: {cpu_load:.1f}% | RAM: {memory_usage:.1f}MB")
            
        conn.sendall(b"STREAM_END")
        
        total_time = time.monotonic() - start_time
        throughput = (bytes_sent / total_time) * 8 / (1024 * 1024) 
        
        print(f"\n[+] Client {addr} Stream Finished. Total Time: {total_time:.4f}s")
        print(f"[+] Client {addr} Throughput (Total): {throughput:.2f} Mbps")

    except ConnectionResetError:
        print(f"[*] Client {addr} desconected.")
    except Exception as e:
        print(f"[*] Error in client thread {addr}: {e}")
    finally:
        conn.close()
        export_metrics_to_csv()
        print(f"[*] Connection with {addr} closed.")

def producer_thread(cap: cv2.VideoCapture):
    
    global SERVER_RUNNING, FRAME_SENT_COUNT
    
    fps = cap.get(cv2.CAP_PROP_FPS)
    sleep_time = 1 / fps if fps > 0 else 1 / 30 
    total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
    FRAME_SENT_COUNT=total_frames
    encode_param = [int(cv2.IMWRITE_JPEG_QUALITY), 90]
    server_process = psutil.Process(os.getpid())
    
    print(f"\n[PRODUCER] Production thread started. Target FPS: {fps:.2f}. Total Frames: {total_frames}")

    try:
        while SERVER_RUNNING and cap.isOpened():
            frame_start = time.monotonic()
            ret, frame = cap.read() 
            
            if not ret:
                print("[PRODUCER] End of video source/camera. Stoping the producer..")
                SERVER_RUNNING = False
                break

            _, encoded_frame = cv2.imencode('.jpg', frame, encode_param)
            frame_data = encoded_frame.tobytes()
            
            frame_nonce = os.urandom(NONCE_SIZE)
            
            # Remove the # from the line corresponding to the cipher you want to test, and leave the others commented out.
            
            #cipher_mode="AES-128-CTR-MAN"
            cipher_mode="AES-CTR-LIB"
            #cipher_mode= "CHACHA20-LIB"
            #cipher_mode= "SALSA20-LIB" 
            #cipher_mode ="BLOWFISH-LIB"    
            #cipher_mode="CAMELLIA-LIB"
            encrypted_data = encrypt.encrypt_dataA(GLOBAL_KEY, frame_data, cipher_mode, frame_nonce) 
            
            try:
                
                FRAME_QUEUE.put((frame_nonce, encrypted_data), timeout=0.01) 
                FRAME_SENT_COUNT += 1
            except queue.Full:
                pass 
            
            time_spent = time.monotonic() - frame_start
            wait_time = sleep_time - time_spent
            if wait_time > 0:
                time.sleep(wait_time)
            
            if FRAME_SENT_COUNT % 50 == 0:
                 cpu_load, memory_usage = monitor_system_load(server_process)
                 print(f" | [PRODUCER] Encripted Frames: {FRAME_SENT_COUNT} | Queue: {FRAME_QUEUE.qsize()}/{FRAME_QUEUE.maxsize} | CPU: {cpu_load:.1f}% | RAM: {memory_usage:.1f}MB")

    except Exception as e:
        print(f"[PRODUCER] Exception in the Producer thread: {e}")
        SERVER_RUNNING = False
    finally:
        cap.release()
        print("[PRODUCER] Production thread closed.")

def shutdown_handler(signum, frame):
    
    global SERVER_RUNNING
    global SERVER_SOCKET
    
    print("\n[!] Interrupt signal received. Initiating controlled shutdown....")
    SERVER_RUNNING = False
    
    if SERVER_SOCKET:
        try:
            SERVER_SOCKET.close() 
            print("[!] Closed listening socket.")
        except Exception as e:
            print(f"[!] Warning: Error closing socket: {e}")

def start_server():
    
    global SERVER_SOCKET
    global CLIENT_THREADS
    global PRODUCER_THREAD
    global SERVER_RUNNING
    
    signal.signal(signal.SIGINT, shutdown_handler)

    cap = cv2.VideoCapture(VIDEO_FILE)
    if not cap.isOpened():
        print(f"CRITICAL ERROR: Could not open video source. ({VIDEO_FILE}).")
        if not os.path.exists(VIDEO_FILE):
             print(f"PLEASE NOTE: The file {VIDEO_FILE} was not found.")
        return

    PRODUCER_THREAD = threading.Thread(target=producer_thread, args=(cap,), name="ProducerThread")
    PRODUCER_THREAD.daemon = True 
    PRODUCER_THREAD.start()

    SERVER_SOCKET = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    SERVER_SOCKET.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)    
    
    try:
        SERVER_SOCKET.bind((HOST, PORT))
        SERVER_SOCKET.listen(5)
        SERVER_SOCKET.settimeout(1) 
        print(f"[*] Server listening at {HOST}:{PORT}. Producer active.")

        while SERVER_RUNNING:
            try:
                conn, addr = SERVER_SOCKET.accept()
                
                client_handler = threading.Thread(target=handle_client_consumer, args=(conn, addr), name=f"Consumer-{addr[1]}")
                client_handler.daemon = True
                client_handler.start()
                CLIENT_THREADS.append(client_handler)
                
            except socket.timeout:
                continue
            except Exception as e:
                if SERVER_RUNNING:
                    print(f"[-] Unexpected error in main loop (accept): {e}")
                break    

    except Exception as e:
        print(f"Critical error during server initialization.: {e}")
    finally:
        print("[*] Main loop terminated. Waiting for threads to finish..")
        
        if PRODUCER_THREAD and PRODUCER_THREAD.is_alive():
            SERVER_RUNNING = False
            PRODUCER_THREAD.join(timeout=5)
            
        for thread in CLIENT_THREADS:
             if thread.is_alive():
                 thread.join(timeout=2) 
        
        print("[*] Server closed successfully..")

if __name__ == '__main__':

    start_server()