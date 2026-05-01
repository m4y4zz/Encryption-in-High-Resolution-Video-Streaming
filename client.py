import socket
import threading
import time
import tkinter as tk
from tkinter import ttk, messagebox
from PIL import Image, ImageTk
import cv2 
import numpy as np
import queue
import io
import sys
import psutil
import os
import encrypt 
import csv
from datetime import datetime

HOST = '127.0.0.1'
PORT = 65432
BUFFER_SIZE = 4096
CLIENT_SOCKET = None
AVAILABLE_CIPHERS = ["AES-CTR-LIB", "CHACHA20-LIB", "SALSA20-LIB", "BLOWFISH-LIB", "CAMELLIA-LIB"]

FRAME_QUEUE = queue.Queue(maxsize=30) 
FRAME_SENT_COUNT = 0 
DECRYPT_THREAD = None
RECEIVE_THREAD = None

CLIENT_METRICS_LOG = []
METRICS_LOCK = threading.Lock()

class StreamState:
    def __init__(self):
        self.key = None
        self.nonce = None
        self.cipher_mode = None
        self.is_streaming = False
        self.total_bytes_received = 0
        self.start_time = None
        self.last_valid_imgtk = None 
        self.consumer_is_running = False
        self.frame_count = 0
        self.fps = 0

STATE = StreamState()
perf_label = None
root = None

def monitor_system_load(process):
    cpu_percent = process.cpu_percent(interval=None)
    memory_info = process.memory_info()
    return cpu_percent, memory_info.rss / (1024 * 1024) 
 
def export_client_metrics():
    with METRICS_LOCK:
        if not CLIENT_METRICS_LOG:
            print("[METRIC] No client data to export.FEWFWEGRE")
            return
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"client_metrics_{timestamp}.csv"
        
        try:
            keys = CLIENT_METRICS_LOG[0].keys()
            with open(filename, 'w', newline='') as f:
                dict_writer = csv.DictWriter(f, fieldnames=keys)
                dict_writer.writeheader()
                dict_writer.writerows(CLIENT_METRICS_LOG)
            print(f"\n[OK] Client Metrics Saved: {filename}")
        except Exception as e:
            print(f"[METRIC] Failed to save client CSV: {e}")
  
def receive_all(sock, n):
    data = b''
    sock.settimeout(60) 
    try:
        while len(data) < n:
            packet = sock.recv(n - len(data))
            if not packet:
                return None
            data += packet
    except socket.timeout:
        if not STATE.is_streaming:
            return None
        pass 
    except ConnectionAbortedError:
        return None
    return data

def update_ui_performance(total_time):
    global STATE
    global perf_label 
    
    perf_label = tk.Label(root, 
                          text="Waiting for stream to start...", 
                          fg="darkgreen", 
                          font=('Arial', 10), 
                          justify=tk.LEFT)
    perf_label.pack(pady=10, padx=10, fill=tk.X)
    
    if total_time > 0 and STATE.total_bytes_received > 0:
        throughput = (STATE.total_bytes_received / total_time) * 8 / (1024 * 1024) 
        
        latency_str = "N/A"
        if STATE.start_time:
             latency = time.monotonic() - STATE.start_time
             latency_str = f"{latency*1000:.2f}ms"
             
        metrics_text = (
            f"Stream ended successfully.\n"
            f"Cipher: {STATE.cipher_mode}\n"
            f"Average Throughput: {throughput:.2f} Mbps\n"
            f"Latency: {latency_str}\n"
            f"Total Recieved: {STATE.total_bytes_received} bytes in {total_time:.2f}s"
        )
        perf_label.config(text=metrics_text)
        
    else:
        perf_label.config(text="Stream Finished. Insufficient data for metrics.")
        
    start_button.config(state=tk.NORMAL, text="WATCH VIDEO")
    stop_button.config(state=tk.DISABLED)
        
    video_label.config(image='', text="Waiting for stream to start...", background='black', foreground='white')
    STATE.last_valid_imgtk = None
    STATE.start_time = None

def start_stream_client(selected_cipher_mode):
    global STATE
    global RECEIVE_THREAD
    global DECRYPT_THREAD
    global CLIENT_SOCKET
    global root
    if STATE.is_streaming:
        return

    while not FRAME_QUEUE.empty():
        try:
            FRAME_QUEUE.get_nowait()
        except queue.Empty:
            pass

    STATE = StreamState()
    STATE.cipher_mode = selected_cipher_mode
    STATE.is_streaming = True
    STATE.frame_count = 0
    
    start_button.config(state=tk.DISABLED, text="CONNECTING...")
    stop_button.config(state=tk.NORMAL)
    video_label.config(image='', text="Waiting for stream to start...", background='black', foreground='white')
    
    RECEIVE_THREAD = threading.Thread(target=receive_thread, args=(selected_cipher_mode,), name="ClientReceiveThread")
    RECEIVE_THREAD.daemon = True
    RECEIVE_THREAD.start()
    
    DECRYPT_THREAD = threading.Thread(target=decrypt_and_display_thread, name="ClientDecryptThread")
    DECRYPT_THREAD.daemon = True
    DECRYPT_THREAD.start()

    root.after(100, check_threads_status)

def receive_thread(selected_cipher_mode):
    
    global CLIENT_SOCKET
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    CLIENT_SOCKET = s
    
    conf = encrypt.CIPHER_CONFIG.get(selected_cipher_mode)
    nonce_len = conf['NONCE_SIZE']

    try:
        s.connect((HOST, PORT))
        
        s.sendall(selected_cipher_mode.encode('utf-8'))

        header = s.recv(BUFFER_SIZE).decode('utf-8')
        if not header.startswith("KEY_START"):
            root.after(0, lambda: messagebox.showerror("Error", "Error receiving KEY_START."))
            STATE.is_streaming = False
            return
            
        key_iv = receive_all(s, 32) 
        if key_iv is None or len(key_iv) != 32: 
            root.after(0, lambda: messagebox.showerror("Error", "Failed to receive the key."))
            STATE.is_streaming = False
            return
            
        STATE.key = key_iv
        stream_header = s.recv(BUFFER_SIZE).decode('utf-8')
        if not stream_header.startswith("STREAM_START"):
            root.after(0, lambda: messagebox.showerror("Error", "Error in the stream header."))
            STATE.is_streaming = False
            return
            
        STATE.fps = float(stream_header.split(':')[-1])
        print(f"Stream started. Expected FPS: {STATE.fps}")
        
        STATE.start_time = time.monotonic() 
        STATE.cipher_mode = selected_cipher_mode
        
        while STATE.is_streaming:
            frame_nonce = receive_all(s, nonce_len)
            if frame_nonce is None:
                break
                
            if not frame_nonce or b"STREAM_END" in frame_nonce:
                print("The video ended, closing...")
                break
                
            size_header = receive_all(s, 8)
            if size_header is None:
                break
                
            if size_header[:4] == b"STRE": 
                break 
                
            frame_size = int.from_bytes(size_header, 'big')
            
            encrypted_data = receive_all(s, frame_size)
            if encrypted_data is None:
                break

            STATE.total_bytes_received += nonce_len + 8 + frame_size 
            try:
                FRAME_QUEUE.put((frame_nonce, encrypted_data), timeout=0.001) 
            except queue.Full:
                pass 
            
            
            if STATE.frame_count % 50 == 0 and STATE.consumer_is_running:
                print(f"[PRODUCER] Frames in the Queue: {FRAME_QUEUE.qsize()}/{FRAME_QUEUE.maxsize} | Bytes Recieved: {STATE.total_bytes_received}")

        cv2.destroyAllWindows() 
        export_client_metrics()

    except ConnectionRefusedError:
        root.after(0, lambda: messagebox.showerror("Connection Error", "Unable to connect to the server."))
    except ConnectionAbortedError:
        print("Connection aborted (clean terminate).")
    except Exception as e:
        if STATE.is_streaming:
            root.after(0, lambda err=e: messagebox.showerror("Stream Error", f"Error in the receiving thread: {err}"))
    finally:
        if s is CLIENT_SOCKET:
            try:
                s.close()
            except Exception:
                pass
            CLIENT_SOCKET = None
            
        STATE.is_streaming = False
        print("The reception thread has been closed.")

def decrypt_and_display_thread():
    
    global STATE
    server_process = psutil.Process(os.getpid())
    STATE.consumer_is_running = True
    
    try:
        while STATE.is_streaming or not FRAME_QUEUE.empty():
            
            try:
                frame_nonce, encrypted_data = FRAME_QUEUE.get(timeout=0.1) 
                FRAME_QUEUE.task_done()
            except queue.Empty:
                if not STATE.is_streaming:
                    break
                continue

            frame_decrypt_start = time.monotonic()
            
            decrypted_data = encrypt.decrypt_dataA(STATE.key, encrypted_data, STATE.cipher_mode, frame_nonce)
            
            frame_decrypt_time = time.monotonic() - frame_decrypt_start
            
            try:
                np_array = np.frombuffer(decrypted_data, dtype=np.uint8)
                frame = cv2.imdecode(np_array, cv2.IMREAD_COLOR)

                if frame is not None:
                    cv2image = cv2.cvtColor(frame, cv2.COLOR_BGR2RGBA)
                    img = Image.fromarray(cv2image)
                    
                    img = img.resize((video_label.winfo_width(), video_label.winfo_height())) 
                    
                    imgtk = ImageTk.PhotoImage(image=img)
                    
                    def update_gui():
                        STATE.last_valid_imgtk = imgtk 
                        video_label.imgtk = imgtk
                        video_label.config(image=imgtk, text="")
                        
                        STATE.frame_count += 1
                        
                        cpu_load, memory_usage = monitor_system_load(server_process)
                        print(f"Frame {STATE.frame_count} | Decrypts: {frame_decrypt_time*1000:.3f}ms | CPU: {cpu_load:.1f}% | RAM: {memory_usage:.1f}MB | Queue: {FRAME_QUEUE.qsize()}")
                        
                        
                        with METRICS_LOCK:
                            CLIENT_METRICS_LOG.append({
                            'frame': STATE.frame_count,
                            'decrypts': frame_decrypt_time*1000,
                            'cpu': cpu_load,
                            'ram_mb': memory_usage,
                        })
                    root.after(0, update_gui)
                    
                
            except Exception as e:
                if STATE.last_valid_imgtk:
                     root.after(0, lambda: video_label.config(image=STATE.last_valid_imgtk, text=""))
                pass
                
            

    except Exception as e:
        print(f"[ERROR] Exception in the Consumer thread: {e}")
    finally:
        STATE.consumer_is_running = False
        print("Decrypting and Exhibiting Thread closed.")

def stop_stream_client():
    global STATE
    global CLIENT_SOCKET

    if not STATE.is_streaming:
        return
    
    STATE.is_streaming = False
    print("\nInitiating controlled shutdown of the stream...")
    
    if CLIENT_SOCKET:
        try:
            CLIENT_SOCKET.close()
            print("Client socket closed.")
        except Exception as e:
            print(f"Warning: Error closing socket: {e}") 
        CLIENT_SOCKET = None
        
    stop_button.config(state=tk.DISABLED)
    start_button.config(state=tk.DISABLED, text="AWAITING CLOSURE...")
    
    check_threads_status()

def check_threads_status():
    
    global RECEIVE_THREAD
    global DECRYPT_THREAD
    
    if STATE.is_streaming:
        root.after(100, check_threads_status)
    elif RECEIVE_THREAD and RECEIVE_THREAD.is_alive():
        root.after(100, check_threads_status)
    elif DECRYPT_THREAD and DECRYPT_THREAD.is_alive():
        root.after(100, check_threads_status)
    else:
        total_time = time.monotonic() - (STATE.start_time if STATE.start_time else time.monotonic())
        update_ui_performance(total_time)
        print("All threads closed. UI updated.")
        
# ----------------------------------------------------------------------
# GUI SETUP (Tkinter)
# ----------------------------------------------------------------------

root = tk.Tk()
root.title("Stream Decryptor")
root.geometry("800x650")
root.resizable(False, False)

perf_label = tk.Label(root, 
                          text="Waiting for stream to start...", 
                          fg="darkgreen", 
                          font=('Arial', 10), 
                          justify=tk.LEFT)
perf_label.pack(pady=10, padx=10, fill=tk.X)

# Control Panel
control_frame = ttk.Frame(root, padding="10")
control_frame.pack(fill='x')

ttk.Label(control_frame, text="Cipher:", font=('Arial', 10, 'bold')).pack(side=tk.LEFT, padx=5)

# Cipher Dropdown
selected_cipher = tk.StringVar(root)

try:
    if 'encrypt' in sys.modules and hasattr(encrypt, 'AVAILABLE_CIPHERS'):
        selected_cipher.set(encrypt.AVAILABLE_CIPHERS[0])
        cipher_options = encrypt.AVAILABLE_CIPHERS
    else:
        selected_cipher.set("Error Loading Cipher")
        cipher_options = ["Error Loading Cipher"]
except Exception:
    selected_cipher.set("Error Loading Cipher")
    cipher_options = ["Error Loading Cipher"]


cipher_menu = ttk.OptionMenu(control_frame, selected_cipher, selected_cipher.get(), *cipher_options)
cipher_menu.pack(side=tk.LEFT, padx=5, fill='x', expand=True)

# Start/Stop Button
start_button = ttk.Button(control_frame, text="WATCH VIDEO", 
                          command=lambda: start_stream_client(selected_cipher.get()))
start_button.pack(side=tk.LEFT, padx=10, fill='x', expand=True)

stop_button = ttk.Button(control_frame, text="END STREAM", 
                         command=stop_stream_client, state=tk.DISABLED)
stop_button.pack(side=tk.LEFT, padx=10, fill='x', expand=True)

# Visualization Panel
video_frame = ttk.Frame(root, padding="10")
video_frame.pack(fill='both', expand=True)

# Video Label (Where the video will be displayed)
video_label = ttk.Label(video_frame, text="Waiting for stream to start...", background='black', foreground='white')
video_label.pack(fill='both', expand=True)


# Metrics Dashboard (Performance)
metric_frame = ttk.Frame(root, padding="10")
metric_frame.pack(fill='x')


# Window closure 
def on_closing():
    stop_stream_client()
    root.destroy()

root.protocol("WM_DELETE_WINDOW", on_closing)

if __name__ == '__main__':
    client_process = psutil.Process(os.getpid()) 
    root.mainloop()