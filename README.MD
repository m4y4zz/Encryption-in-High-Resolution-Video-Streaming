## Encryption in High Resolution Video Streaming 🔐🎥

This project consists of a client-server infrastructure developed in Python for real-time streaming of high-resolution videos up to 4K. The system performs a frame-by-frame encryption on the server side, and decrypts each frame on the client side before showing it on the user interface. Both the client and the server measure different metrics, some are shown on their interfaces after the whole video has been reproduced, while others are exported on an .csv file. The main goal of this project was to make a comparative performance analysis among multiple cryptographic algorithms, AES, CHACHA20, SALSA20, Blowfish, and Camellia.

### Technologies

* *Language*: Python
* *Main Libraries*: OpenCV, PyCryptodome, Cryptography, Socket, Tkinter

### Implemented Algorithms

* *AES*
* *ChaCha20*
* *Salsa20*
* *Blowfish*
* *Camellia*
All of these algorithms used a 32 bytes key.

### Features

This project was developed to test the high-resolution video Big Bucket Bunny (bbb_sunflower_2160p_60fps_normal.mp4). However, due to its size, it is not included in this repository. To test the project, the video test_video.mp4 was included.


### How to Run the Project

1. Install dependencies: pip install opencv-python pycryptodome cryptography
2. Run the server: python server.py
3. Run the client: python client.py

### Performance Analysis and Results

The evaluated metrics were the CPU and RAM usage, Throughput, Latency and Frame Rate (FPS). ChaCha20 reached the highest throughput values for a different number of clients, and the lowest latency, which was a result that was anticipated. AES-256 was the most stable algorithm, proving it can be a plausible choice for these sytems.

### Preview

<div align="center">
  <video src="https://github.com/user-attachments/assets/0648af57-0f71-43d9-bfe4-e91acddb9539" width="100%" controls>
    O seu navegador não suporta a visualização de vídeos.
  </video>
</div>
