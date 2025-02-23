import tkinter as tk
from tkinter import filedialog, ttk, simpledialog
import os
import threading
import zlib
import struct
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hashlib
from concurrent.futures import ThreadPoolExecutor
import queue
import math


class FastCompressor:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("Fast Compressor and Encryptor")
        self.window.geometry("425x400")

        # Configure interface
        self.setup_ui()

        # Increased buffer size for better speed
        self.BUFFER_SIZE = 4 * 1024 * 1024  # 4MB buffer
        # Number of parallel workers, handle os.cpu_count() returning None
        self.MAX_WORKERS = max(4, os.cpu_count() or 1)

    def setup_ui(self):
        # Main frame
        main_frame = ttk.Frame(self.window, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Buttons
        ttk.Button(main_frame, text="Select File", command=self.select_file).grid(row=0, column=0, pady=5)
        ttk.Button(main_frame, text="Compress and Encrypt", command=self.start_compression).grid(row=1, column=0, pady=5)
        ttk.Button(main_frame, text="Decompress and Decrypt", command=self.start_decompression).grid(row=2, column=0, pady=5)

        # Progress bar
        self.progress = ttk.Progressbar(main_frame, length=400, mode='determinate')
        self.progress.grid(row=3, column=0, pady=10)

        # Status label
        self.status_label = ttk.Label(main_frame, text="")
        self.status_label.grid(row=4, column=0, pady=5)

        # Processed files list
        self.log_text = tk.Text(main_frame, height=10, width=50)
        self.log_text.grid(row=5, column=0, pady=5)

    def get_password(self):
        password = simpledialog.askstring("Password", "Enter password:", show='*')
        if password is None:
            return None
        # Convert password to 32-byte (256-bit) key using SHA256
        return hashlib.sha256(password.encode()).digest()

    def select_file(self):
        self.filename = filedialog.askopenfilename()
        if self.filename:
            self.log_message(f"Selected file: {self.filename}")

    def process_chunk(self, chunk, cipher, compressor):
        """Process a single chunk with compression and encryption"""
        compressed = compressor.compress(chunk)
        flushed = compressor.flush()  # finish compression for this chunk
        return cipher.encrypt(compressed + flushed)

    def process_chunk_decrypt(self, chunk, cipher, decompressor):
        """Process a single chunk with decryption and decompression"""
        decrypted = cipher.decrypt(chunk)
        decompressed = decompressor.decompress(decrypted)
        flushed = decompressor.flush()
        return decompressed + flushed

    def compress_and_encrypt(self, input_path, output_path, key):
        try:
            filesize = os.path.getsize(input_path)
            bytes_processed = 0

            # Generate random nonce for CTR mode
            nonce = get_random_bytes(8)
            # Create cipher in CTR mode (Counter mode - very fast and parallelizable)
            # Note: The initial cipher instance below is only used for writing nonce based flush data previously.
            cipher = AES.new(key, AES.MODE_CTR, nonce=nonce, initial_value=0)

            with open(input_path, 'rb') as infile, open(output_path, 'wb') as outfile:
                # Write nonce and timestamp
                outfile.write(nonce)
                timestamp = int(datetime.now().timestamp())
                outfile.write(struct.pack('<Q', timestamp))

                # Calculate optimal chunk size and number of chunks
                total_chunks = math.ceil(filesize / self.BUFFER_SIZE)

                with ThreadPoolExecutor(max_workers=self.MAX_WORKERS) as executor:
                    futures = []
                    chunk_index = 0

                    # Submit chunks for parallel processing
                    while True:
                        chunk = infile.read(self.BUFFER_SIZE)
                        if not chunk:
                            break

                        compressor_obj = zlib.compressobj(level=1)  # Level 1 for maximum speed
                        future = executor.submit(
                            self.process_chunk,
                            chunk,
                            AES.new(key, AES.MODE_CTR, nonce=nonce, initial_value=chunk_index),
                            compressor_obj
                        )
                        futures.append((chunk_index, future))
                        chunk_index += 1

                    # Process results in order and write length-prefixed blocks
                    for chunk_idx, future in futures:
                        result = future.result()
                        # Write 4-byte length prefix for the encrypted block
                        outfile.write(struct.pack('<I', len(result)))
                        outfile.write(result)

                        bytes_processed += self.BUFFER_SIZE
                        progress = min(100, (infile.tell() / filesize) * 100)
                        self.update_progress(progress)

            return True
        except Exception as e:
            self.log_message(f"Error during process: {str(e)}")
            return False

    def decrypt_and_decompress(self, input_path, output_path, key):
        try:
            filesize = os.path.getsize(input_path)

            with open(input_path, 'rb') as infile, open(output_path, 'wb') as outfile:
                # Read nonce
                nonce = infile.read(8)
                # Skip timestamp
                infile.read(8)

                with ThreadPoolExecutor(max_workers=self.MAX_WORKERS) as executor:
                    futures = []
                    chunk_index = 0

                    while True:
                        # Read 4-byte length prefix
                        length_bytes = infile.read(4)
                        if not length_bytes or len(length_bytes) < 4:
                            break
                        block_length = struct.unpack('<I', length_bytes)[0]
                        block_data = infile.read(block_length)
                        if len(block_data) < block_length:
                            break

                        decompressor = zlib.decompressobj()
                        future = executor.submit(
                            self.process_chunk_decrypt,
                            block_data,
                            AES.new(key, AES.MODE_CTR, nonce=nonce, initial_value=chunk_index),
                            decompressor
                        )
                        futures.append(future)
                        chunk_index += 1

                    # Process results in order
                    for future in futures:
                        result = future.result()
                        outfile.write(result)
                        progress = min(100, (infile.tell() / filesize) * 100)
                        self.update_progress(progress)

            return True
        except Exception as e:
            self.log_message(f"Error during process: {str(e)}")
            return False

    def start_compression(self):
        if not hasattr(self, 'filename'):
            self.log_message("Please select a file first")
            return

        key = self.get_password()
        if not key:
            self.log_message("Process cancelled")
            return

        output_path = self.filename + '.fcomp'

        def compress_thread():
            self.status_label.config(text="Compressing and encrypting...")
            success = self.compress_and_encrypt(self.filename, output_path, key)
            if success:
                self.log_message(f"Process completed: {output_path}")
            self.status_label.config(text="Ready")

        threading.Thread(target=compress_thread).start()

    def start_decompression(self):
        input_path = filedialog.askopenfilename(filetypes=[("Compressed files", "*.fcomp")])
        if not input_path:
            return

        key = self.get_password()
        if not key:
            self.log_message("Process cancelled")
            return

        output_path = input_path[:-6]  # Remove .fcomp extension

        def decompress_thread():
            self.status_label.config(text="Decrypting and decompressing...")
            success = self.decrypt_and_decompress(input_path, output_path, key)
            if success:
                self.log_message(f"Process completed: {output_path}")
            self.status_label.config(text="Ready")

        threading.Thread(target=decompress_thread).start()

    def update_progress(self, value):
        def _update():
            self.progress['value'] = value
        self.window.after(0, _update)

    def log_message(self, message):
        def _log():
            self.log_text.insert(tk.END, f"{message}\n")
            self.log_text.see(tk.END)
        self.window.after(0, _log)

    def run(self):
        self.window.mainloop()


if __name__ == "__main__":
    app = FastCompressor()
    app.run()
