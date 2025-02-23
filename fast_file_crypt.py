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


class FastCompressor:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("Compresor y Encriptador Ultra Rápido")
        self.window.geometry("425x400")

        # Configuración de la interfaz
        self.setup_ui()

        # Aumentamos el tamaño del buffer para mayor velocidad
        self.BUFFER_SIZE = 4 * 1024 * 1024  # 4MB buffer

    def setup_ui(self):
        # Frame principal
        main_frame = ttk.Frame(self.window, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Botones
        ttk.Button(main_frame, text="Seleccionar Archivo", command=self.select_file).grid(row=0, column=0, pady=5)
        ttk.Button(main_frame, text="Comprimir y Encriptar", command=self.start_compression).grid(row=1, column=0,
                                                                                                  pady=5)
        ttk.Button(main_frame, text="Descomprimir y Desencriptar", command=self.start_decompression).grid(row=2,
                                                                                                          column=0,
                                                                                                          pady=5)

        # Barra de progreso
        self.progress = ttk.Progressbar(main_frame, length=400, mode='determinate')
        self.progress.grid(row=3, column=0, pady=10)

        # Etiqueta de estado
        self.status_label = ttk.Label(main_frame, text="")
        self.status_label.grid(row=4, column=0, pady=5)

        # Lista de archivos procesados
        self.log_text = tk.Text(main_frame, height=10, width=50)
        self.log_text.grid(row=5, column=0, pady=5)

    def get_password(self):
        password = simpledialog.askstring("Contraseña", "Introduce la contraseña:", show='*')
        if password is None:
            return None
        # Convertir contraseña a una llave de 32 bytes (256 bits) usando SHA256
        return hashlib.sha256(password.encode()).digest()

    def select_file(self):
        self.filename = filedialog.askopenfilename()
        if self.filename:
            self.log_message(f"Archivo seleccionado: {self.filename}")

    def compress_and_encrypt(self, input_path, output_path, key):
        try:
            filesize = os.path.getsize(input_path)
            bytes_processed = 0

            # Generar nonce aleatorio para CTR mode
            nonce = get_random_bytes(8)
            # Crear cipher en modo CTR (Counter mode - muy rápido y paralelizable)
            cipher = AES.new(key, AES.MODE_CTR, nonce=nonce, initial_value=0)

            with open(input_path, 'rb') as infile, open(output_path, 'wb') as outfile:
                # Escribir nonce y timestamp
                outfile.write(nonce)
                timestamp = int(datetime.now().timestamp())
                outfile.write(struct.pack('<Q', timestamp))

                # Comprimir y encriptar en chunks grandes
                compressor = zlib.compressobj(level=1)  # Nivel 1 para máxima velocidad

                while True:
                    chunk = infile.read(self.BUFFER_SIZE)
                    if not chunk:
                        break

                    # Comprimir y encriptar en un solo paso
                    compressed = compressor.compress(chunk)
                    if compressed:
                        encrypted = cipher.encrypt(compressed)
                        outfile.write(encrypted)

                    bytes_processed += len(chunk)
                    progress = (bytes_processed / filesize) * 100
                    self.update_progress(progress)

                # Procesar datos restantes
                compressed = compressor.flush()
                if compressed:
                    encrypted = cipher.encrypt(compressed)
                    outfile.write(encrypted)

            return True
        except Exception as e:
            self.log_message(f"Error durante el proceso: {str(e)}")
            return False

    def decrypt_and_decompress(self, input_path, output_path, key):
        try:
            filesize = os.path.getsize(input_path)
            bytes_processed = 0

            with open(input_path, 'rb') as infile, open(output_path, 'wb') as outfile:
                # Leer nonce
                nonce = infile.read(8)
                # Crear cipher en modo CTR
                cipher = AES.new(key, AES.MODE_CTR, nonce=nonce, initial_value=0)

                # Saltar el timestamp
                infile.read(8)

                # Desencriptar y descomprimir
                decompressor = zlib.decompressobj()

                while True:
                    chunk = infile.read(self.BUFFER_SIZE)
                    if not chunk:
                        break

                    # Desencriptar y descomprimir en un solo paso
                    decrypted = cipher.decrypt(chunk)
                    decompressed = decompressor.decompress(decrypted)
                    outfile.write(decompressed)

                    bytes_processed += len(chunk)
                    progress = (bytes_processed / filesize) * 100
                    self.update_progress(progress)

                # Procesar datos restantes
                outfile.write(decompressor.flush())

            return True
        except Exception as e:
            self.log_message(f"Error durante el proceso: {str(e)}")
            return False

    def start_compression(self):
        if not hasattr(self, 'filename'):
            self.log_message("Por favor selecciona un archivo primero")
            return

        key = self.get_password()
        if not key:
            self.log_message("Proceso cancelado")
            return

        output_path = self.filename + '.fcomp'

        def compress_thread():
            self.status_label.config(text="Comprimiendo y encriptando...")
            success = self.compress_and_encrypt(self.filename, output_path, key)
            if success:
                self.log_message(f"Proceso completado: {output_path}")
            self.status_label.config(text="Listo")

        threading.Thread(target=compress_thread).start()

    def start_decompression(self):
        input_path = filedialog.askopenfilename(filetypes=[("Archivos comprimidos", "*.fcomp")])
        if not input_path:
            return

        key = self.get_password()
        if not key:
            self.log_message("Proceso cancelado")
            return

        output_path = input_path[:-6]  # Remover la extensión .fcomp

        def decompress_thread():
            self.status_label.config(text="Desencriptando y descomprimiendo...")
            success = self.decrypt_and_decompress(input_path, output_path, key)
            if success:
                self.log_message(f"Proceso completado: {output_path}")
            self.status_label.config(text="Listo")

        threading.Thread(target=decompress_thread).start()

    def update_progress(self, value):
        self.progress['value'] = value
        self.window.update_idletasks()

    def log_message(self, message):
        self.log_text.insert(tk.END, f"{message}\n")
        self.log_text.see(tk.END)

    def run(self):
        self.window.mainloop()


if __name__ == "__main__":
    app = FastCompressor()
    app.run()