# fast-file-crypt

High-performance parallel file encryption and compression tool written in Python. Designed for processing large files with emphasis on speed through parallel processing.

## Features

- **Parallel Processing**: Utilizes all available CPU cores for maximum performance
- **Large File Support**: Efficiently handles files of any size through chunk-based processing
- **Fast Encryption**: Uses AES-CTR mode for high-speed encryption
- **Memory Efficient**: Processes files in chunks to maintain low memory footprint
- **User-Friendly GUI**: Simple graphical interface for easy operation
- **Progress Tracking**: Real-time progress monitoring and chunk processing status
- **Password Protection**: Secure file encryption with password protection

## Technical Details

- Chunk-based parallel processing (16MB chunks by default)
- AES-CTR mode encryption with unique nonce per chunk
- Level 1 zlib compression for optimal speed/compression ratio
- Asynchronous I/O operations for improved performance
- Process pool executor for true parallel processing
- Ordered chunk processing to maintain file integrity

## Requirements

```bash
Python 3.8+
pycryptodome
```

## Installation

1. Clone the repository:
```bash
git clone https://github.com/reiarseni/fast-file-crypt.git
cd fast-file-crypt
```

2. Install required packages:
```bash
pip install pycryptodome
```

## Usage

### Running the GUI Application

```bash
python fast_file_crypt.py
```

### GUI Operations

1. **Compress and Encrypt**:
   - Click "Select File"
   - Choose the file to process
   - Click "Compress and Encrypt"
   - Enter password when prompted
   - Wait for processing to complete
   - Output file will be saved with `.fcomp` extension

2. **Decompress and Decrypt**:
   - Click "Select File"
   - Choose the `.fcomp` file
   - Click "Decompress and Decrypt"
   - Enter the original password
   - Wait for processing to complete

## Performance

Performance varies based on:
- Number of CPU cores available
- Storage device speed (SSD vs HDD)
- File size
- Available RAM

Typical performance improvements over single-threaded processing:
- 2-4x faster on quad-core systems
- 4-8x faster on octa-core systems
- Best performance with files larger than 100MB

## Implementation Details

The tool uses a pipeline architecture:
1. File splitting into chunks
2. Parallel compression of chunks
3. Parallel encryption of compressed chunks
4. Ordered chunk reassembly
5. Asynchronous file writing

### Process Flow
```
Input File → Chunk Division → Parallel Processing Pool → Ordered Reassembly → Output File
                                ↳ Compression
                                ↳ Encryption
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Built using Python's multiprocessing capabilities
- Uses pycryptodome for AES encryption
- Inspired by the need for fast, parallel file processing

## Security Note

This tool prioritizes speed over maximum security. While it uses standard AES encryption, it:
- Uses faster but less secure encryption modes
- Minimizes encryption rounds for performance
- May be vulnerable to certain cryptographic attacks

Not recommended for highly sensitive data requiring maximum security.
