# Contributing

Contributions are welcome. Please follow these guidelines.

## Getting Started

1. Fork the repository
2. Clone your fork
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   pip install -r requirements-dev.txt
   ```
4. Create a feature branch: `git checkout -b feature/your-feature`

## Development

Run the application:
```bash
# GUI mode
python pqc_encryptor.py

# CLI mode
python pqc_encryptor.py encrypt <folder> <output.pqc> -p "passphrase"
python pqc_encryptor.py decrypt <file.pqc> <output_dir> -p "passphrase"
```

Build the .exe:
```bash
# Windows
build_exe.bat
```

## Pull Request Process

1. Test your changes with both encrypt and decrypt operations
2. Ensure the .exe build still works
3. Update documentation if needed
4. Submit a PR with a clear description of the changes

## Code Style

- Single-file architecture (keep everything in `pqc_encryptor.py`)
- Follow existing code conventions
- No external GUI frameworks beyond tkinter

## Security

- Never weaken cryptographic parameters
- Do not add debug/logging that could leak sensitive data
- Report vulnerabilities privately (see SECURITY.md)
