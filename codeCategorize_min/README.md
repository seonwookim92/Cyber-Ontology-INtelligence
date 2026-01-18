# File Language Detector & Malware Analyzer

Binary 폴더 안에 Ghidra 12.0을 풀고, ghidra_12.0_PUBLIC으로 풀리는지 확인 후, Gradle Build를 꼭 해주어야 합니다.

A comprehensive tool to detect programming languages, deobfuscate scripts, and analyze threat actors in binary executables and script files.

## Supported Languages

- **Binary Files:**
  - C
  - C++
  - C#
  - Java (JAR)

- **Script/Source Files:**
  - C (source)
  - C++ (source)
  - C# (source)
  - Java (source)
  - PowerShell
  - VBScript
  - Python
  - Ruby
  - JavaScript
  - PHP
  - Perl
  - Shell
  - Go
  - Rust
  - And many more via Pygments...

## Architecture

The system consists of three main components:

1. **detector.py** - Core language detection logic using:
   - `python-magic` for file type detection
   - `pefile` for PE executable analysis
   - `pygments` for script/source code language detection
   - Interpreter availability checks (python, ruby, node, java, etc.)
2. **server.py** - FastAPI REST API with MCP support
3. **app.py** - Streamlit web interface

## Installation

### Prerequisites

Make sure you have Python 3.8+ installed.

On macOS, you may need to install libmagic:
```bash
brew install libmagic
```

On Linux (Ubuntu/Debian):
```bash
sudo apt-get install libmagic1
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

## Usage

### Option 1: Web Interface (Streamlit)

1. **Start the FastAPI server:**
```bash
python server.py
```

The server will start on http://localhost:8000

2. **In a new terminal, start the Streamlit app:**
```bash
streamlit run app.py
```

The web interface will open in your browser.

3. **Use the web interface:**
   - Upload a file
   - Review the detected language
   - Modify if needed using the dropdown
   - Click "Submit" to get the final JSON result

### Option 2: Command Line (detector.py)

```bash
python detector.py <file_path>
```

Example:
```bash
python detector.py /path/to/executable.exe
```

### Option 3: API Endpoints

**Upload a file:**
```bash
curl -X POST -F "file=@yourfile.exe" http://localhost:8000/upload
```

**Finalize detection:**
```bash
curl -X POST http://localhost:8000/finalize \
  -H "Content-Type: application/json" \
  -d '{"file_id": "uuid-here", "type": "Binary", "language": "C++"}'
```

### Option 4: MCP Integration

The FastAPI server exposes an MCP tool called `detect_file_language`.

To use it with MCP clients, configure your MCP client to connect to:
```
http://localhost:8000
```

The tool accepts a `file_path` parameter and returns detection results.

## API Endpoints

- `GET /` - API information
- `GET /health` - Health check
- `POST /upload` - Upload a file for language detection
- `POST /deobfuscate` - Deobfuscate PowerShell/VBScript files
- `POST /analyze-threat-actor` - Analyze file for threat actor attribution
- `POST /finalize` - Submit final analysis result

## How It Works

### Complete Analysis Workflow

1. **Step 1 - File Upload**: Upload file via web UI or API
2. **Step 2 - Language Detection & User Review**:
   - **Binary Detection**:
     - PE files (Windows .exe, .dll) → Analyzed with pefile for C/C++/C# detection
     - ELF files (Linux executables) → Analyzed for C/C++ indicators
     - Mach-O files (macOS executables) → Detected as C++
     - JAR files → Detected as Java
   - **Script/Source Detection**:
     - File extension matching (.py, .rb, .js, etc.)
     - Pygments-based language detection for source code
     - Heuristic pattern matching for PowerShell, VBScript, etc.
     - Interpreter availability check (python, ruby, node, java, etc.)
   - User can review and modify the detected language
3. **Step 3 - Deobfuscation** (PowerShell/VBScript only):
   - Original code display
   - Deobfuscated code
   - Aggressively deobfuscated code
   - IoC extraction (URLs, IPs)
   - Download buttons for deobfuscated versions
4. **Step 4 - Threat Actor Analysis** (Binary + PowerShell/VBScript):
   - File analysis using ML/heuristics
   - Threat actor attribution
   - Confidence probability
5. **Step 5 - Final Results**:
   - Complete analysis summary
   - Language classification
   - Threat actor (if applicable)
   - IoC list (if applicable)
   - JSON export to stdout

## Output Format

The final result is returned as JSON:

```json
{
  "file_id": "uuid-v4",
  "filename": "malware.ps1",
  "final_type": "Script",
  "final_language": "PowerShell",
  "final_category": "Script (PowerShell)",
  "threat_actor": "APT1",
  "threat_actor_probability": 0.80,
  "ioc_list": {
    "urls": [
      {"Pass": 1, "URL": "http://malicious-c2.example.com/api"},
      {"Pass": 1, "URL": "http://malicious-c2.example.com/upload"}
    ],
    "ips": [
      {"Pass": 2, "IP": "192.168.100.50"},
      {"Pass": 2, "IP": "10.0.0.15"}
    ]
  }
}
```

## File Structure

```
codeCategorize/
├── detector.py          # Language detection logic
├── server.py           # FastAPI server
├── app.py              # Streamlit frontend
├── requirements.txt    # Python dependencies
├── README.md          # This file
└── temp/              # Temporary upload directory (auto-created)
```

## Security Notes

- This tool is designed for internal use with trusted files
- No file size limits are enforced by default
- Files are temporarily stored in the `temp/` directory
- Files are cleaned up after finalization

## Troubleshooting

**python-magic not working on Windows:**
- Uncomment `python-magic-bin` in requirements.txt
- Reinstall: `pip install python-magic-bin`

**libmagic not found on macOS:**
```bash
brew install libmagic
```

**API connection error:**
- Make sure the FastAPI server is running: `python server.py`
- Check that port 8000 is not in use

## License

MIT License
