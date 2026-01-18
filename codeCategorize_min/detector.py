"""
File Language Detector
Detects programming language and type (binary/script) for given files.
Supports: C, C++, C#, Java (JAR), VBScript, PowerShell, and many more via Pygments
"""

import magic
import zipfile
import os
import shutil
from typing import Dict, Optional
from pathlib import Path


class LanguageDetector:
    """Detects the programming language and type of a file."""

    def __init__(self):
        """Initialize the detector with magic, pygments, and check available interpreters."""
        self.magic = magic.Magic(mime=False)
        self.magic_mime = magic.Magic(mime=True)

        # Try to initialize Pygments for script/source detection
        try:
            from pygments.lexers import guess_lexer, get_lexer_by_name
            self.has_pygments = True
        except ImportError:
            self.has_pygments = False
            print("Warning: pygments not installed. Install with: pip install pygments")

        # Check available interpreters
        self.interpreters = self._check_interpreters()

    def detect(self, file_path: str) -> Dict[str, str]:
        """
        Detect the language and type of a file.

        Args:
            file_path: Path to the file to analyze

        Returns:
            Dictionary with 'type' and 'language' keys
            type: 'Binary' or 'Script'
            language: 'C', 'C++', 'C#', 'Java', 'PowerShell', 'VBScript', or 'ETC'
        """
        if not os.path.exists(file_path):
            return {"type": "ETC", "language": "ETC"}

        # Get file info
        file_type = self.magic.from_file(file_path)
        mime_type = self.magic_mime.from_file(file_path)
        file_ext = Path(file_path).suffix.lower()

        # Check for JAR files (Java)
        if self._is_jar(file_path, mime_type, file_ext):
            return {"type": "Binary", "language": "Java"}

        # Check for PE executables (Windows)
        if self._is_pe_executable(file_type, mime_type):
            lang = self._detect_pe_language(file_path, file_type)
            return {"type": "Binary", "language": lang}

        # Check for ELF executables (Linux)
        if self._is_elf_executable(file_type, mime_type):
            lang = self._detect_elf_language(file_path, file_type)
            return {"type": "Binary", "language": lang}

        # Check for Mach-O executables (macOS)
        if self._is_macho_executable(file_type, mime_type):
            return {"type": "Binary", "language": "C++"}  # Most common

        # Check for script/source files (use Guesslang)
        script_result = self._detect_script_or_source(file_path, file_type, mime_type, file_ext)
        if script_result:
            return script_result

        # Default to ETC
        return {"type": "ETC", "language": "ETC"}

    def _check_interpreters(self) -> Dict[str, bool]:
        """Check which language interpreters are installed."""
        interpreters_to_check = [
            'python', 'python3', 'ruby', 'node', 'nodejs', 'perl',
            'php', 'bash', 'sh', 'powershell', 'pwsh', 'java', 'javac'
        ]

        available = {}
        for interpreter in interpreters_to_check:
            available[interpreter] = shutil.which(interpreter) is not None

        return available

    def _is_jar(self, file_path: str, mime_type: str, file_ext: str) -> bool:
        """Check if file is a JAR file."""
        if file_ext == '.jar':
            return True

        if 'zip' in mime_type.lower() or 'java' in mime_type.lower():
            try:
                with zipfile.ZipFile(file_path, 'r') as jar:
                    # JAR files have META-INF/MANIFEST.MF
                    return 'META-INF/MANIFEST.MF' in jar.namelist()
            except:
                pass

        return False

    def _is_pe_executable(self, file_type: str, mime_type: str) -> bool:
        """Check if file is a PE executable."""
        # Check for text/script files first (not PE executables)
        if 'text' in mime_type or 'script' in file_type.lower():
            return False

        pe_indicators = [
            'PE32', 'PE32+', 'MS-DOS executable',
            'DLL', '.Net assembly'
        ]
        return any(indicator in file_type for indicator in pe_indicators)

    def _is_elf_executable(self, file_type: str, mime_type: str) -> bool:
        """Check if file is an ELF executable."""
        # Check for text/script files first (not ELF executables)
        if 'text' in mime_type or 'script' in file_type.lower():
            return False

        return 'ELF' in file_type or mime_type == 'application/x-executable'

    def _is_macho_executable(self, file_type: str, mime_type: str) -> bool:
        """Check if file is a Mach-O executable."""
        return 'Mach-O' in file_type

    def _detect_pe_language(self, file_path: str, file_type: str) -> str:
        """Detect language for PE executables."""
        try:
            import pefile

            pe = pefile.PE(file_path)

            # Check for .NET assembly (C#)
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8').lower()
                    if 'mscoree.dll' in dll_name or 'clr' in dll_name:
                        return "C#"

            # Check if it's a .NET assembly through file type
            if '.Net assembly' in file_type or 'MSIL' in file_type:
                return "C#"

            # Check for C++ indicators
            # Look for common C++ runtime libraries
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                cpp_dlls = ['msvcp', 'msvcr', 'vcruntime']
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8').lower()
                    if any(cpp_dll in dll_name for cpp_dll in cpp_dlls):
                        # Could be C or C++, check for C++ specific symbols
                        return "C++"

            # Check sections for clues
            section_names = [section.Name.decode('utf-8').strip('\x00') for section in pe.sections]
            if '.rdata' in section_names or '.data' in section_names:
                # Common in both C and C++, default to C++
                return "C++"

            # Default to C for PE files
            return "C"

        except ImportError:
            # pefile not installed, use heuristics
            if '.Net assembly' in file_type or 'MSIL' in file_type:
                return "C#"
            return "C++"
        except Exception as e:
            # If analysis fails, default to C++
            return "C++"

    def _detect_elf_language(self, file_path: str, file_type: str) -> str:
        """Detect language for ELF executables."""
        # Read the binary and look for indicators
        try:
            with open(file_path, 'rb') as f:
                content = f.read(10000)  # Read first 10KB

                # Look for C++ indicators
                cpp_indicators = [b'std::']
                if any(indicator in content for indicator in cpp_indicators):
                    return "C++"

                # Default to C for ELF
                return "C"
        except:
            return "C"

    def _detect_script_or_source(self, file_path: str, file_type: str, mime_type: str, file_ext: str) -> Optional[Dict[str, str]]:
        """Detect script/source files using Guesslang."""
        # Quick extension-based detection for common cases
        ext_map = {
            '.ps1': 'PowerShell', '.psm1': 'PowerShell', '.psd1': 'PowerShell',
            '.vbs': 'VBScript', '.vbe': 'VBScript',
            '.py': 'Python', '.rb': 'Ruby', '.js': 'JavaScript',
            '.c': 'C', '.cpp': 'C++', '.cc': 'C++', '.cxx': 'C++',
            '.cs': 'C#', '.java': 'Java', '.php': 'PHP', '.pl': 'Perl',
            '.sh': 'Shell', '.bash': 'Shell', '.go': 'Go', '.rs': 'Rust'
        }

        if file_ext in ext_map:
            lang = ext_map[file_ext]
            return {"type": "Script", "language": lang}

        # Check if it's a text file
        if 'text' in mime_type or 'script' in mime_type or self._is_likely_text_file(file_path):
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read(50000)  # Read up to 50KB

                # Use Pygments if available
                if self.has_pygments and content.strip():
                    try:
                        from pygments.lexers import guess_lexer

                        lexer = guess_lexer(content)
                        detected_lang = lexer.name

                        # Map Pygments lexer names to our language names
                        lang_map = {
                            'Python': 'Python',
                            'Python 3': 'Python',
                            'C': 'C',
                            'C++': 'C++',
                            'C#': 'C#',
                            'Java': 'Java',
                            'JavaScript': 'JavaScript',
                            'Ruby': 'Ruby',
                            'PHP': 'PHP',
                            'Perl': 'Perl',
                            'Bash': 'Shell',
                            'Shell': 'Shell',
                            'PowerShell': 'PowerShell',
                            'Go': 'Go',
                            'Rust': 'Rust',
                            'Swift': 'Swift',
                            'Kotlin': 'Kotlin',
                            'TypeScript': 'TypeScript',
                            'Lua': 'Lua',
                            'R': 'R',
                            'Scala': 'Scala',
                            'Haskell': 'Haskell',
                            'Clojure': 'Clojure',
                            'Erlang': 'Erlang',
                            'Elixir': 'Elixir',
                            'VBScript': 'VBScript',
                            'VB.net': 'VBScript',
                        }

                        if detected_lang in lang_map:
                            return {"type": "Script", "language": lang_map[detected_lang]}
                        elif detected_lang:
                            # Return the detected language even if not in map
                            return {"type": "Script", "language": detected_lang}

                    except Exception as e:
                        # Pygments failed, fall back to heuristics
                        pass

                # Fallback: manual heuristics for specific languages
                # PowerShell
                ps_indicators = ['param(', '$_', 'Get-', 'Set-', 'Write-Host', 'Write-Output']
                if any(indicator in content for indicator in ps_indicators):
                    return {"type": "Script", "language": "PowerShell"}

                # VBScript
                vbs_indicators = ['WScript.', 'Dim ', 'Set ', 'MsgBox', "On Error Resume Next"]
                if any(indicator in content for indicator in vbs_indicators):
                    return {"type": "Script", "language": "VBScript"}

                # Python
                if 'def ' in content or 'import ' in content or 'from ' in content:
                    return {"type": "Script", "language": "Python"}

                # Ruby
                if content.startswith('#!/usr/bin/env ruby') or 'require ' in content or 'puts ' in content:
                    return {"type": "Script", "language": "Ruby"}

            except:
                pass

        return None

    def _is_likely_text_file(self, file_path: str) -> bool:
        """Check if file is likely a text file by reading first few bytes."""
        try:
            with open(file_path, 'rb') as f:
                chunk = f.read(8192)
                # Check for null bytes (binary indicator)
                if b'\x00' in chunk:
                    return False
                # Try to decode as UTF-8
                try:
                    chunk.decode('utf-8')
                    return True
                except UnicodeDecodeError:
                    return False
        except:
            return False


if __name__ == "__main__":
    # Test the detector
    detector = LanguageDetector()

    import sys
    if len(sys.argv) > 1:
        result = detector.detect(sys.argv[1])
        print(f"Type: {result['type']}")
        print(f"Language: {result['language']}")

        # Show interpreter availability if it's a script
        if result['type'] == 'Script' and result['language'] != 'ETC':
            lang = result['language'].lower()
            interpreters_map = {
                'python': ['python', 'python3'],
                'ruby': ['ruby'],
                'javascript': ['node', 'nodejs'],
                'perl': ['perl'],
                'php': ['php'],
                'shell': ['bash', 'sh'],
                'powershell': ['powershell', 'pwsh'],
                'java': ['java', 'javac']
            }

            if lang in interpreters_map:
                available = []
                for interp in interpreters_map[lang]:
                    if detector.interpreters.get(interp):
                        available.append(interp)

                if available:
                    print(f"Available interpreters: {', '.join(available)}")
                else:
                    print(f"Warning: No {result['language']} interpreter found")
    else:
        print("Usage: python detector.py <file_path>")
        print("\nInstalled interpreters:")
        for interp, available in sorted(detector.interpreters.items()):
            status = "✓" if available else "✗"
            print(f"  {status} {interp}")
