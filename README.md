# Windows File System Monitor for Malware Analysis

A Windows-only Python tool that monitors file system activity and logs:
- File creation
- File modification
- File deletion

Designed for malware analysis, DFIR, and sandboxing.

## Features

- Recursive directory monitoring
- SHA-256 hashing for modified files
- Smart hashing (skips empty files)
- Administrator privilege auto-prompt (UAC)
- Exclusion support:
  - Directory paths
  - Wildcards
  - File extensions
- Append-only logging

## Requirements

- Windows
- Python 3.10+
- Administrator privileges

## Installation

```bash
pip install -r requirements.txt
