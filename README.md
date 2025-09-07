# Open-Source Configuration Exposure Scanner

A free, open-source tool to help individuals and small organizations detect misconfigurations in their public-facing assets.

## Features

- **Port scanning (Nmap)**
- **SSL/TLS checks (SSLyze)**
- **Web configuration checks (headers, directory listing, CMS detection)**
- **DNS information gathering (A, AAAA, MX, NS, TXT records)**
- **Local HTML report with actionable advice**
- **Modern, user-friendly GUI (Tkinter)**
- **Modular: Select which scans to run (Port, SSL, HTTP, DNS) in both CLI and GUI**
- **Visual scan status, progress bar, and clear results in GUI**

## Requirements

- Python 3.8+
- [nmap](https://nmap.org/) (system package, e.g. `sudo apt install nmap`)
- [Tkinter](https://wiki.python.org/moin/TkInter) (for GUI, e.g. `sudo apt install python3-tk`)
- Install Python dependencies:
  ```bash
  pip install -r requirements.txt
  ```

## Usage
*Make sure to activate Virtual Environment*
```
source venv/bin/activate
```

### 1. **Command-Line Interface (CLI)**

Run all modules (default):
```bash
python main.py example.com
```

Run specific modules:
```bash
python main.py example.com --modules ports ssl http dns
```

Specify output file:
```bash
python main.py example.com --output my_report.html
```

### 2. **Graphical User Interface (GUI)**

Launch the GUI:
```bash
python main.py --gui
```
- Enter a domain or IP.
- Select which scan modules to run (all are checked by default).
- Click "Start Scan".
- View real-time status and results in the app. An HTML report is also generated.

## Example Test Domain
- Use `testphp.vulnweb.com` for safe, legal testing.

## For Hackathons
- 100% open-source, no cloud or paid services
- Easy to extend and customize
- Real-world impact for small business security

## Troubleshooting
- If you see `ModuleNotFoundError: No module named 'dns'`, run:
  ```bash
  pip install dnspython
  ```
- If the GUI fails to launch, ensure Tkinter is installed:
  ```bash
  sudo apt install python3-tk
  ```
- If port scanning fails, ensure `nmap` is installed:
  ```bash
  sudo apt install nmap
  ```

## Extending
- Add new scan modules by creating a new file in `scanner/` and updating `cli.py` and `gui.py`.
- The codebase is modular and easy to extend for more checks (e.g., CORS, vulnerability DBs, batch scanning).
