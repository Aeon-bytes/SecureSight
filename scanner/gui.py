import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
from scanner.port_scanner import scan_ports
from scanner.ssl_scanner import scan_ssl
from scanner.http_scanner import scan_http
from scanner.report import generate_report

class ScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("SecureSight - Exposure Scanner")
        self.root.geometry("600x500")
        self.root.resizable(False, False)
        self.create_widgets()

    def create_widgets(self):
        # Title
        title = ttk.Label(self.root, text="Open-Source Configuration Exposure Scanner", font=("Arial", 16, "bold"))
        title.pack(pady=10)

        # Input
        input_frame = ttk.Frame(self.root)
        input_frame.pack(pady=10)
        ttk.Label(input_frame, text="Domain or IP:").pack(side=tk.LEFT)
        self.target_entry = ttk.Entry(input_frame, width=40)
        self.target_entry.pack(side=tk.LEFT, padx=5)
        self.output_entry = ttk.Entry(input_frame, width=25)
        self.output_entry.insert(0, "scan_report.html")
        self.output_entry.pack(side=tk.LEFT, padx=5)
        ttk.Button(input_frame, text="Browse", command=self.browse_file).pack(side=tk.LEFT)

        # Scan button
        self.scan_btn = ttk.Button(self.root, text="Start Scan", command=self.start_scan)
        self.scan_btn.pack(pady=10)

        # Progress
        self.progress = ttk.Progressbar(self.root, mode="indeterminate")
        self.progress.pack(fill=tk.X, padx=20, pady=5)

        # Results
        self.result_text = tk.Text(self.root, height=18, wrap=tk.WORD, font=("Consolas", 10))
        self.result_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.result_text.config(state=tk.DISABLED)

    def browse_file(self):
        file = filedialog.asksaveasfilename(defaultextension=".html", filetypes=[("HTML files", "*.html")])
        if file:
            self.output_entry.delete(0, tk.END)
            self.output_entry.insert(0, file)

    def start_scan(self):
        target = self.target_entry.get().strip()
        output = self.output_entry.get().strip()
        if not target:
            messagebox.showerror("Input Error", "Please enter a domain or IP to scan.")
            return
        self.result_text.config(state=tk.NORMAL)
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, f"Scanning {target}...\n")
        self.result_text.config(state=tk.DISABLED)
        self.progress.start()
        self.scan_btn.config(state=tk.DISABLED)
        threading.Thread(target=self.run_scan, args=(target, output), daemon=True).start()

    def run_scan(self, target, output):
        try:
            results = {}
            self.append_result("[1/3] Scanning ports...\n")
            results['ports'] = scan_ports(target)
            self.append_result("[2/3] Scanning SSL/TLS...\n")
            results['ssl'] = scan_ssl(target)
            self.append_result("[3/3] Scanning web configuration...\n")
            results['http'] = scan_http(target)
            generate_report(target, results, output)
            self.append_result(f"\nScan complete! Report saved to {output}\n\n")
            self.show_summary(results)
        except Exception as e:
            self.append_result(f"\nError: {e}\n")
        finally:
            self.progress.stop()
            self.scan_btn.config(state=tk.NORMAL)

    def append_result(self, text):
        self.result_text.config(state=tk.NORMAL)
        self.result_text.insert(tk.END, text)
        self.result_text.see(tk.END)
        self.result_text.config(state=tk.DISABLED)

    def show_summary(self, results):
        # Ports
        ports = results.get('ports', {})
        if 'error' in ports:
            self.append_result(f"[Ports] Error: {ports['error']}\n")
        elif ports.get('open_ports'):
            self.append_result(f"[Ports] Open ports: {', '.join(map(str, ports['open_ports']))}\n")
        else:
            self.append_result("[Ports] No open ports detected.\n")
        # SSL
        ssl = results.get('ssl', {})
        if 'error' in ssl:
            self.append_result(f"[SSL] Error: {ssl['error']}\n")
        else:
            self.append_result(f"[SSL] Expires: {ssl.get('not_after', 'N/A')}, Advice: {ssl.get('advice', 'N/A')}\n")
        # HTTP/Web
        http = results.get('http', {})
        if 'error' in http:
            self.append_result(f"[Web] Error: {http['error']}\n")
        else:
            if http.get('findings'):
                self.append_result("[Web] Findings:\n")
                for finding in http['findings']:
                    self.append_result(f"  - {finding}\n")
            else:
                self.append_result("[Web] No major web config issues detected.\n")

if __name__ == "__main__":
    root = tk.Tk()
    app = ScannerGUI(root)
    root.mainloop()
