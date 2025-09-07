import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading

# Import the centralized scan function instead of individual modules
from scanner.cli import run_all_scans
from scanner.report import generate_report

class ScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("SecureSight - Exposure Scanner")
        self.root.geometry("750x650") # Increased size for more controls
        self.root.resizable(False, False)

        # Apply a theme
        self.style = ttk.Style()
        self.style.theme_use("clam") # "clam", "alt", "default", "classic"
        self.style.configure("TLabel", font=("Arial", 10))
        self.style.configure("TButton", font=("Arial", 10, "bold"))
        self.style.configure("TCheckbutton", font=("Arial", 10))
        self.style.configure("Green.TLabel", foreground="green")
        self.style.configure("Red.TLabel", foreground="red")
        self.style.configure("Blue.TLabel", foreground="blue")

        self.create_widgets()

    def create_widgets(self):
        # Title
        title = ttk.Label(self.root, text="Open-Source Configuration Exposure Scanner", font=("Arial", 18, "bold"))
        title.pack(pady=15)

        # Input Frame
        input_frame = ttk.Frame(self.root)
        input_frame.pack(pady=10, padx=20, fill=tk.X)

        ttk.Label(input_frame, text="Target (Domain or IP):").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.target_entry = ttk.Entry(input_frame, width=50)
        self.target_entry.grid(row=0, column=1, padx=5, sticky=tk.EW)

        ttk.Label(input_frame, text="Report Output File:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.output_entry = ttk.Entry(input_frame, width=40)
        self.output_entry.insert(0, "scan_report.html")
        self.output_entry.grid(row=1, column=1, padx=5, sticky=tk.EW)
        ttk.Button(input_frame, text="Browse", command=self.browse_file).grid(row=1, column=2, padx=5)

        input_frame.grid_columnconfigure(1, weight=1)

        # Scan Modules Selection
        modules_frame = ttk.LabelFrame(self.root, text="Select Scan Modules", padding=(10, 5))
        modules_frame.pack(pady=10, padx=20, fill=tk.X)

        self.module_vars = {
            "ports": tk.BooleanVar(value=True),
            "ssl": tk.BooleanVar(value=True),
            "http": tk.BooleanVar(value=True),
            "dns": tk.BooleanVar(value=True),
        }

        row_num = 0
        for module_name, var in self.module_vars.items():
            cb = ttk.Checkbutton(modules_frame, text=module_name.upper(), variable=var)
            cb.grid(row=row_num // 2, column=row_num % 2, sticky=tk.W, padx=10, pady=2)
            row_num += 1

        # Scan & Control Buttons
        control_frame = ttk.Frame(self.root)
        control_frame.pack(pady=10, padx=20, fill=tk.X)

        self.scan_btn = ttk.Button(control_frame, text="Start Scan", command=self.start_scan)
        self.scan_btn.pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)

        self.clear_btn = ttk.Button(control_frame, text="Clear Results", command=self.clear_results)
        self.clear_btn.pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)

        # Progress & Status
        self.progress = ttk.Progressbar(self.root, mode="determinate", length=500) # Changed to determinate
        self.progress.pack(fill=tk.X, padx=20, pady=5)

        # Status labels in a dedicated frame (fixes pack/grid mix)
        status_frame = ttk.Frame(self.root)
        status_frame.pack(pady=5, padx=20, fill=tk.X)
        self.status_labels = {
            "ports": ttk.Label(status_frame, text="Ports: Pending"),
            "ssl": ttk.Label(status_frame, text="SSL: Pending"),
            "http": ttk.Label(status_frame, text="HTTP: Pending"),
            "dns": ttk.Label(status_frame, text="DNS: Pending"),
        }
        col_num = 0
        for label in self.status_labels.values():
            label.grid(row=0, column=col_num, padx=5, sticky=tk.W)
            col_num += 1

        # Results Text Area
        self.result_text = tk.Text(self.root, height=15, wrap=tk.WORD, font=("Consolas", 10), bg="#f0f0f0", bd=1, relief=tk.FLAT)
        self.result_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.result_text.config(state=tk.DISABLED)

    def browse_file(self):
        file = filedialog.asksaveasfilename(defaultextension=".html", filetypes=[("HTML files", "*.html")])
        if file:
            self.output_entry.delete(0, tk.END)
            self.output_entry.insert(0, file)

    def clear_results(self):
        self.result_text.config(state=tk.NORMAL)
        self.result_text.delete(1.0, tk.END)
        self.result_text.config(state=tk.DISABLED)
        for label in self.status_labels.values():
            label.config(text=label.cget("text").split(':')[0] + ": Pending", style="TLabel")

    def update_status(self, module, status, style="TLabel"):
        if module in self.status_labels:
            self.status_labels[module].config(text=f"{module.capitalize()}: {status}", style=style)

    def start_scan(self):
        target = self.target_entry.get().strip()
        output = self.output_entry.get().strip()
        if not target:
            messagebox.showerror("Input Error", "Please enter a domain or IP to scan.")
            return

        selected_modules = [name for name, var in self.module_vars.items() if var.get()]
        if not selected_modules:
            messagebox.showerror("Input Error", "Please select at least one scan module.")
            return

        self.clear_results()
        self.append_result(f"Starting scan for {target}...\n")

        self.progress.config(mode="determinate", maximum=len(selected_modules))
        self.progress_step = 0
        self.progress.set(self.progress_step)

        self.scan_btn.config(state=tk.DISABLED)
        self.clear_btn.config(state=tk.DISABLED)

        # Reset status labels
        for module in self.module_vars.keys():
            self.update_status(module, "Pending")

        threading.Thread(target=self.run_scan, args=(target, output, selected_modules), daemon=True).start()

    def run_scan(self, target, output, selected_modules):
        all_results = {}
        try:
            scan_order = ["ports", "ssl", "http", "dns"]
            actual_scans_to_run = [m for m in scan_order if m in selected_modules]

            for i, module in enumerate(actual_scans_to_run):
                self.update_status(module, "Running...", style="Blue.TLabel")
                self.append_result(f"[{i+1}/{len(actual_scans_to_run)}] Scanning {module.upper()}...\n")

                if module == "ports":
                    all_results['ports'] = scan_ports(target)
                elif module == "ssl":
                    all_results['ssl'] = scan_ssl(target)
                elif module == "http":
                    all_results['http'] = scan_http(target)
                elif module == "dns":
                    all_results['dns'] = scan_dns(target)
                
                if all_results.get(module, {}).get('error'):
                    self.update_status(module, "Error", style="Red.TLabel")
                else:
                    self.update_status(module, "Completed", style="Green.TLabel")
                
                self.progress_step += 1
                self.progress.set(self.progress_step)
                self.root.update_idletasks()

            generate_report(target, all_results, output)
            self.append_result(f"\nScan complete! Report saved to {output}\n\n")
            self.show_summary(all_results)

        except Exception as e:
            self.append_result(f"\nAn unexpected error occurred: {e}\n")
            messagebox.showerror("Scan Error", f"An unexpected error occurred during scanning: {e}")
        finally:
            self.progress.stop()
            self.scan_btn.config(state=tk.NORMAL)
            self.clear_btn.config(state=tk.NORMAL)

    def append_result(self, text):
        self.result_text.config(state=tk.NORMAL)
        self.result_text.insert(tk.END, text)
        self.result_text.see(tk.END)
        self.result_text.config(state=tk.DISABLED)

    def show_summary(self, results):
        self.append_result("\n--- Scan Summary ---\n")
        # Ports
        if 'ports' in results:
            ports = results['ports']
            if 'error' in ports:
                self.append_result(f"[Ports] Error: {ports['error']}\n")
            elif ports.get('open_ports'):
                self.append_result(f"[Ports] Open ports: {', '.join(map(str, ports['open_ports']))}\n")
            else:
                self.append_result("[Ports] No open ports detected.\n")
        
        # SSL
        if 'ssl' in results:
            ssl = results['ssl']
            if 'error' in ssl:
                self.append_result(f"[SSL] Error: {ssl['error']}\n")
            else:
                self.append_result(f"[SSL] Expires: {ssl.get('not_after', 'N/A')}, Advice: {ssl.get('advice', 'N/A')}\n")
        
        # HTTP/Web
        if 'http' in results:
            http = results['http']
            if 'error' in http:
                self.append_result(f"[Web] Error: {http['error']}\n")
            else:
                if http.get('findings'):
                    self.append_result("[Web] Findings:\n")
                    for finding in http['findings']:
                        self.append_result(f"  - {finding}\n")
                else:
                    self.append_result("[Web] No major web config issues detected.\n")
        
        # DNS
        if 'dns' in results:
            dns_res = results['dns']
            if 'error' in dns_res:
                self.append_result(f"[DNS] Error: {dns_res['error']}\n")
            else:
                self.append_result(f"[DNS] A Records: {', '.join(dns_res['a'])}\n")
                self.append_result(f"[DNS] AAAA Records: {', '.join(dns_res['aaaa'])}\n")
                self.append_result(f"[DNS] MX Records: {', '.join(dns_res['mx'])}\n")
                self.append_result(f"[DNS] NS Records: {', '.join(dns_res['ns'])}\n")
                self.append_result(f"[DNS] TXT Records: {', '.join(dns_res['txt'])}\n")

# Removed the __main__ block as main.py will handle GUI launch
