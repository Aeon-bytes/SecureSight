import sys

def main():
    if '--gui' in sys.argv:
        from scanner.gui import ScannerGUI
        import tkinter as tk
        root = tk.Tk()
        app = ScannerGUI(root)
        root.mainloop()
    else:
        from scanner.cli import main as cli_main
        cli_main()

if __name__ == "__main__":
    main()
