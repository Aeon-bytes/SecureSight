import nmap

def scan_ports(target):
    nm = nmap.PortScanner()
    try:
        nm.scan(target, arguments='-T4 --top-ports 100')
        if target not in nm.all_hosts():
            return {"error": f"Host {target} is unreachable or scan failed."}
        open_ports = []
        for proto in nm[target].all_protocols():
            lport = nm[target][proto].keys()
            for port in lport:
                state = nm[target][proto][port]['state']
                if state == 'open':
                    open_ports.append(port)
        if not open_ports:
            return {"open_ports": [], "advice": "No open ports detected. Good job!"}
        return {
            "open_ports": open_ports,
            "advice": "Close unnecessary ports to reduce attack surface."
        }
    except nmap.PortScannerError as e:
        return {"error": f"Nmap error: {str(e)}"}
    except Exception as e:
        return {"error": str(e)}
