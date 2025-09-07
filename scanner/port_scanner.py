import nmap

def scan_ports(target):
    nm = nmap.PortScanner()
    try:
        nm.scan(target, arguments='-T4 --top-ports 100')
        open_ports = []
        for proto in nm[target].all_protocols():
            lport = nm[target][proto].keys()
            for port in lport:
                state = nm[target][proto][port]['state']
                if state == 'open':
                    open_ports.append(port)
        return {
            "open_ports": open_ports,
            "advice": "Close unnecessary ports to reduce attack surface."
        }
    except Exception as e:
        return {"error": str(e)}
