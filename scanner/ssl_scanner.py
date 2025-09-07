from sslyze import ServerNetworkLocation, Scanner, ServerScanRequest, ScanCommand
from sslyze.plugins.certificate_info.implementation import CertificateInfoScanResult

def scan_ssl(target):
    try:
        server_location = ServerNetworkLocation(hostname=target, port=443)
        scan_request = ServerScanRequest(
            server_location=server_location,
            scan_commands={ScanCommand.CERTIFICATE_INFO}
        )
        scanner = Scanner()
        scanner.queue_scans([scan_request])
        for scan_result in scanner.get_results():
            # The actual scan results are in scan_result.scan_result
            scan_cmds = getattr(scan_result, 'scan_result', None)
            if scan_cmds and hasattr(scan_cmds, 'certificate_info_result'):
                cert_info = scan_cmds.certificate_info_result
                if isinstance(cert_info, CertificateInfoScanResult):
                    expired = cert_info.certificate_has_expired
                    advice = "Renew SSL certificate." if expired else "SSL certificate is valid."
                    return {
                        "expired": expired,
                        "subject": getattr(cert_info, 'subject', 'N/A'),
                        "issuer": getattr(cert_info, 'issuer', 'N/A'),
                        "not_after": getattr(cert_info, 'not_after', 'N/A'),
                        "advice": advice
                    }
                elif hasattr(cert_info, 'error_message'):
                    return {"error": cert_info.error_message}
                else:
                    return {"error": "Could not retrieve certificate info."}
            else:
                return {"error": "No certificate info found in scan result."}
        return {"error": "No scan results returned. Host may not support HTTPS on port 443."}
    except Exception as e:
        return {"error": str(e)}
