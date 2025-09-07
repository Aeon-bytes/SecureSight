import dns.resolver

def scan_dns(target):
    results = {"a": [], "aaaa": [], "mx": [], "ns": [], "txt": [], "advice": "Review DNS records for any anomalies or misconfigurations."}
    try:
        # A Records
        a_records = dns.resolver.resolve(target, 'A')
        for ipval in a_records:
            results['a'].append(str(ipval))

        # AAAA Records
        try:
            aaaa_records = dns.resolver.resolve(target, 'AAAA')
            for ipval in aaaa_records:
                results['aaaa'].append(str(ipval))
        except dns.resolver.NoAnswer:
            pass # No AAAA records found

        # MX Records
        try:
            mx_records = dns.resolver.resolve(target, 'MX')
            for mxpref in mx_records:
                results['mx'].append(f"{mxpref.preference} {mxpref.exchange}")
        except dns.resolver.NoAnswer:
            pass # No MX records found

        # NS Records
        try:
            ns_records = dns.resolver.resolve(target, 'NS')
            for nsval in ns_records:
                results['ns'].append(str(nsval))
        except dns.resolver.NoAnswer:
            pass # No NS records found

        # TXT Records
        try:
            txt_records = dns.resolver.resolve(target, 'TXT')
            for txtval in txt_records:
                results['txt'].append(txtval.strings[0].decode())
        except dns.resolver.NoAnswer:
            pass # No TXT records found

    except dns.resolver.NXDOMAIN:
        results['error'] = f"Domain {target} does not exist."
    except dns.resolver.NoNameservers:
        results['error'] = f"No nameservers found for {target}."
    except Exception as e:
        results['error'] = str(e)
    return results

