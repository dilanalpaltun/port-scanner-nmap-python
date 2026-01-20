import nmap


def run_auto_scan(target_ip: str) -> str:
    options = "-sV -sC --script ssl-enum-ciphers,dns-recursion"
    nm = nmap.PortScanner()
    nm.scan(hosts=target_ip, arguments=options)

    output = ""
    for host in nm.all_hosts():
        output += f"Host: {host}\n"
        for protocol in nm[host].all_protocols():
            output += f"Protocol: {protocol}\n"
            ports = nm[host][protocol]

            for port, details in ports.items():
                service_name = details.get("name", "Unknown Service")
                output += f"Port {port}: {service_name}\n"

                if "outdated" in details.get("product", "").lower() or "vulnerable" in details.get("product", "").lower():
                    output += (
                        f"WARNING: {port}/{protocol} - {service_name} "
                        f"(Version: {details.get('product', 'Unknown')} {details.get('version', 'Unknown')}) may be outdated.\n"
                    )

                if service_name.lower() in ["ftp", "telnet"]:
                    output += f"WARNING: {port}/{protocol} - {service_name} service may be insecure!\n"

                if "ssl-enum-ciphers" in details.get("script", {}):
                    output += "WARNING: Weak SSL/TLS ciphers may be enabled. Details:\n"
                    output += f"{details['script']['ssl-enum-ciphers']}\n"

                if "dns-recursion" in details.get("script", {}):
                    output += "WARNING: DNS recursion might be enabled. Details:\n"
                    output += f"{details['script']['dns-recursion']}\n"

    return output
