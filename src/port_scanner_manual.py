import nmap
from ip_utils import get_local_ip


class PortScanner:
    def __init__(self, target_ip: str):
        self.target_ip = target_ip
        self.nm = nmap.PortScanner()

    def check_port_state(self, port: int) -> str:
        try:
            self.nm.scan(self.target_ip, str(port))
            state = self.nm[self.target_ip]["tcp"][int(port)]["state"]

            if state == "open":
                return self.run_manual_scan(port)
            return f"Port {port} is CLOSED. Vulnerability scan cannot be performed.\n"

        except KeyError:
            return "Invalid IP address or port.\n"
        except Exception as err:
            return f"An error occurred: {err}\n"

    def run_manual_scan(self, port: int) -> str:
        options = f"-p {port} --script ssl-enum-ciphers,dns-recursion"
        nm = nmap.PortScanner()
        nm.scan(hosts=self.target_ip, arguments=options)

        output = ""
        host_key = get_local_ip()  # original style preserved
        if not host_key:
            host_key = self.target_ip

        for protocol in nm[host_key].all_protocols():
            output += f"Protocol: {protocol}\n"
            ports = nm[host_key][protocol]

            for p, details in ports.items():
                service_name = details.get("name", "Unknown Service")
                output += f"Port {p}: {service_name}\n"

                if "outdated" in details.get("product", "").lower() or "vulnerable" in details.get("product", "").lower():
                    output += (
                        f"WARNING: {p}/{protocol} - {service_name} "
                        f"(Version: {details.get('product', 'Unknown')} {details.get('version', 'Unknown')}) may be outdated.\n"
                    )

                if "ssl-enum-ciphers" in details.get("script", {}):
                    output += "WARNING: Weak SSL/TLS ciphers may be enabled. Details:\n"
                    output += f"{details['script']['ssl-enum-ciphers']}\n"

                if "dns-recursion" in details.get("script", {}):
                    output += "WARNING: DNS recursion might be enabled. Details:\n"
                    output += f"{details['script']['dns-recursion']}\n"

        return f"Scanning port {port}...\n{output}"
