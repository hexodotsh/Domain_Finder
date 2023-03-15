import socket
import dns.resolver
import nmap

def get_domain_info(domain):
    try:
        ip = socket.gethostbyname(domain)
        result = f"Domain: {domain}\nIP Address: {ip}\n"
        return ip, result
    except socket.gaierror:
        result = f"Error: Unable to get IP address for {domain}\n"
        return None, result

def find_subdomains(domain, subdomain_list):
    resolver = dns.resolver.Resolver()
    found_subdomains = []

    for subdomain in subdomain_list:
        try:
            query = f"{subdomain}.{domain}"
            answers = resolver.resolve(query, "A")
            ip = answers[0].address
            result = f"Subdomain: {query}\nIP Address: {ip}\n"
            found_subdomains.append((query, ip, result))
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            pass

    return found_subdomains

def load_subdomain_list(file_path):
    with open(file_path, "r") as file:
        subdomain_list = [line.strip() for line in file.readlines()]
    return subdomain_list

def scan_ports(ip, ports):
    nm = nmap.PortScanner()
    result = ""
    try:
        nm.scan(ip, ports)
        for port, info in nm[ip]['tcp'].items():
            result += f"Port {port}: {info['state']} ({info['name']})\n"
    except Exception as e:
        result = f"Error scanning ports: {str(e)}\n"
    return result

if __name__ == "__main__":
    domain = input("Enter the domain: ").strip()
    subdomain_file = input("Enter the subdomain list file path: ").strip()
    output_file = "output.txt"

    try:
        subdomain_list = load_subdomain_list(subdomain_file)
    except FileNotFoundError:
        print(f"Error: File {subdomain_file} not found.")
    else:
        ip, domain_info = get_domain_info(domain)
        with open(output_file, "w") as file:
            file.write(domain_info)
            print(domain_info)

        if ip:
            scan_ports_list = '80,443,8080,8081'
            scan_results = scan_ports(ip, scan_ports_list)
            with open(output_file, "a") as file:
                file.write(f"Scanning ports {scan_ports_list} for {domain}:\n")
                file.write(scan_results)
            print(f"Scanning ports {scan_ports_list} for {domain}:")
            print(scan_results)

        print("\n")
        found_subdomains = find_subdomains(domain, subdomain_list)

        if not found_subdomains:
            print("No subdomains found from the given list.")
            with open(output_file, "a") as file:
                file.write("No subdomains found from the given list.\n")
        else:
            for subdomain, subdomain_ip, subdomain_info in found_subdomains:
                scan_results = scan_ports(subdomain_ip, scan_ports_list)
                with open(output_file, "a") as file:
                    file.write(subdomain_info)
                    file.write(f"Scanning ports {scan_ports_list} for {subdomain}:\n")
                    file.write(scan_results)
                    file.write("\n")
                print(subdomain_info)
                print(f"Scanning ports {scan_ports_list} for {subdomain}:")
                print(scan_results)
                print("\n")
