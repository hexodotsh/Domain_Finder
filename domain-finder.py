import socket
import dns.resolver

def get_domain_info(domain):
    try:
        ip = socket.gethostbyname(domain)
        print(f"Domain: {domain}\nIP Address: {ip}\n")
    except socket.gaierror:
        print(f"Error: Unable to get IP address for {domain}")

def find_subdomains(domain, subdomain_list):
    resolver = dns.resolver.Resolver()
    found_subdomains = []
    
    for subdomain in subdomain_list:
        try:
            query = f"{subdomain}.{domain}"
            answers = resolver.resolve(query, "A")
            ip = answers[0].address
            print(f"Subdomain: {query}\nIP Address: {ip}\n")
            found_subdomains.append(query)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            pass

    return found_subdomains

def load_subdomain_list(file_path):
    with open(file_path, "r") as file:
        subdomain_list = [line.strip() for line in file.readlines()]
    return subdomain_list

if __name__ == "__main__":
    domain = input("Enter the domain: ").strip()
    subdomain_file = input("Enter the subdomain list file path: ").strip()

    try:
        subdomain_list = load_subdomain_list(subdomain_file)
    except FileNotFoundError:
        print(f"Error: File {subdomain_file} not found.")
    else:
        get_domain_info(domain)
        found_subdomains = find_subdomains(domain, subdomain_list)

        if not found_subdomains:
            print("No subdomains found from the given list.")
        else:
            print(f"Found subdomains: {', '.join(found_subdomains)}")
