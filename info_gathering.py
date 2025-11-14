from http.client import responses
import whois
import dns.resolver
import shodan
import requests
import argparse
import socket

# -------- ARGUMENT PARSER --------
parser = argparse.ArgumentParser(
    description="This is a basic information gathering tool.",
    usage="python3 info_gathering.py -d DOMAIN [-s IP] [-o FILE]"
)

parser.add_argument(
    "-d", "--domain",
    help="Enter the Domain Name for footprinting.",
    required=True
)

parser.add_argument(
    "-s", "--shodan",
    help="Enter the IP for Shodan search."
)

parser.add_argument(
    "-o", "--output",
    help="Enter the file to write output to."
)

args = parser.parse_args()

domain = args.domain
ip = args.shodan
output = args.output

# Function to save output
def save(text):
    if output:
        with open(output, "a") as f:
            f.write(text + "\n")


# ---------------------------------
# WHOIS MODULE
# ---------------------------------

print("[+] Getting WHOIS info...")
save("\n===== WHOIS INFORMATION =====")

try:
    w = whois.whois(domain)
    print("[+] WHOIS info found.")

    whois_text = (
        f"Domain Name: {w.domain_name}\n"
        f"Registrar: {w.registrar}\n"
        f"Creation Date: {w.creation_date}\n"
        f"Expiration Date: {w.expiration_date}\n"
        f"Registrant Name: {w.get('name')}\n"
        f"Registrant Country: {w.get('country')}\n"
    )

    print(whois_text)
    save(whois_text)

except Exception as e:
    print("[-] WHOIS lookup failed:", e)
    save(f"WHOIS Error: {e}")


# ---------------------------------
# DNS MODULE
# ---------------------------------
print("[+] Getting DNS Info...")
save("\n===== DNS RECORDS =====")

try:
    for a in dns.resolver.resolve(domain, 'A'):
        line = f"A Record: {a.to_text()}"
        print(line)
        save(line)

    for ns in dns.resolver.resolve(domain, 'NS'):
        line = f"NS Record: {ns.to_text()}"
        print(line)
        save(line)

    for mx in dns.resolver.resolve(domain, 'MX'):
        line = f"MX Record: {mx.to_text()}"
        print(line)
        save(line)

    for txt in dns.resolver.resolve(domain, 'TXT'):
        line = f"TXT Record: {txt.to_text()}"
        print(line)
        save(line)

except Exception as e:
    print("[-] DNS lookup failed:", e)
    save(f"DNS Error: {e}")


# ---------------------------------
# GEOLOCATION MODULE
# ---------------------------------
print("[+] Getting geolocation info...")
save("\n===== GEOLOCATION DATA =====")

try:
    ip_addr = socket.gethostbyname(domain)
    url = f"https://geolocation-db.com/json/{ip_addr}"

    response = requests.get(url).json()

    geo_text = (
        f"Country: {response.get('country_name')}\n"
        f"Latitude: {response.get('latitude')}\n"
        f"Longitude: {response.get('longitude')}\n"
        f"City: {response.get('city')}\n"
        f"State: {response.get('state')}"
    )

    print(geo_text)
    save(geo_text)

except Exception as e:
    print("[-] Geolocation lookup failed:", e)
    save(f"Geolocation Error: {e}")


# ---------------------------------
# SHODAN MODULE
# ---------------------------------

if ip:
    print("[+] Performing Shodan search...")
    save("\n===== SHODAN RESULTS =====")

    try:
        api = shodan.Shodan("9hew3msxGxgi0L8tQsKmik8zBQXFUb6D")

        results = api.host(ip)

        shodan_info = (
            f"IP: {results.get('ip_str')}\n"
            f"Organization: {results.get('org')}\n"
            f"Operating System: {results.get('os')}\n"
            f"Open Ports: {results.get('ports')}\n"
        )

        print(shodan_info)
        save(shodan_info)

        for item in results['data']:
            banner = "\n--- Banner ---\n" + str(item.get('data'))
            print(banner)
            save(banner)

    except shodan.APIError as e:
        print("[-] Shodan API error:", e)
        save(f"Shodan Error: {e}")

    except Exception as e:
        print("[-] Unexpected error:", e)
        save(f"Unknown Error: {e}")
