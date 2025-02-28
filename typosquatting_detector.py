import itertools
import dns.resolver
import whois
import requests
import ssl
import socket
import time
import random
import csv
from tqdm import tqdm
from bs4 import BeautifulSoup
from fuzzywuzzy import fuzz

def generate_typo_domains(domain):
    typo_variations = set()
    base_name, tld = domain.rsplit('.', 1)
    
    # 1. Errori di battitura comuni (scambio di lettere adiacenti)
    for i in range(len(base_name) - 1):
        typo = list(base_name)
        typo[i], typo[i + 1] = typo[i + 1], typo[i]
        typo_variations.add("".join(typo) + '.' + tld)
    
    # 2. Aggiunta o omissione di lettere
    for i in range(len(base_name)):
        typo_variations.add(base_name[:i] + base_name[i+1:] + '.' + tld)  # Omissione
    
    for char in 'abcdefghijklmnopqrstuvwxyz':
        for i in range(len(base_name) + 1):
            typo_variations.add(base_name[:i] + char + base_name[i:] + '.' + tld)  # Aggiunta
    
    # 3. Sostituzione con caratteri simili
    replacements = {'o': '0', 'i': '1', 'l': '1', 's': '5', 'e': '3', 'a': '@'}
    for key, val in replacements.items():
        typo_variations.add(base_name.replace(key, val) + '.' + tld)
    
    # 4. Cambio del TLD
    common_tlds = ['com', 'net', 'org', 'info', 'biz']
    for new_tld in common_tlds:
        typo_variations.add(base_name + '.' + new_tld)
    
    return list(typo_variations)

def check_domain_exists(domain):
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['8.8.8.8', '1.1.1.1']  # Usa Google e Cloudflare DNS
    try:
        resolver.resolve(domain, 'A')
        return True
    except dns.resolver.NXDOMAIN:
        return False
    except dns.resolver.NoAnswer:
        return False
    except dns.resolver.LifetimeTimeout:
        return False
    except dns.resolver.NoNameservers:
        return False

def get_whois_info(domain):
    try:
        w = whois.whois(domain)
        return w.domain_name, w.registrar, w.creation_date, w.expiration_date
    except:
        return None, None, None, None

def get_ip_address(domain):
    try:
        answer = dns.resolver.resolve(domain, 'A')
        return [ip.to_text() for ip in answer]
    except:
        return None

def get_mx_record(domain):
    try:
        answer = dns.resolver.resolve(domain, 'MX')
        return [mx.to_text() for mx in answer]
    except:
        return None

def get_ssl_certificate(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return cert.get('issuer'), cert.get('notBefore'), cert.get('notAfter')
    except:
        return None, None, None

def check_redirect(domain):
    try:
        response = requests.get("http://" + domain, timeout=5, allow_redirects=True)
        if response.history:
            return response.url  # URL finale dopo i redirect
        return None
    except:
        return None

def check_ip_abuse(ip, api_key):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": api_key,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }
    try:
        response = requests.get(url, headers=headers, params=params)
        data = response.json()
        return data.get("data", {}).get("abuseConfidenceScore", 0)
    except:
        return None

def analyze_typosquatting(main_domain, check_abuse=False, api_key=None):
    typo_domains = generate_typo_domains(main_domain)
    detected_domains = []
    checked_ips = {}
    
    with open("typosquatting_results.csv", "w", newline="") as csvfile:
        fieldnames = ["domain", "whois", "ip", "mx_record", "ssl_issuer", "ssl_valid_from", "ssl_valid_to", "redirect", "abuse_score"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
    
        for typo in tqdm(typo_domains, desc="Scanning typosquatting domains"):
            time.sleep(random.uniform(1, 3))  # Random sleep
            
            if check_domain_exists(typo):
                whois_info = get_whois_info(typo)
                ip_address = get_ip_address(typo)
                mx_record = get_mx_record(typo)
                ssl_issuer, ssl_valid_from, ssl_valid_to = get_ssl_certificate(typo)
                redirect_url = check_redirect(typo)
                abuse_score = None
                
                if check_abuse and api_key and ip_address:
                    for ip in ip_address:
                        if ip not in checked_ips:
                            checked_ips[ip] = check_ip_abuse(ip, api_key)
                        abuse_score = checked_ips[ip]
                
                result = {
                    "domain": typo,
                    "whois": whois_info,
                    "ip": ip_address,
                    "mx_record": mx_record,
                    "ssl_issuer": ssl_issuer,
                    "ssl_valid_from": ssl_valid_from,
                    "ssl_valid_to": ssl_valid_to,
                    "redirect": redirect_url,
                    "abuse_score": abuse_score
                }
                detected_domains.append(result)
                writer.writerow(result)
    
    return detected_domains

if __name__ == "__main__":
    main_domain = input("Inserisci il dominio principale (es. google.com): ")
    check_abuse = input("Vuoi controllare gli IP su AbuseIPDB? (s/n): ").strip().lower() == 's'
    api_key = None
    if check_abuse:
        api_key = input("Inserisci la tua API Key di AbuseIPDB: ")
    results = analyze_typosquatting(main_domain, check_abuse, api_key)
    
    print("\nDomini sospetti trovati:")
    for result in results:
        print(f"{result['domain']} - WHOIS: {result['whois']} - IP: {result['ip']} - MX: {result['mx_record']} - SSL: {result['ssl_issuer']} - Redirect: {result['redirect']} - Abuse Score: {result['abuse_score']}")