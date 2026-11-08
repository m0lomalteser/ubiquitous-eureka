import os
import re
import time
import requests
from bs4 import BeautifulSoup

# URL des Apple Security Advisories
APPLE_URL = "https://support.apple.com/en-us/149230"

# Optional: GitHub Personal Token für höhere API-Rate-Limits (wird dringend empfohlen)
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")

def fetch_cves_from_apple():
    """Lädt die Apple-Support-Seite und extrahiert alle eindeutigen CVE-Nummern."""
    print(lese := f"[*] Lade Apple-Support-Seite: {APPLE_URL} ...")
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    }
    
    try:
        response = requests.get(APPLE_URL, headers=headers, timeout=15)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"[!] Fehler beim Abrufen der Apple-Seite: {e}")
        return []

    # BeautifulSoup nutzen, um den Text zu parsen
    soup = BeautifulSoup(response.text, 'html.parser')
    page_text = soup.get_text()

    # Regex für CVE-Muster (z.B. CVE-2026-12345 oder CVE-2023-12345)
    cve_pattern = r"CVE-\d{4}-\d{4,7}"
    found_cves = sorted(list(set(re.findall(cve_pattern, page_text))))
    
    print(f"[+] {len(found_cves)} eindeutige CVEs auf der Seite gefunden.")
    return found_cves

def search_github_for_cve(cve):
    """Durchsucht GitHub nach Repositories, die die CVE-Nummer erwähnen."""
    url = f"https://api.github.com/search/repositories?q={cve}+in:readme,description,name"
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "Apple-CVE-PoC-Checker"
    }
    
    if GITHUB_TOKEN:
        headers["Authorization"] = f"token {GITHUB_TOKEN}"

    try:
        response = requests.get(url, headers=headers, timeout=10)
        
        # Bei Rate-Limit-Überschreitung kurz warten
        if response.status_code == 403:
            print(f"    [!] Rate-Limit erreicht (403). Warte 10 Sekunden...")
            time.sleep(10)
            response = requests.get(url, headers=headers, timeout=10)
            
        if response.status_code == 200:
            data = response.json()
            items = data.get("items", [])
            urls = [item["html_url"] for item in items]
            return urls
        else:
            print(f"    [!] GitHub API Fehler für {cve}: Statuscode {response.status_code}")
            return []
            
    except requests.exceptions.RequestException as e:
        print(f"    [!] Netzwerkfehler bei GitHub-Abfrage für {cve}: {e}")
        return []

def main():
    cves = fetch_cves_from_apple()
    if not cves:
        print("[!] Keine CVEs gefunden oder Zugriff verweigert.")
        return

    print("\n[*] Starte GitHub-Suche nach PoCs / Repositories...\n" + "="*50)
    
    results = {}
    for i, cve in enumerate(cves, 1):
        print(f"[{i}/{len(cves)}] Suche nach {cve} ...")
        repos = search_github_for_cve(cve)
        
        if repos:
            print(f"    [+] Treffer gefunden! ({len(repos)} Repositories)")
            for repo in repos:
                print(f"        -> {repo}")
            results[cve] = repos
        else:
            print(f"    [-] Keine öffentlichen Repositories gefunden.")
        
        # Höflichkeits-Pause gegen GitHub Rate-Limits (ohne Token besonders wichtig)
        time.sleep(2)

    print("\n" + "="*50)
    print("[*] Zusammenfassung:")
    if results:
        print(f"[+] Für folgende CVEs wurden GitHub-Treffer erzielt:")
        for cve, urls in results.items():
            print(f"    - {cve}:")
            for u in urls:
                print(f"        {u}")
    else:
        print("[-] Für keine der gefundenen CVEs wurden auf Anhieb öffentliche GitHub-Treffer erzielt.")

if __name__ == "__main__":
    main()
