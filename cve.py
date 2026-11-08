import os
import re
import time
import requests
from bs4 import BeautifulSoup

APPLE_URL = "https://support.apple.com/en-us/149230"
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
OUTPUT_FILE = "cve_results.txt"

def fetch_cves_from_apple():
    print(f"[*] Lade Apple-Support-Seite: {APPLE_URL} ...")
    headers = {"User-Agent": "Mozilla/5.0 (compatible; CVE-Bot/1.0)"}
    try:
        response = requests.get(APPLE_URL, headers=headers, timeout=15)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"[!] Fehler beim Abrufen der Apple-Seite: {e}")
        return []

    soup = BeautifulSoup(response.text, 'html.parser')
    page_text = soup.get_text()
    cve_pattern = r"CVE-\d{4}-\d{4,7}"
    return sorted(list(set(re.findall(cve_pattern, page_text))))

def search_github_for_cve(cve):
    url = f"https://api.github.com/search/repositories?q={cve}+in:readme,description,name"
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "Apple-CVE-PoC-Checker"
    }
    if GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"

    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 403:
            print("    [!] Rate-Limit erreicht. Warte 10 Sekunden...")
            time.sleep(10)
            response = requests.get(url, headers=headers, timeout=10)
            
        if response.status_code == 200:
            return [item["html_url"] for item in response.json().get("items", [])]
        return []
    except requests.exceptions.RequestException:
        return []

def main():
    cves = fetch_cves_from_apple()
    if not cves:
        return

    results = {}
    for i, cve in enumerate(cves, 1):
        print(f"[{i}/{len(cves)}] Prüfe {cve} ...")
        repos = search_github_for_cve(cve)
        if repos:
            results[cve] = repos
        time.sleep(1.5) # Etwas Pause für die API

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(f"Apple CVE GitHub Suchergebnisse für {APPLE_URL}\n")
        f.write("="*50 + "\n\n")
        if results:
            for cve, urls in results.items():
                f.write(f"{cve}:\n")
                for u in urls:
                    f.write(f"  - {u}\n")
                f.write("\n")
        else:
            f.write("Keine Repositories gefunden.\n")
    print(f"[+] Fertig. Gespeichert in {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
