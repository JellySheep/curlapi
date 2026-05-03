import requests
import json
import time
import re
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor

NVD_IGNORE_LIST = ["NVD-CWE-Other", "NVD-CWE-noinfo"]
CWE_CACHE = {}

def clean_description(raw_text):
    if not raw_text:
        return ""
    # 1. Пытаемся вытащить суть
    match = re.search(r"CVE-\d{4}-\d+:\s*(.*)", raw_text, re.DOTALL | re.IGNORECASE)
    text = match.group(1).strip() if match else raw_text.strip()
    
    # 2. слово "Description", даты (YYYY-MM-DD), версии (8.x.x)
    text = re.sub(r'(?i)^description[:\s]*', '', text)
    text = re.sub(r'\d{4}-\d{2}-\d{2}', '', text)
    text = re.sub(r'\b\d+\.\d+\.\d+\b', '', text)
    
    # 3. "lib" и остатки технических префиксов curl
    text = re.sub(r'^\s*[M|L|H]\s+lib\s+', '', text, flags=re.MULTILINE)
    
    # 4. лишние пробелы и переносы
    text = re.sub(r'\n\s*\n', '\n', text) 
    return text.strip()

def get_affected_versions_from_site(cve_id):
    url = f"https://curl.se/docs/{cve_id}.html"
    versions = set()
    try:
        res = requests.get(url, timeout=10)
        if res.status_code == 200:
            soup = BeautifulSoup(res.text, 'html.parser')
            text = soup.get_text()
            range_match = re.search(r"Affected versions: curl\s+([\d\.]+)\s+to\s+(?:and including\s+)?([\d\.]+)", text)
            if range_match:
                versions.add(range_match.group(1))
                versions.add(range_match.group(2))
            all_v = re.findall(r"curl\s+(\d+\.\d+\.\d+)", text)
            for v in all_v: versions.add(v)
    except: pass
    return list(versions)

def get_cwe_from_curl_site(cve_id):
    url = f"https://curl.se/docs/{cve_id}.html"
    try:
        res = requests.get(url, timeout=10)
        if res.status_code == 200:
            found = re.findall(r'CWE-\d+', res.text)
            return [c for c in set(found) if c not in NVD_IGNORE_LIST]
    except: pass
    return []

def get_unified_cwe_info(cwe_id):
    if cwe_id in NVD_IGNORE_LIST or "unknown" in cwe_id.lower():
        return {"name": "Unclassified", "description": "No data found."}

    if cwe_id in CWE_CACHE:
        return CWE_CACHE[cwe_id]

    nvd_cwe_url = f"https://services.nvd.nist.gov/rest/json/cwe/2.0?cweId={cwe_id}"
    try:
        res = requests.get(nvd_cwe_url, timeout=10)
        if res.status_code == 200:
            data = res.json().get('cwe', [])
            if data:
                result = {
                    "name": data[0].get('title', f"Weakness {cwe_id}"),
                    "description": clean_description(data[0].get('description', [{}])[0].get('value', ""))
                }
                CWE_CACHE[cwe_id] = result
                return result
    except: pass

    try:
        cwe_num = re.search(r'\d+', cwe_id).group()
        mitre_url = f"https://cwe.mitre.org/data/definitions/{cwe_num}.html"
        res = requests.get(mitre_url, timeout=10)
        if res.status_code == 200:
            soup = BeautifulSoup(res.text, 'html.parser')
            name_tag = soup.find('h2')
            name = name_tag.text.split(':')[-1].strip() if name_tag else f"Weakness {cwe_id}"
            desc_div = soup.find('div', id='Description')
            desc = clean_description(desc_div.text) if desc_div else "Description not available."
            result = {"name": name, "description": desc}
            CWE_CACHE[cwe_id] = result
            return result
    except: pass

    return {"name": f"Security Weakness {cwe_id}", "description": "Details not available."}

def get_cve_details(cve_id, versions_from_main, raw_desc, vendor_date):
    print(f"[*] Обогащение {cve_id}...")
    mitre_url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
    nvd_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    nvd_headers = {"apiKey": "05d54d83-41ee-4771-92f2-3877642ebaff"}
    
    top_cvss = {}
    cpe_list = set()
    pub_date, upd_date = vendor_date, vendor_date
    cna = {}

    def update_max_cvss(ver, score, vector, severity):
        ver_str = str(ver)
        try:
            score_float = float(score)
        except:
            score_float = 0.0
        if ver_str not in top_cvss or score_float > top_cvss[ver_str]['score']:
            top_cvss[ver_str] = {
                "version": ver_str,
                "score": score_float,
                "vector": vector,
                "severity": str(severity).upper()
            }

    # 1. MITRE
    try:
        m_res = requests.get(mitre_url, timeout=10)
        if m_res.status_code == 200:
            m_data = m_res.json()
            cna = m_data.get('containers', {}).get('cna', {})
            for m in cna.get('metrics', []):
                for k in ['cvssV4_0', 'cvssV3_1', 'cvssV3_0']:
                    if k in m:
                        v = m[k]
                        update_max_cvss(
                            v.get('version', k[-3:].replace('_', '.')), 
                            v.get('baseScore', 0.0),
                            v.get('vectorString', "n/a"),
                            v.get('baseSeverity', 'UNKNOWN')
                        )
    except: pass

    # 2. NVD
    n_data_full = None
    try:
        n_res = requests.get(nvd_url, headers=nvd_headers, timeout=10)
        if n_res.status_code == 200:
            n_data_full = n_res.json().get('vulnerabilities', [])
            if n_data_full:
                cve_nvd = n_data_full[0].get('cve', {})
                pub_date = cve_nvd.get('published', vendor_date)
                upd_date = cve_nvd.get('lastModified', vendor_date)
                
                metrics = cve_nvd.get('metrics', {})
                for m_ver in ['cvssMetricV40', 'cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                    for entry in metrics.get(m_ver, []):
                        cvss_data = entry.get('cvssData', {})
                        update_max_cvss(
                            cvss_data.get('version', m_ver[-2:].replace('V', '').replace('0', '0.0').replace('31', '3.1')),
                            cvss_data.get('baseScore', 0.0),
                            cvss_data.get('vectorString', "n/a"),
                            (cvss_data.get('baseSeverity') or entry.get('baseSeverity') or "UNKNOWN")
                        )
    except: pass
        
    cvss_list = sorted(top_cvss.values(), key=lambda x: x['version'], reverse=True)

    # 3. CPE
    site_vers = get_affected_versions_from_site(cve_id)
    for v in site_vers: cpe_list.add(f"cpe:2.3:a:haxx:curl:{v.strip('.')}:*:*:*:*:*:*:*")
    if not cpe_list and cna:
        for node in cna.get('affected', []):
            for v_entry in node.get('versions', []):
                ver = v_entry.get('version')
                if ver and ver not in ['0', 'n/a']:
                    cpe_list.add(f"cpe:2.3:a:haxx:curl:{ver.strip()}:*:*:*:*:*:*:*")
    if not cpe_list and n_data_full:
        for config in n_data_full[0].get('cve', {}).get('configurations', []):
            for node in config.get('nodes', []):
                for match in node.get('cpeMatch', []):
                    cpe_list.add(match.get('criteria'))
    if not cpe_list:
        for v in versions_from_main:
            cpe_list.add(f"cpe:2.3:a:haxx:curl:{v.strip('.')}:*:*:*:*:*:*:*")
    if not cpe_list: cpe_list.add("cpe:2.3:a:haxx:curl:*:*:*:*:*:*:*:*")

    # 4. CWE
    cwe_ids = set(get_cwe_from_curl_site(cve_id))
    if cna:
        for pt in cna.get('problemTypes', []):
            for p_desc in pt.get('descriptions', []):
                cid = p_desc.get('cweId')
                if cid and 'CWE-' in cid: cwe_ids.add(cid)
    if not cwe_ids and n_data_full:
        weaknesses = n_data_full[0].get('cve', {}).get('weaknesses', [])
        for w in weaknesses:
            for w_desc in w.get('description', []):
                cid = w_desc.get('value')
                if cid and 'CWE-' in cid: cwe_ids.add(cid)

    final_cwes = {cid: get_unified_cwe_info(cid) for cid in cwe_ids if cid not in NVD_IGNORE_LIST}
    if not final_cwes: final_cwes["CWE-unknown"] = {"name": "Unclassified", "description": "No data found."}

    desc_val = cna.get('descriptions', [{}])[0].get('value', raw_desc) if cna else raw_desc
    
    return {
        "published_date": pub_date,
        "updated_date": upd_date,
        "description": clean_description(desc_val),
        "cvss_list": cvss_list or [{"version": "3.1", "score": 0.0, "vector": "n/a", "severity": "NONE"}],
        "cpe_list": sorted(list(cpe_list)),
        "cwe": final_cwes
    }

def process_item(item):
    try:
        details = get_cve_details(item['ID'], item['tmp_versions'], item['raw_desc'], item['vendor_release_date'])
        entry = {k: v for k, v in item.items() if k not in ['tmp_versions', 'raw_desc']}
        entry.update(details)
        time.sleep(0.3) 
        return entry
    except Exception as e:
        print(f"[!] Ошибка потока для {item['ID']}: {e}")
        return None

def main():
    print("[*] Task 1: Scraping curl.se...")
    try:
        res = requests.get("https://curl.se/docs/security.html", timeout=15)
        soup = BeautifulSoup(res.text, 'html.parser')
        t1, t2_pre = [], []
        for row in soup.find_all('tr'):
            links = row.find_all('a', href=re.compile(r'CVE-\d{4}-\d+'))
            if not links: continue
            cve_id = re.search(r'CVE-\d{4}-\d+', links[0].text).group()
            cols = row.find_all('td')
            v_main = re.findall(r'(\d+\.\d+(?:\.\d+)?)', cols[3].text) if len(cols) >= 4 else []
            date_m = re.search(r'\d{4}-\d{2}-\d{2}', row.get_text())
            rel_date = date_m.group(0) if date_m else "2024-01-01"
            
            item = {"ID": cve_id, "vendor_release_date": rel_date, "vendor_release_url": f"https://curl.se/docs/{cve_id}.html"}
            if not any(d['ID'] == cve_id for d in t1):
                t1.append(item)
                t2_pre.append({**item, "tmp_versions": v_main, "raw_desc": row.get_text()})

        with open('result_task_1.json', 'w') as f: json.dump(t1, f, indent=4)
        
        print(f"[*] Task 2: Enriching {len(t2_pre)} items using 5 threads...")
        with ThreadPoolExecutor(max_workers=5) as executor:
            results = list(executor.map(process_item, t2_pre))
            
        final = [r for r in results if r is not None]
        with open('result_task_2.json', 'w', encoding='utf-8') as f:
            json.dump(final, f, indent=4, ensure_ascii=False)
            
        print("[+] Done.")
    except Exception as e: print(f"[!] Critical Error: {e}")

if __name__ == "__main__":
    main()
