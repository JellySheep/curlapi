import requests
import json
import time
import re
import pandas as pd
from bs4 import BeautifulSoup
from cwe2.database import Database

# Инициализируем БД CWE
CWE_DB = Database()
FSTEC_EXCEL_MAP = None
NVD_IGNORE_LIST = ["NVD-CWE-Other", "NVD-CWE-noinfo"]

def clean_description(raw_text):
    match = re.search(r"(CVE-\d{4}-\d+:.+)", raw_text, re.DOTALL)
    if match:
        return match.group(1).strip()
    return re.sub(r'^\d+\s+[M|L|H]\s+lib\s+', '', raw_text.strip(), flags=re.MULTILINE).strip()

def get_affected_versions_from_site(cve_id):
    url = f"https://curl.se/docs/{cve_id}.html"
    versions = set()
    try:
        res = requests.get(url, timeout=10)
        if res.status_code == 200:
            soup = BeautifulSoup(res.text, 'html.parser')
            text = soup.get_text()
            # Ищем диапазон: 8.11.0 to 8.15.0
            range_match = re.search(r"Affected versions: curl\s+([\d\.]+)\s+to\s+(?:and including\s+)?([\d\.]+)", text)
            if range_match:
                versions.add(range_match.group(1))
                versions.add(range_match.group(2))
            # Ищем любые упоминания версий
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

def get_fstec_cwes(cve_id, file_path='vullist.xlsx'):
    global FSTEC_EXCEL_MAP
    if FSTEC_EXCEL_MAP is None:
        FSTEC_EXCEL_MAP = {}
        try:
            df = pd.read_excel(file_path, header=2)
            cve_col, cwe_col = "Идентификаторы других систем описаний уязвимости", "Тип ошибки CWE"
            if cve_col in df.columns and cwe_col in df.columns:
                df = df.dropna(subset=[cve_col, cwe_col])
                for _, row in df.iterrows():
                    found_cves = re.findall(r'CVE-\d{4}-\d+', str(row[cve_col]))
                    cwe_val = str(row[cwe_col]).strip()
                    if "CWE-" in cwe_val:
                        for cve in found_cves:
                            if cve not in FSTEC_EXCEL_MAP: FSTEC_EXCEL_MAP[cve] = set()
                            FSTEC_EXCEL_MAP[cve].add(cwe_val)
        except: FSTEC_EXCEL_MAP = {}
    return list(FSTEC_EXCEL_MAP.get(cve_id, []))

def get_unified_cwe_info(cwe_id):
    try:
        cwe_num = int(re.search(r'\d+', cwe_id).group())
        cwe_obj = CWE_DB.get(cwe_num)
        return {"name": cwe_obj.name, "description": cwe_obj.description or f"Details for {cwe_id}"}
    except:
        return {"name": f"Security Weakness {cwe_id}", "description": "Provided by vendor/FSTEC."}

def get_cve_details(cve_id, versions_from_main, raw_desc, vendor_date):
    print(f"[*] Обогащение {cve_id}...")
    mitre_url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
    nvd_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    nvd_headers = {"apiKey": "05d54d83-41ee-4771-92f2-3877642ebaff"}
    
    cvss_list = []
    cpe_list = set()
    pub_date, upd_date = vendor_date, vendor_date
    cna = {} # Инициализация для предотвращения ошибки UnboundLocalError

    # 1. ЗАПРОС К MITRE
    try:
        m_res = requests.get(mitre_url, timeout=10)
        if m_res.status_code == 200:
            m_data = m_res.json()
            cna = m_data.get('containers', {}).get('cna', {})
            for m in cna.get('metrics', []):
                for k in ['cvssV3_1', 'cvssV3_0', 'cvssV4_0']:
                    if k in m:
                        v = m[k]
                        cvss_list.append({
                            "version": v.get('version', '3.1'),
                            "score": float(v.get('baseScore', 0.0)),
                            "vector": v.get('vectorString', "n/a"),
                            "severity": str(v.get('baseSeverity', 'UNKNOWN')).upper()
                        })
    except: pass

    # 2. ЗАПРОС К NVD (Даты + CVSS если MITRE пустой)
    n_data_full = None
    try:
        n_res = requests.get(nvd_url, headers=nvd_headers, timeout=10)
        if n_res.status_code == 200:
            n_data_full = n_res.json().get('vulnerabilities', [])
            if n_data_full:
                cve_nvd = n_data_full[0].get('cve', {})
                pub_date = cve_nvd.get('published', vendor_date)
                upd_date = cve_nvd.get('lastModified', vendor_date)
                
                # Если MITRE не дал CVSS, берем из NVD
                if not cvss_list:
                    metrics = cve_nvd.get('metrics', {})
                    for m_ver in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                        for entry in metrics.get(m_ver, []):
                            cvss_data = entry.get('cvssData', {})
                            cvss_list.append({
                                "version": cvss_data.get('version', '3.1'),
                                "score": float(cvss_data.get('baseScore', 0.0)),
                                "vector": cvss_data.get('vectorString', "n/a"),
                                "severity": (cvss_data.get('baseSeverity') or entry.get('baseSeverity') or "UNKNOWN").upper()
                            })
    except: pass

    # 3. ЛОГИКА CPE (Сайт -> MITRE -> NVD -> Main Page)
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
            for desc in pt.get('descriptions', []):
                cid = desc.get('cweId')
                if cid and 'CWE-' in cid: cwe_ids.add(cid)
    
    if not cwe_ids: cwe_ids.update(get_fstec_cwes(cve_id))

    final_cwes = {cid: get_unified_cwe_info(cid) for cid in cwe_ids if cid not in NVD_IGNORE_LIST}
    if not final_cwes: final_cwes["CWE-unknown"] = {"name": "Unclassified", "description": "No data found."}

    # Описание
    desc_val = cna.get('descriptions', [{}])[0].get('value', raw_desc) if cna else raw_desc
    
    return {
        "published_date": pub_date,
        "updated_date": upd_date,
        "description": clean_description(desc_val),
        "cvss_list": cvss_list or [{"version": "3.1", "score": 0.0, "vector": "n/a", "severity": "NONE"}],
        "cpe_list": sorted(list(cpe_list)),
        "cwe": final_cwes
    }

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
        
        print("[*] Task 2: Enriching...")
        final = []
        for item in t2_pre:
            details = get_cve_details(item['ID'], item['tmp_versions'], item['raw_desc'], item['vendor_release_date'])
            entry = {k: v for k, v in item.items() if k not in ['tmp_versions', 'raw_desc']}
            entry.update(details)
            final.append(entry)
            time.sleep(0.6) # Чтобы не забанили API

        with open('result_task_2.json', 'w', encoding='utf-8') as f:
            json.dump(final, f, indent=4, ensure_ascii=False)
        print("[+] Done.")
    except Exception as e: print(f"[!] Critical Error: {e}")

if __name__ == "__main__":
    main()
