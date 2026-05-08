import requests
import json
import time
import re
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor

NVD_IGNORE_LIST = ["NVD-CWE-Other", "NVD-CWE-noinfo"]
CWE_CACHE = {}

def clean_text_data(raw_text):
    if not raw_text:
        return ""
    # Очистка от мусорных символов разметки и лишних пробелов
    text = re.sub(r'[\r\n\t]+', ' ', raw_text)
    text = re.sub(r'\s{2,}', ' ', text)
    return text.strip()

def clean_description(raw_text):
    if not raw_text:
        return ""
    # Убираем префикс CVE-ID
    match = re.search(r"CVE-\d{4}-\d+:\s*(.*)", raw_text, re.DOTALL | re.IGNORECASE)
    text = match.group(1).strip() if match else raw_text.strip()
    
    # Твоя логика чистки специфики curl
    text = re.sub(r'(?i)^description[:\s]*', '', text)
    text = re.sub(r'\d{4}-\d{2}-\d{2}', '', text)
    # Удаляем версии, но сохраняем пробелы для читаемости
    text = re.sub(r'\b\d+\.\d+(?:\.\d+)?\b', '', text)
    text = re.sub(r'libcurl\s*[<>]\s*', 'libcurl ', text)
    text = re.sub(r'(?m)^\s*[M|L|H]\s+lib\s+', '', text)
    
    return clean_text_data(text)

def get_affected_versions_from_site(cve_id):
    url = f"https://curl.se/docs/{cve_id}.html"
    versions = set()
    try:
        res = requests.get(url, timeout=10)
        if res.status_code == 200:
            soup = BeautifulSoup(res.text, 'html.parser')
            text = soup.get_text()
            
            # Строгое выделение блока пораженных версий
            section = re.search(r"Affected versions:(.*?)Not affected versions:", text, re.DOTALL | re.IGNORECASE)
            if section:
                content = section.group(1)
                
                # 1. Диапазоны (curl X to Y)
                ranges = re.findall(r"curl\s+([\d\.]+)\s+to\s+(?:and including\s+)?([\d\.]+)", content)
                for start, end in ranges:
                    versions.add(start.strip('.'))
                    versions.add(end.strip('.'))
                
                # 2. Одиночные версии с учетом операторов (>=, => включают версию, > — нет)
                matches = re.finditer(r"(?P<op>[^0-9]*)\s*curl\s+(?P<ver>\d+\.\d+(?:\.\d+)?)", content)
                for m in matches:
                    op, ver = m.group('op'), m.group('ver').strip('.')
                    if '>' in op and '=' not in op:
                        continue
                    versions.add(ver)
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
    try:
        cwe_num = re.search(r'\d+', cwe_id).group()
        res = requests.get(f"https://cwe.mitre.org/data/definitions/{cwe_num}.html", timeout=10)
        if res.status_code == 200:
            soup = BeautifulSoup(res.text, 'html.parser')
            name = soup.find('h2').text.split(':')[-1].strip() if soup.find('h2') else f"Weakness {cwe_id}"
            desc_div = soup.find('div', id='Description')
            # Используем глубокую очистку для описания CWE
            desc = clean_text_data(desc_div.text) if desc_div else "Description not available."
            result = {"name": name, "description": desc}
            CWE_CACHE[cwe_id] = result
            return result
    except: pass
    return {"name": f"Security Weakness {cwe_id}", "description": "Details not available."}

def get_cve_details(cve_id, versions_from_main, raw_desc, vendor_date):
    print(f"[*] Обогащение {cve_id}...")
    mitre_url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
    top_cvss, cpe_list = {}, set()
    pub_date, upd_date = vendor_date, vendor_date
    cna = {}

    def update_max_cvss(metrics_list):
        for m in metrics_list:
            for k in ['cvssV4_0', 'cvssV3_1', 'cvssV3_0', 'cvssV2_0']:
                if k in m:
                    v = m[k]
                    ver_str = v.get('version', k[-3:].replace('_', '.'))
                    score = float(v.get('baseScore', 0.0))
                    if ver_str not in top_cvss or score > top_cvss[ver_str]['score']:
                        top_cvss[ver_str] = {
                            "version": ver_str, "score": score,
                            "vector": v.get('vectorString', "n/a"),
                            "severity": str(v.get('baseSeverity', 'UNKNOWN')).upper()
                        }

    try:
        m_res = requests.get(mitre_url, timeout=10)
        if m_res.status_code == 200:
            m_data = m_res.json()
            meta = m_data.get('cveMetadata', {})
            pub_date = (meta.get('datePublished') or vendor_date)[:10]
            upd_date = (meta.get('dateUpdated') or pub_date)[:10]
            cna = m_data.get('containers', {}).get('cna', {})
            update_max_cvss(cna.get('metrics', []))
            for adp in m_data.get('containers', {}).get('adp', []):
                update_max_cvss(adp.get('metrics', []))

            for node in cna.get('affected', []):
                for v_entry in node.get('versions', []):
                    if v_entry.get('status') in ['fixed', 'not affected']: continue
                    ver = v_entry.get('version')
                    if ver and re.match(r'^\d', str(ver)) and ver != 'n/a':
                        cpe_list.add(f"cpe:2.3:a:haxx:curl:{str(ver).strip()}:*:*:*:*:*:*:*")
    except: pass

    # Слияние версий (сайт + главная таблица)
    site_vers = get_affected_versions_from_site(cve_id)
    # Фильтруем версии из главной таблицы на наличие признаков фикса в строке
    filtered_main = [v for v in versions_from_main if not re.search(r'(fixed|not affected).*?' + re.escape(v), raw_desc, re.I)]
    
    for v in (set(site_vers) | set(filtered_main)):
        cpe_list.add(f"cpe:2.3:a:haxx:curl:{v.strip('.')}:*:*:*:*:*:*:*")
    
    if not cpe_list: cpe_list.add("cpe:2.3:a:haxx:curl:*:*:*:*:*:*:*:*")

    cwe_ids = set(get_cwe_from_curl_site(cve_id))
    if cna:
        for pt in cna.get('problemTypes', []):
            for p_desc in pt.get('descriptions', []):
                cid = p_desc.get('cweId')
                if cid and 'CWE-' in cid: cwe_ids.add(cid)

    final_cwes = {cid: get_unified_cwe_info(cid) for cid in cwe_ids if cid not in NVD_IGNORE_LIST}
    if not final_cwes: final_cwes["CWE-unknown"] = {"name": "Unclassified", "description": "No data found."}

    desc_val = cna.get('descriptions', [{}])[0].get('value', raw_desc) if cna else raw_desc

    return {
        "url": f"https://www.cve.org/CVERecord?id={cve_id}",
        "published_date": pub_date,
        "updated_date": upd_date,
        "description": clean_description(desc_val),
        "cvss_list": sorted(top_cvss.values(), key=lambda x: x['version'], reverse=True) or [{"version": "3.1", "score": 0.0, "vector": "n/a", "severity": "NONE"}],
        "cpe_list": sorted(list(cpe_list)),
        "cwe": final_cwes
    }

def process_item(item):
    try:
        details = get_cve_details(item['ID'], item['tmp_versions'], item['raw_desc'], item['vendor_release_date'])
        entry = {k: v for k, v in item.items() if k not in ['tmp_versions', 'raw_desc']}
        entry.update(details)
        return entry
    except Exception as e:
        print(f"[!] Ошибка для {item['ID']}: {e}")
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
            # Паттерн версии поддерживает X.Y и X.Y.Z
            v_main = re.findall(r'(\d+\.\d+(?:\.\d+)?)', cols[3].text) if len(cols) >= 4 else []
            date_m = re.search(r'\d{4}-\d{2}-\d{2}', row.get_text())
            rel_date = date_m.group(0) if date_m else "2024-01-01"
            
            item = {"ID": cve_id, "vendor_release_date": rel_date, "vendor_release_url": f"https://curl.se/docs/{cve_id}.html"}
            if not any(d['ID'] == cve_id for d in t1):
                t1.append(item)
                t2_pre.append({**item, "tmp_versions": v_main, "raw_desc": row.get_text()})

        with open('result_task_1.json', 'w') as f: json.dump(t1, f, indent=4)

        print(f"[*] Task 2: Enriching {len(t2_pre)} items...")
        with ThreadPoolExecutor(max_workers=5) as executor:
            results = list(executor.map(process_item, t2_pre))

        final = [r for r in results if r is not None]
        with open('result_task_2.json', 'w', encoding='utf-8') as f:
            json.dump(final, f, indent=4, ensure_ascii=False)
        print("[+] Done.")
    except Exception as e: print(f"[!] Critical Error: {e}")

if __name__ == "__main__":
    main()
