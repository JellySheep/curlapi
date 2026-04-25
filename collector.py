import requests
import json
import time

def get_cve_details(cve_id):
    print(f"[*] Запрашиваю данные для {cve_id}...")
    url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
    try:
        res = requests.get(url, timeout=10)
        if res.status_code != 200: 
            print(f"[!] Ошибка API для {cve_id}: {res.status_code}")
            return None
        data = res.json()
    except Exception as e:
        print(f"[!] Ошибка сети: {e}")
        return None

    cna = data.get('containers', {}).get('cna', {})
    
    # 1. Извлекаем CVSS
    cvss_list = []
    for m in cna.get('metrics', []):
        for key in ['cvssV3_1', 'cvssV3_0', 'cvssV4_0', 'cvssV2_0']:
            if key in m:
                v = m[key]
                cvss_list.append({
                    "version": str(v.get('version', key.replace('cvssV', '').replace('_', '.'))),
                    "score": v.get('baseScore', 0.0),
                    "vector": v.get('vectorString', "n/a"),
                    "severity": str(v.get('baseSeverity', 'UNKNOWN')).upper()
                })

    # Заглушка для CVSS, если данных нет (нужна для Задачи 4)
    if not cvss_list:
        cvss_list.append({
            "version": "n/a",
            "score": 0.0,
            "vector": "n/a",
            "severity": "NONE"
        })

    # 2. Извлекаем CPE
    cpe_list = []
    for aff in cna.get('affected', []):
        raw_cpes = aff.get('cpes', [])
        for cpe in raw_cpes:
            if "http" in cpe or "n/a" in cpe:
                continue
            cpe_list.append(cpe)
            
    if not cpe_list:
        cpe_list.append("cpe:2.3:a:haxx:curl:*:*:*:*:*:*:*:*")
    
    cpe_list = list(set(cpe_list)) # Удаляем дубли

    # 3. Извлекаем CWE
    cwe_dict = {}
    for pt in cna.get('problemTypes', []):
        for desc in pt.get('descriptions', []):
            if desc.get('cweId'):
                cid = desc['cweId']
                cwe_dict[cid] = {
                    "name": desc.get('description', cid), 
                    "description": desc.get('description', cid)
                }

    if not cwe_dict:
        cwe_dict["None"] = {"name": "n/a", "description": "n/a"}

    return {
        # Добавляем or "" (пустую строку), чтобы не было null (None)
        "published_date": data.get('cveMetadata', {}).get('datePublished') or "",
        "updated_date": data.get('cveMetadata', {}).get('dateUpdated') or "",
        "description": cna.get('descriptions', [{}])[0].get('value', 'No description'),
        "cvss_list": cvss_list,
        "cpe_list": cpe_list,
        "cwe": cwe_dict
    }
def main():
    try:
        with open('result_task_1.json', 'r', encoding='utf-8') as f:
            task1_data = json.load(f)
    except FileNotFoundError:
        print("[-] Файл result_task_1.json не найден!")
        return

    final_results = []

    for item in task1_data:
        cve_id = item.get('ID')
        if not cve_id: continue
        
        details = get_cve_details(cve_id)
        
        if details:
            full_entry = item.copy()
            full_entry.update(details)
            # Если поле url из задачи 1 отсутствует, создаем его для валидатора
            if 'url' not in full_entry and 'vendor_release_url' in full_entry:
                full_entry['url'] = full_entry['vendor_release_url']
                
            final_results.append(full_entry)
        
        time.sleep(0.5)

    with open('result_task_2.json', 'w', encoding='utf-8') as f:
        json.dump(final_results, f, indent=4, ensure_ascii=False)
    
    print(f"[+] Готово! Обработано {len(final_results)} записей. Файл: result_task_2.json")

if __name__ == "__main__":
    main()
