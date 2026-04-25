import json
import psycopg2
from datetime import datetime
import os

# Настройки подключения (согласно docker-compose)
DB_CONFIG = {
    "dbname": "curl_vulnerabilities",
    "user": "artem",
    "password": "password",
    "host": os.getenv("DB_HOST", "localhost"), # Будет искать 'db', если в докере
    "port": "5432"
}

def parse_date(date_str):
    if not date_str:
        return None
    try:
        # Простая попытка привести к формату для Postgres
        return date_str.split('T')[0]
    except:
        return None

def fill_db():
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()
        print("[*] Подключено к базе данных.")

        with open('result_task_2.json', 'r', encoding='utf-8') as f:
            data = json.load(f)

        for item in data:
            # 1. Вставка в основную таблицу vulnerabilities
            cur.execute("""
                INSERT INTO vulnerabilities 
                (cve_id, vendor_release_date, vendor_release_url, cve_url, published_date, updated_date, description)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (cve_id) DO UPDATE SET description = EXCLUDED.description
                RETURNING id;
            """, (
                item.get('ID'),
                parse_date(item.get('vendor_release_date')),
                item.get('vendor_release_url'),
                item.get('url'),
                parse_date(item.get('published_date')),
                parse_date(item.get('updated_date')),
                item.get('description')
            ))
            
            v_id = cur.fetchone()[0]

            # 2. Вставка CVSS
            for cvss in item.get('cvss_list', []):
                cur.execute("""
                    INSERT INTO cvss_metrics (vulnerability_id, version, score, severity, vector)
                    VALUES (%s, %s, %s, %s, %s)
                """, (v_id, cvss.get('version'), cvss.get('score'), cvss.get('severity'), cvss.get('vector')))

            # 3. Вставка CPE
            for cpe in item.get('cpe_list', []):
                cur.execute("INSERT INTO cpe_entries (vulnerability_id, cpe_string) VALUES (%s, %s)", (v_id, cpe))

            # 4. Вставка CWE
            cwe_data = item.get('cwe', {})
            for cwe_id, info in cwe_data.items():
                cur.execute("""
                    INSERT INTO cwe_entries (vulnerability_id, cwe_id, name, description)
                    VALUES (%s, %s, %s, %s)
                """, (v_id, cwe_id, info.get('name'), info.get('description')))

        conn.commit()
        print(f"[+] База данных успешно заполнена! Обработано {len(data)} записей.")

    except Exception as e:
        print(f"[-] Ошибка при заполнении БД: {e}")
    finally:
        if conn:
            cur.close()
            conn.close()

if __name__ == "__main__":
    fill_db()
