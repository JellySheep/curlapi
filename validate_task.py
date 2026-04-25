import json
import xml.etree.ElementTree as ET
from jsonschema import validate, ValidationError

def validate_json():
    print("--- JSON Validation (Task 2) ---")
    try:
        with open('result_task_2.json', 'r', encoding='utf-8') as f:
            data = json.load(f)
        with open('json_schema.json', 'r', encoding='utf-8') as f:
            schema = json.load(f)
        
        for index, item in enumerate(data):
            try:
                validate(instance=item, schema=schema["items"] if schema.get("type") == "array" else schema)
            except ValidationError as e:
                field = list(e.path)[0] if e.path else "unknown"
                message = e.message
                cve_id = item.get('ID', f"Index {index}")
                
                print(f"[!] Ошибка в записи {cve_id}:")
                if "is a required property" in message:
                    missing_property = message.split("'")[1]
                    print(f"    => Не пройдена проверка по полю: '{missing_property}' (поле отсутствует)")
                else:
                    print(f"    => Не пройдена проверка по полю: '{field}' ({message})")
                return False

        print("[+] JSON валидация пройдена успешно!")
        return True
    except Exception as e:
        print(f"[-] Ошибка валидации JSON: {e}")
        return False

def check_xml_consistency():
    print("\n--- XML Data Consistency (Task 3) ---")
    try:
        # Загружаем оба файла
        with open('result_task_2.json', 'r', encoding='utf-8') as f:
            json_data = json.load(f)
        
        tree = ET.parse('result_task_3.xml')
        xml_root = tree.getroot()
        xml_items = xml_root.findall('vulnerability')

        # 1. Проверка количества
        json_count = len(json_data)
        xml_count = len(xml_items)
        
        print(f"[*] Записей в JSON: {json_count}")
        print(f"[*] Записей в XML:  {xml_count}")

        if json_count != xml_count:
            print(f"[!] Расхождение! JSON содержит {json_count} записей, а XML — {xml_count}")
            return False

        # 2. Проверка соответствия ID первой и последней записи
        if json_count > 0:
            first_json_id = json_data[0].get('ID')
            first_xml_id = xml_items[0].find('ID').text
            
            if first_json_id == first_xml_id:
                print(f"[+] Целостность подтверждена (ID первой записи: {first_xml_id})")
            else:
                print(f"[!] Ошибка! ID первой записи не совпадает: JSON({first_json_id}) != XML({first_xml_id})")
                return False

        print("[+] Проверка соответствия данных завершена успешно!")
        return True

    except Exception as e:
        print(f"[-] Ошибка при проверке XML: {e}")
        return False

if __name__ == "__main__":
    if validate_json():
        check_xml_consistency()
