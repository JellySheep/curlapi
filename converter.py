import json
import xml.etree.ElementTree as ET
from xml.dom import minidom

def create_xml():
    try:
        with open('result_task_2.json', 'r', encoding='utf-8') as f:
            data = json.load(f)
    except FileNotFoundError:
        print("[-] Ошибка: result_task_2.json не найден. Сначала запусти collector.py")
        return

    root = ET.Element("vulnerabilities")

    for item in data:
        vnode = ET.SubElement(root, "vulnerability")
        
        # Поля 1 уровня
        for key in ["ID", "vendor_release_date", "vendor_release_url", "published_date", "updated_date", "description"]:
            child = ET.SubElement(vnode, key)
            child.text = str(item.get(key, ""))

        # Поля 2 уровня: cvss_list
        cvss_list_node = ET.SubElement(vnode, "cvss_list")
        for cvss in item.get("cvss_list", []):
            # <cvss version=... score=... severity=...>vector</cvss>
            cvss_node = ET.SubElement(cvss_list_node, "cvss", {
                "version": str(cvss.get("version", "")),
                "score": str(cvss.get("score", "")),
                "severity": str(cvss.get("severity", ""))
            })
            cvss_node.text = cvss.get("vector", "")

        # Поля 2 уровня: cpe_list
        cpe_list_node = ET.SubElement(vnode, "cpe_list")
        for cpe_str in item.get("cpe_list", []):
            # <cpe>cpe_string</cpe>
            cpe_node = ET.SubElement(cpe_list_node, "cpe")
            cpe_node.text = cpe_str

        # Поля 2 уровня: cwe_list
        cwe_list_node = ET.SubElement(vnode, "cwe_list")
        cwe_data = item.get("cwe", {})
        for cwe_id, info in cwe_data.items():
            # <cwe id=... name=...>description</cwe>
            cwe_node = ET.SubElement(cwe_list_node, "cwe", {
                "id": cwe_id,
                "name": info.get("name", "")
            })
            cwe_node.text = info.get("description", "")

    # Сохранение
    xml_str = ET.tostring(root, encoding='utf-8')
    pretty_xml = minidom.parseString(xml_str).toprettyxml(indent="  ")
    
    with open("result_task_3.xml", "w", encoding='utf-8') as f:
        f.write(pretty_xml)
    print("[+] Задача 3: XML успешно сохранен в result_task_3.xml")

if __name__ == "__main__":
    create_xml()
