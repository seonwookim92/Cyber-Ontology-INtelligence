import csv
import os
import sys

# 경로 설정
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(os.path.dirname(SCRIPT_DIR))
INPUT_FILE = os.path.join(PROJECT_ROOT, 'data', 'raw', 'cisa_kev.csv')
OUTPUT_FILE = os.path.join(PROJECT_ROOT, 'data', 'processed', 'cisa_kev_clean.csv')

def process_kev():
    if not os.path.exists(INPUT_FILE):
        print(f"[Error] Input file not found: {INPUT_FILE}")
        sys.exit(1)

    print(f"[*] Processing CISA KEV data...")
    
    with open(INPUT_FILE, 'r', encoding='utf-8', errors='replace') as f_in, \
         open(OUTPUT_FILE, 'w', newline='', encoding='utf-8') as f_out:
        
        reader = csv.DictReader(f_in)
        
        # Neo4j로 로드하기 편하게 헤더 이름 변경 (매핑)
        # Raw CSV Header -> Clean CSV Header
        field_mapping = {
            'cveID': 'cve_id',
            'vendorProject': 'vendor',
            'product': 'product',
            'vulnerabilityName': 'name',
            'dateAdded': 'date_added',
            'shortDescription': 'description',
            'requiredAction': 'required_action',
            'dueDate': 'due_date',
            'knownRansomwareCampaignUse': 'ransomware_use'
        }
        
        writer = csv.DictWriter(f_out, fieldnames=list(field_mapping.values()))
        writer.writeheader()
        
        count = 0
        for row in reader:
            clean_row = {}
            for raw_key, clean_key in field_mapping.items():
                # 데이터 값 정제 (따옴표 등)
                value = row.get(raw_key, '').strip()
                clean_row[clean_key] = value
            
            writer.writerow(clean_row)
            count += 1
            
    print(f"[+] Saved {count} rows to {OUTPUT_FILE}")

if __name__ == "__main__":
    process_kev()