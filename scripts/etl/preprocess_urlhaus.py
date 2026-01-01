import csv
import os
import sys

# 경로 설정
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(os.path.dirname(SCRIPT_DIR))
INPUT_FILE = os.path.join(PROJECT_ROOT, 'data', 'raw', 'urlhaus_online.csv')
OUTPUT_FILE = os.path.join(PROJECT_ROOT, 'data', 'processed', 'urlhaus_indicators.csv')

def process_urlhaus():
    if not os.path.exists(INPUT_FILE):
        print(f"[Error] Input file not found: {INPUT_FILE}")
        sys.exit(1)

    print(f"[*] Processing URLHaus data from: {INPUT_FILE}")

    # URLHaus 데이터의 실제 컬럼 순서 (raw 파일 기준)
    # id, dateadded, url, url_status, last_online, threat, tags, urlhaus_link, reporter
    
    # 우리가 저장할 깔끔한 헤더 이름
    output_headers = [
        'id', 'date_added', 'url', 'url_status', 'last_online', 
        'threat', 'tags', 'urlhaus_link', 'reporter'
    ]

    row_count = 0

    with open(INPUT_FILE, 'r', encoding='utf-8', errors='replace') as f_in, \
         open(OUTPUT_FILE, 'w', newline='', encoding='utf-8') as f_out:
        
        # CSV Writer 설정 (우리가 정한 헤더로 씀)
        writer = csv.writer(f_out)
        writer.writerow(output_headers)
        
        # Raw 파일 읽기 (주석 제거 로직)
        # csv.reader를 사용하여 따옴표("") 안에 있는 콤마 처리까지 맡김
        reader = csv.reader(f_in)

        for row in reader:
            if not row: continue # 빈 줄 건너뜀
            
            # 첫 번째 컬럼이 '#'으로 시작하면 주석(설명문 or 원래 헤더)으로 간주하고 스킵
            # 예: "3747164" (데이터) vs "# id" (헤더) vs "# Terms..." (주석)
            first_col = row[0]
            if first_col.startswith('#'):
                continue
                
            # 데이터 컬럼 개수가 맞는지 확인 (안전장치)
            if len(row) < 9:
                continue

            # 데이터 정제 (Tags 공백 제거 등)
            # row[6] is tags
            row[6] = row[6].replace(' ', '') 

            # 그대로 쓰기 (순서가 맞으므로 DictWriter보다 빠름)
            writer.writerow(row)
            row_count += 1
            
    print(f"[+] URLHaus processing done.")
    print(f"    - Input lines skipped (comments/headers)")
    print(f"    - Saved {row_count} valid indicators to {OUTPUT_FILE}")

if __name__ == "__main__":
    process_urlhaus()