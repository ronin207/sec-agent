#!/usr/bin/env python3
"""
スクリプトの説明: Solidity監査PDFレポートのインデックスを生成します。
"""

import os
import json
from pathlib import Path
import re
from datetime import datetime

def extract_contract_name_from_filename(filename):
    """ファイル名からコントラクト名を抽出します。"""
    # ファイル名から拡張子を削除
    basename = os.path.basename(filename)
    contract_name = os.path.splitext(basename)[0]

    # ファイル名から余分な部分を削除
    contract_name = re.sub(r'[-_]audit[-_]report', '', contract_name, flags=re.IGNORECASE)
    contract_name = re.sub(r'[-_]security[-_]audit', '', contract_name, flags=re.IGNORECASE)
    contract_name = re.sub(r'halborn[-_]', '', contract_name, flags=re.IGNORECASE)

    return contract_name

def create_reports_index(reports_dir):
    """監査レポートのインデックスを作成します。"""
    reports_dir = Path(reports_dir)
    index_file = reports_dir / "index.json"

    pdf_files = list(reports_dir.glob("*.pdf"))
    print(f"{len(pdf_files)}件のPDFファイルが見つかりました。")

    reports = []
    for pdf_file in pdf_files:
        contract_name = extract_contract_name_from_filename(pdf_file.name)
        report_info = {
            "contract_name": contract_name,
            "report_path": str(pdf_file),
            "findings": [],  # 空のリスト（PDFを解析する際に埋められます）
            "timestamp": datetime.now().isoformat()
        }
        reports.append(report_info)

    index_data = {"reports": reports}

    with open(index_file, 'w') as f:
        json.dump(index_data, f, indent=2)

    print(f"インデックスファイルを生成しました: {index_file}")
    return index_file

if __name__ == "__main__":
    reports_dir = "security_agent/data/sources/audit_reports"
    index_file = create_reports_index(reports_dir)
    print(f"処理完了。{len(json.loads(open(index_file).read())['reports'])}件のレポートがインデックス化されました。")