#!/usr/bin/env python3
"""
スクリプトの説明: PDF監査レポートから脆弱性の発見事項（findings）を抽出します。
"""

import os
import json
import PyPDF2
import re
from pathlib import Path
import concurrent.futures
import logging

# ロギングの設定
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def extract_findings_from_pdf(pdf_path):
    """
    PDFから脆弱性の発見事項（findings）を抽出します。

    Args:
        pdf_path: PDFファイルのパス

    Returns:
        findings: 発見された脆弱性のリスト
    """
    try:
        logger.info(f"Processing {pdf_path}")
        findings = []
        with open(pdf_path, 'rb') as file:
            pdf_reader = PyPDF2.PdfReader(file)
            text = ""

            # PDFの全ページからテキストを抽出
            for page in pdf_reader.pages:
                text += page.extract_text()

            # "Finding"のセクションを探す
            finding_sections = re.split(r'(?i)finding\s+\d+[\.\:]\s+|issue\s+\d+[\.\:]\s+|vulnerability\s+\d+[\.\:]\s+', text)

            if len(finding_sections) <= 1:  # 他のパターンを試す
                finding_sections = re.split(r'(?i)finding[\:\s]+|issue[\:\s]+|vulnerability[\:\s]+', text)

            # 各セクションを処理
            for section in finding_sections[1:]:  # 最初のセクションはヘッダーなので無視
                finding = {
                    "severity": "unknown",
                    "description": "",
                    "location": "",
                    "recommendation": ""
                }

                # 重要度（Severity）を抽出
                severity_match = re.search(r'(?i)severity[\:\s]+(critical|high|medium|low|informational|info)', section)
                if severity_match:
                    finding["severity"] = severity_match.group(1).lower()

                # 説明（Description）を抽出
                desc_match = re.search(r'(?i)description[\:\s]+(.*?)(?=severity|\n\n|\Z)', section, re.DOTALL)
                if desc_match:
                    finding["description"] = desc_match.group(1).strip()
                else:
                    # タイトルらしき部分を抽出
                    lines = section.split('\n')
                    if lines:
                        potential_title = lines[0].strip()
                        if len(potential_title) < 200:  # タイトルは短いはず
                            finding["description"] = potential_title

                # 場所（Location）を抽出
                loc_match = re.search(r'(?i)location[\:\s]+(.*?)(?=\n\n|\Z)', section, re.DOTALL)
                if loc_match:
                    finding["location"] = loc_match.group(1).strip()

                # 推奨事項（Recommendation）を抽出
                rec_match = re.search(r'(?i)recommendation[s]?[\:\s]+(.*?)(?=\n\n|\Z)', section, re.DOTALL)
                if rec_match:
                    finding["recommendation"] = rec_match.group(1).strip()

                # 説明が空でない場合だけfindings配列に追加
                if finding["description"]:
                    findings.append(finding)

        # 何も見つからなかった場合は別の方法でtitleとseverityを抽出
        if not findings:
            # セクション見出しを探す
            section_titles = re.findall(r'\n[A-Z][A-Za-z\s\-]{3,50}[\:\.]', text)
            severity_keywords = ['critical', 'high', 'medium', 'low', 'info', 'informational']

            for title in section_titles:
                title = title.strip()
                severity = "unknown"

                # タイトルから重要度を判断
                for keyword in severity_keywords:
                    if keyword.lower() in title.lower():
                        severity = keyword.lower()
                        break

                findings.append({
                    "severity": severity,
                    "description": title,
                    "location": "",
                    "recommendation": ""
                })

        logger.info(f"Extracted {len(findings)} findings from {pdf_path}")
        return findings

    except Exception as e:
        logger.error(f"Error processing {pdf_path}: {str(e)}")
        return []

def update_findings_in_index(index_file):
    """
    インデックスファイルのfindings項目を更新します。

    Args:
        index_file: インデックスファイルのパス
    """
    try:
        with open(index_file, 'r') as f:
            index_data = json.load(f)

        total_reports = len(index_data['reports'])
        total_findings = 0

        # 並行処理でPDFからfindingsを抽出
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            futures = {}

            for i, report in enumerate(index_data['reports']):
                pdf_path = report['report_path']
                logger.info(f"[{i+1}/{total_reports}] Queuing {pdf_path}")

                if os.path.exists(pdf_path):
                    futures[executor.submit(extract_findings_from_pdf, pdf_path)] = i
                else:
                    logger.warning(f"File not found: {pdf_path}")

            for future in concurrent.futures.as_completed(futures):
                idx = futures[future]
                findings = future.result()
                index_data['reports'][idx]['findings'] = findings
                total_findings += len(findings)

                # 進捗状況を表示
                pdf_path = index_data['reports'][idx]['report_path']
                logger.info(f"[{idx+1}/{total_reports}] Processed {pdf_path} - Found {len(findings)} findings")

        # 更新したインデックスを保存
        with open(index_file, 'w') as f:
            json.dump(index_data, f, indent=2)

        logger.info(f"更新完了: {total_reports}件のレポートから合計{total_findings}件のfindingsを抽出しました。")

    except Exception as e:
        logger.error(f"インデックス更新中にエラーが発生しました: {str(e)}")

if __name__ == "__main__":
    reports_dir = "security_agent/data/sources/audit_reports"
    index_file = Path(reports_dir) / "index.json"

    if index_file.exists():
        logger.info(f"インデックスファイル {index_file} を処理します")
        update_findings_in_index(index_file)
    else:
        logger.error(f"インデックスファイル {index_file} が見つかりません")