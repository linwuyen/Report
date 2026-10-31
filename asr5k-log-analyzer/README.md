# ASR5K Firmware Log Analyzer V0.1

**離線診斷工具；不讀取、不修改、不編譯、不燒錄 ASR5K 韌體。**

這是 Proof of Concept，僅支援標準化 JSONL 事件，不支援直接讀取原始 CCS Watch、UART 或 Logic Analyzer CSV。首次發佈附帶人工模擬案例與 12 個 unittest。

## 新 Windows 電腦快速開始

安裝 Python 3.10+，開啟 PowerShell：

    git clone https://github.com/linwuyen/Report.git
    cd Report\asr5k-log-analyzer
    py -m pip install -r requirements.txt
    py -m unittest discover -s tests -v
    py analyzer.py --input samples/demo.jsonl --output reports/demo_report.json --demo

模擬資料的 ON-edge → DDS wave 延遲為 42.5 ms，故 Overall: FAIL 是預期的測試結果，**不代表真實硬體 FAIL**。

## 選用 OpenAI API

在 OpenAI Platform 建立 **Secret Key**（通常以 sk- 開頭），不要複製 Tracking ID；也不要把完整金鑰貼到程式、文件或 GitHub。

PowerShell 輸入金鑰（只在目前視窗有效）：

    $secureKey = Read-Host "Enter OpenAI API Key" -AsSecureString
    $env:OPENAI_API_KEY = [System.Net.NetworkCredential]::new("", $secureKey).Password.Trim()

確認環境變數有設定但不洩露內容：

    ![string]::IsNullOrEmpty($env:OPENAI_API_KEY)

經確認送出資料已獲授權、且目前輸入為人工模擬資料後，執行：

    py analyzer.py --input samples/demo.jsonl --output reports/demo_report.json --demo --ai --allow-external-upload

確定性 JSON 報告位於 reports/demo_report.json，AI 分析位於 reports/demo_report_ai.md。也可使用 --model 指定你的 API Project 可存取的模型。AI 分析是選用功能，模型失敗不影響確定性報告。

**注意：** 使用 --ai --allow-external-upload 會向 OpenAI API 傳送計算後的 findings（非原始 log），但這些 findings 仍可能含有機密資訊。未取得授權時不要上傳公司資料。store=False 不等於所有服務端處理／保留都已停用。

## 已支援

- 嚴格解析 JSONL，每筆一行，逐筆保留原始行號。
- 依 session_id 隔離開機／RESET 事件，避免跨 session 拼接。
- COMMAND_APPLIED_DIFFER 為 WARN，不能只靠單次不同步判定故障。
- NACK_EXHAUSTED、進入 FAULT 的明確事件偵測。
- 同一來源、同一 timebase 內的 OUT-ON HIGH → DDS WAVE START 延遲，檢查 40 ±1 ms；其他情形回報證據不足。
- 檢查 timestamp 非單調性與 source SHA／燒錄 .out SHA256 metadata。
- Python deterministic report + 選用 AI 假設／缺失證據／下一個最小測試。

## 最小 JSONL 格式

每筆必須包含 session_id、ts_us、timebase、source、event；可另提供 fields、firmware_sha、binary_sha256。

    {"session_id":"S001","ts_us":120000,"timebase":"LA_CAPTURE_01","source":"LA","event":"out_on_high","fields":{}}
    {"session_id":"S001","ts_us":160000,"timebase":"LA_CAPTURE_01","source":"LA","event":"dds_wave_start","fields":{}}

ts_us 單位為 microsecond。即使 timebase 名稱一致，也不能直接證明實體時鐘同步；實機驗證需要確認 LA 通道對應、邊緣極性、時鐘精度，以及實際燒錄的 .out 與 source SHA。

## 驗證與限制

- 先執行 unittest，預期 12/12 PASS。
- 真實 ASR5K 輸入尚未驗證；沒有經驗證的 raw log parser。
- 未建立完整故障 enum、counter rollover、multiple pulse pairing 規則。
- AI 不能變更 deterministic PASS/FAIL；所有根因推論都必須另以量測證據驗證。
- 不要把真實機密 log、API key、報告、.out 推到公開儲存庫。
- Rollback：從 Report repository 移除此獨立資料夾即可；不影響產品韌體。
