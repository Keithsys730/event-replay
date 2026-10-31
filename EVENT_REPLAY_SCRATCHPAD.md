# 🧭 Event-Replay: Architectural Scratchpad & Specification Lock (INCUBATE)

> **Order**: `ORD-0156`  
> **Target Repository**: `D:\AI_Code_Workspace\event-replay`  
> **Mode**: `EVALUATE` / `INCUBATE`  
> **Status**: `GATE 1 LOCKED & RATIFIED BY KEITH (2026-10-31)`  
> **Timestamp**: `2026-10-31T14:05:00Z`  
> **Ratification**: Keith approved ("准") on 2026-10-31.

---

## 1. 核心定位與問題定義 (Problem Statement & Purpose)

在現代非同步架構（分散式微服務、邊緣物聯網 MQTT、車載 CAN 通訊）中，非同步訊息流與事件驅動架構引發嚴重的**除錯與審計黑盒**問題：
1. **時序非預期與競態盲點**：下游微服務崩潰或資料狀態異常時，工程師無法獲知崩潰前在 Messaging Bus 上通過的真實事件序列。
2. **重現成本極高**：傳統環境無法精確重演歷史事件時序（Lack of Deterministic Replay），常常因為時間戳漂移、下游狀態不一致導致「本機測永遠正常，線上偶發崩潰」。
3. **副作用失控風險**：研發人員不敢在測試或預發環境輕易重放事件，深怕重放舊事件觸發重複扣款、發送真實通知或實體執行器動作。

**`event-replay` 的核心目的**：
提供輕量、自包含、雙軌抽象架構的**非同步事件流時光回放儀與資料版本控制引擎（Time-Travel Event Stream Replay & Delta Versioning）**。讓工程師與 AI Agent 能以確定性時序錄製、回溯、差量比對並安全重演歷史事件。

---

## 2. 蘇格拉底深度三維度 (Keith Archetype Deepening Protocol)

### 維度 A：物理邊界、因果時序與資料模型 (Physics & Boundary)
- **因果時序保證 (Causal Consistency vs Clock Skew)**：
  - 嚴格分離 **事件產生時間戳 (`timestamp_utc`)** 與 **日誌錄製序號 (`seq_id`)**。
  - 回放引擎支援兩種時鐘驅動模式：
    1. `Preserve-Interval`（依歷史事件間隔真實縮放重播，如 0.5x, 1x, 5x, 10x 播放）。
    2. `Immediate-Step`（單步步進模式，供 Agent 或工程師依序偵錯斷言）。
- **不可變事件格式契約 (Immutable Event Schema)**：
  ```python
  @dataclass(frozen=True)
  class RecordedEvent:
      seq_id: int                    # 全域單調遞增物理序號 (跨 Topic 因果錨點)
      event_id: str                  # 原始 UUID 或 Message-ID
      stream_topic: str              # Topic / Queue / Channel
      partition_key: str | None      # 分區鍵 (局部有序性保證)
      timestamp_utc: str             # ISO-8601 UTC
      headers: dict[str, str]        # 元數據 (Trace ID, Content-Type, 自訂標籤)
      payload: bytes                 # 二進位/字串原始負載 (Protobuf, JSON, MsgPack)
      checksum_sha256: str           # 防竄改校驗碼
  ```
- **反記憶體爆炸機制 (Memory Protection & Chunked Streams)**：
  - 本地快照底層採用分塊追加日誌（Chunked Append-Only JSONL 或 SQLite WAL），回放時使用串流生成器（Streaming Iterator），嚴格禁止一次性將海量事件全部載入記憶體。

### 維度 B：雙軌架構拓撲與可攜性 (Topology & Portability)
依循 Hexagonal Architecture（六角架構）：
```
                    +--------------------------------+
                    |    Consumer / CLI / TUI / MCP  |
                    +---------------+----------------+
                                    |
                    +---------------+----------------+
                    |      Core Domain Engine        |
                    |   (EventStream, Cursor, Replay)|
                    +---------------+----------------+
                                    |
            +-----------------------+-----------------------+
            |                                               |
+-----------v-----------+                       +-----------v-----------+
| Ingestion Adapters    |                       | Sinks / Replay Drivers|
| - Kafka / Redpanda    |                       | - Dry-Run / Diff Sink |
| - RabbitMQ / AMQP     |                       | - Live Broker Producer|
| - MQTT / CAN-Log      |                       | - JSONL / Parquet Exporter
| - 100% Offline Mock   |                       +-----------------------+
+-----------------------+
```
- **核心領域 (`event_replay.domain`)**：
  - 零外部網路依賴、零第三方重量級 Broker 依賴。
  - 核心抽象：`EventIngestionPort`、`EventSinkPort`、`ReplayEngine`、`StreamDiffer`。
- **適配器層 (`event_replay.adapters`)**：
  - 雙軌 Ingestion：支援通用 MQ（Kafka/RabbitMQ/Redis）與邊緣日誌（MQTT/CAN/JSONL）。
  - 離線優先：自帶 100% 離線 Mock Fixtures，測試套件執行無需本地啟動 Docker 或 Broker。

### 維度 C：副作用隔離、安全性與防投毒 (Safety & Side-Effect Quarantine)
- **副作用隔離鐵律 (Quarantine Invariant)**：
  - 在重播模式（Replay Mode）下，所有重放事件的 Header **強制自動注入**：
    `X-Event-Replay: true`
    `X-Replay-Session-Id: <uuid>`
    `X-Original-Timestamp: <iso_utc>`
  - 預設提供 `DryRunSink`（虛擬重放與差量對比），僅捕獲「若重放，下游預期狀態有何變更」，不向外部網路發射任何物理封包。
- **敏感資料去識別化 (PII Masking)**：
  - 內建敏感字串遮蔽器，錄製或重播時自動遮蔽常見機密鍵（`token`, `password`, `auth`, `secret`, `credit_card`）。

---

## 3. 六大核心盲點防禦矩陣 (Red-Team Remediations)

1. **防自我回放風暴 (Self-Replay Storm Quarantine - INV-1)**：
   - Ingestion Adapter 強制過濾 `X-Event-Replay: true`，杜絕任何無限自我放大閉環。
2. **時間倒流悖論與時序平移 (Timestamp-Shift Projection - INV-2)**：
   - 支援 `Shift-To-Current` 相對時鐘平移模式：保持各事件微秒級相對時間差，但將時間軸投影至現在，避免下游因 Token 過期或 Message TTL 拒絕舊事件。
   - 支援動態 Header 替換鉤子（`--override-header "Authorization=Bearer <fresh_token>"`）。
3. **全域因果序守恆 (Cross-Topic Causal Sequencer - INV-3)**：
   - 跨 Topic/Partition 多流錄製時，使用單一全域單調序號序列（Interleaved Sequence）。
   - 回放調度器使用單一優先級隊列（Priority Queue），強制保證 `Seq N` 未發射前絕不發射 `Seq N+1`，杜絕跨 Topic 因果倒置。
4. **綱要演進與位元級穿透 (Bit-Exact Passthrough - INV-4)**：
   - Payload 預設以原始二進位 `bytes` 零修改穿透重送，完全免疫 Schema Registry / Protobuf 版本升級帶來的反序列化崩潰。
   - 僅在 `diff` 或 `inspect` 檢視時調用可選解碼器。
5. **有毒訊息二分排查 (Poison Pill Bisecting & Step Mode - INV-5)**：
   - 支援 `--time-window` 與 `--filter` 精確定位崩潰事件。
   - 提供互動式單步執行模式（按 `Space` 鍵逐筆發射），工程師可邊看下游日誌邊精確定位 Bug。
6. **索引與負載分離儲存 (Hybrid Storage Architecture - INV-6)**：
   - 索引層：SQLite WAL 儲存序號、時間戳、Topic、Header 與偏移量。
   - 負載層：Zstandard 壓縮分塊日誌（Chunked Append-Only Compressed BLOBs），防禦高吞吐磁碟寫入放大。

---

## 4. 領域不變量矩陣 (Invariants Checklist)

| 不變量編號 | 規則名稱 | 機構保證 (Mechanical Guarantee) |
|---|---|---|
| **INV-1** | **防自我回放風暴** | Ingestion Adapter 強制過濾 `X-Event-Replay: true`，杜絕任何無限放大閉環。 |
| **INV-2** | **雙模式時序映射** | 支援 `Shift-To-Current`，防止下游因過期 Token 或 TTL 拒絕舊事件。 |
| **INV-3** | **全域因果序保證** | 跨 Topic 多分區採用單一優先隊列發射，嚴禁因果倒置。 |
| **INV-4** | **位元級透明穿透** | Payload 預設以原始二進位 `bytes` 零改動重送，免疫 Schema 演進崩潰。 |
| **INV-5** | **零外部依賴與離線 Mock** | 核心領域與測試 100% 離線，5 秒內執行完畢，不啟動真實 Docker/Broker。 |
| **INV-6** | **動態路徑與可攜性** | 遵循 Rule 8，無硬編碼絕對路徑，開箱即用。 |

---

## 5. 示蹤彈垂直切片規劃 (Tracer-Bullet Slices: TB-1 ~ TB-4)

| 切片編號 | 切片名稱 | 涵蓋範疇 (輸入 → 運算 → 輸出) | 可執行驗證閘口 (Deterministic Command) |
|---|---|---|---|
| **TB-1** | **核心不可變事件流與因果引擎 (Core Stream & Causal Ordering)** | 定義 `RecordedEvent`、單調序號生成器、Chunked 追加儲存、優先隊列因果調度。 | `pytest tests/test_core_stream.py -v` |
| **TB-2** | **雙軌六角適配器與防自我回放 (Hexagonal Adapters & Storm Defense)** | Ingestion Port (JSONL, Mock Broker, MQTT)、Sink Port (Dry-Run, Live Stub)、`X-Event-Replay` 防迴圈過濾。 | `pytest tests/test_adapters.py -v` |
| **TB-3** | **時光回放時鐘與差量比對器 (Replay Engine & Differ)** | Preserve-Interval / Shift-To-Current / Step Clock、事件差量比對器 (Stream Differ)、Header 覆寫鉤子。 | `pytest tests/test_replay_engine.py -v` |
| **TB-4** | **CLI 控制終端與 FastMCP 工具介面 (CLI & FastMCP Server)** | CLI (`event-replay record/replay/diff/inspect/bisect`) 與 FastMCP stdio 伺服器供 Agent 自動調度。 | `pytest tests/test_cli_and_mcp.py -v` |

---

## 6. Gate 1 決策結論 (Terminal Gate 1 Ratification)

- **批准紀錄**：Keith 於 2026-10-31 審閱並批准（「准」）。
- **邊界確認**：本工單 `ORD-0156` 為純規格深化與評估（`EVALUATE`），在 Gate 1 鎖定前未編寫任何生產程式碼，達成零代碼變更終端結案。
- **後續銜接**：將在經 Keith 最終確認後，透過 `/front-desk` 簽發 `ORD-0157`（`BUILD`）正式啟動工程開發。
