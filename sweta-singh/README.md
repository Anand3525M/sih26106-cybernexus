# Campaign Correlation Engine (Stage 6) - Sweta Singh

Part of the TraceMail project (Team CYBERNEXUS). Identifies coordinated scam/phishing attacks across multiple emails by correlating disparate indicators into unified attack campaign graphs.

---

## 🚀 Key Capabilities

1. **Multi-Signal Correlation**:
   - **Shared URL / Endpoint Reuse** (Weight: `0.35`)
   - **Near-Duplicate Subject/Body Text Similarity** (Weight: `0.25`, TF-IDF Cosine Similarity $\ge 0.80$)
   - **Shared Sending Domain / Apex Domain** (Weight: `0.20`)
   - **Shared Sender IP / Subnet** (Weight: `0.15`, matching IP or `/24` subnet)
   - **Temporal Clustering** (Weight: `0.05`, exponential/linear decay within configurable time window)

2. **Full Weight Transparency**:
   - Every correlation match returns individual signal scores and the exact active weights applied.
   - Weights are configurable through the `CorrelationWeights` class.

3. **Incremental NetworkX Graph**:
   - Ingests incoming emails one by one, adding nodes and similarity edges.
   - Automatically clusters connected emails into campaign IDs (e.g. `CAMPAIGN-CLUSTER-001`).
   - Exports the graph to JSON (`campaign_graph.json`) ready for frontend visualization (D3.js, Cytoscape, etc.).

4. **Persistent SQLite Store**:
   - Stores processed emails and verdicts with fast querying.

---

## 📁 Directory Layout

```
sweta-singh/
├── correlation_engine.py       # Core correlation engine, analyzers, SQLite store, NetworkX graph
├── models.py                   # Pydantic data contracts (EmailVerdict, CorrelationWeights, etc.)
├── demo_runner.py              # Ingestion pipeline for 5 synthetic campaign emails
├── test_correlation_engine.py  # Comprehensive unit test suite
├── campaign_emails.db          # SQLite database of processed emails
├── campaign_graph.json         # Exported NetworkX graph for frontend visualization
├── test-data/
│   ├── synthetic-campaign/     # 5 synthetic coordinated phishing emails
│   │   ├── email1.txt
│   │   ├── email2.txt
│   │   ├── email3.txt
│   │   ├── email4.txt
│   │   └── email5.txt
│   └── noise-emails/           # Real noise emails from Enron & SpamAssassin
│       ├── noise1_enron.txt
│       ├── noise2_enron.txt
│       ├── noise3_spamassassin_ham.txt
│       ├── noise4_spamassassin_spam.txt
│       └── noise5_w3schools.txt
└── README.md
```

---

## 🎯 Accuracy Benchmark & Evaluation

Tested against 5 synthetic campaign emails + 5 authentic noise emails from Enron and SpamAssassin:

| Metric | Baseline Weights | Tuned Weights (Active) |
| :--- | :--- | :--- |
| **Campaign Emails Linked** | 5 / 5 (100% Recall) | **5 / 5 (100% Recall)** |
| **Campaign Pairs Linked (TP)** | 10 / 10 | **10 / 10** |
| **False Positives (FP)** | 1 / 35 (Enron corporate link) | **0 / 35 (0% False Positives)** |
| **Precision** | 90.9% | **100.0%** |
| **Recall** | 100.0% | **100.0%** |
| **F1-Score** | 0.9524 | **1.0000** |

Run the full benchmark:
```bash
python sweta-singh/demo_runner.py --benchmark
```

---

## ⚡ Quick Start

### Run the Demo
```bash
python sweta-singh/demo_runner.py
```

### Run Unit Tests
```bash
python -m unittest sweta-singh/test_correlation_engine.py
```

### Adjusting Signal Weights
```python
from correlation_engine import CampaignCorrelationEngine
from models import CorrelationWeights

# Customize weights (must sum to 1.0)
custom_weights = CorrelationWeights(
    shared_url=0.35,
    text_similarity=0.25,
    shared_domain=0.20,
    shared_ip=0.15,
    temporal_clustering=0.05,
)

engine = CampaignCorrelationEngine(
    weights=custom_weights,
    correlation_threshold=0.40,
    text_duplicate_threshold=0.80,
    temporal_window_hours=48.0,
)
```
