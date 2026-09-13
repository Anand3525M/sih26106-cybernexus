"""Demo Runner for Campaign Correlation Engine (Stage 6).

Ingests the 5 synthetic phishing campaign emails, processes them sequentially
through the correlation engine, displays per-signal similarity breakdowns and
fused confidence scores with transparent weights, constructs the attack graph,
and exports the graph as JSON.
"""

import os
import sys
import re
import glob
from pathlib import Path
from typing import List

# Ensure Windows terminal handles UTF-8 cleanly
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from models import EmailVerdict, CorrelationWeights
from correlation_engine import CampaignCorrelationEngine


def parse_raw_email(filepath: str, email_index: int) -> EmailVerdict:
    """Parse key headers and body from plain text email file."""
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    sender = ""
    subject = ""
    date_str = "2026-09-10T08:00:00Z"
    sender_ip = None
    body = ""

    lines = content.split("\n")
    body_lines = []
    in_body = False

    for line in lines:
        if in_body:
            body_lines.append(line)
        elif line.startswith("From:"):
            sender = line.replace("From:", "").strip()
        elif line.startswith("Subject:"):
            subject = line.replace("Subject:", "").strip()
        elif line.startswith("Date:"):
            date_str = line.replace("Date:", "").strip()
        elif line.startswith("Sender-IP:"):
            sender_ip = line.replace("Sender-IP:", "").strip()
        elif line.startswith("Body:"):
            body_lines.append(line.replace("Body:", "").strip())
            in_body = True
        elif not line.strip() and (sender or subject):
            in_body = True
        elif in_body:
            body_lines.append(line)

    body = "\n".join(body_lines).strip()
    if not body:
        body = content.strip()

    # Extract URLs from body and headers
    url_pattern = r"https?://[^\s<>\"']+"
    extracted_urls = re.findall(url_pattern, content)

    email_id = f"EMAIL-{email_index:03d}"

    return EmailVerdict(
        email_id=email_id,
        timestamp=date_str,
        sender=sender or "unknown@sender.com",
        sender_ip=sender_ip,
        subject=subject or f"Test Email {email_index}",
        body=body,
        extracted_urls=extracted_urls,
        stage_verdict="phishing",
        threat_score=0.92,
    )


def print_plain_language_weights(weights: CorrelationWeights):
    """Answers Step 4: Display the exact weight numbers in plain language."""
    print("=" * 80)
    print(" [*] TRACEMAIL CORRELATION ENGINE: ACTIVE SIGNAL WEIGHT CONFIGURATION")
    print("=" * 80)
    print(f"Total Fused Confidence = sum(Signal_Score * Signal_Weight)\n")

    items = [
        (
            "Shared URL",
            weights.shared_url,
            "35%",
            "Primary weight. Phishing campaigns almost always reuse attack URLs, landing pages, or auth endpoints across different email variations."
        ),
        (
            "Text / Template Similarity",
            weights.text_similarity,
            "25%",
            "High weight. Uses TF-IDF cosine similarity (>= 0.80) to detect near-duplicate templates, subject lines, and lure wording variations."
        ),
        (
            "Shared Sending Domain",
            weights.shared_domain,
            "20%",
            "Moderate-high weight. Matches sender domain or apex domain. Balanced so benign corporate emails do not falsely trigger correlations on domain alone."
        ),
        (
            "Shared Sender IP / Subnet",
            weights.shared_ip,
            "15%",
            "Moderate weight. Identifies identical sending relay IPs or shared /24 subnets."
        ),
        (
            "Temporal Clustering",
            weights.temporal_clustering,
            "5%",
            "Tie-breaker weight. Measures burst velocity within 48h. Calibrated to 5% to prevent regular daily business emails from falsely linking."
        ),
    ]

    for name, weight, pct, rationale in items:
        print(f" • {name:<28} : {weight:.2f} ({pct})")
        print(f"   Rationale: {rationale}\n")

    total = weights.total_weight()
    print(f"Total Sum of Weights: {total:.2f} (100%)\n")
    print("=" * 80)


def run_benchmark():
    """Runs the Day 4 accuracy benchmark: 5 campaign emails + 5 real noise emails."""
    script_dir = Path(__file__).parent.resolve()
    camp_dir = script_dir / "test-data" / "synthetic-campaign"
    if not camp_dir.exists():
        camp_dir = script_dir.parent / "test-data" / "synthetic-campaign"

    noise_dir = script_dir / "test-data" / "noise-emails"
    if not noise_dir.exists():
        noise_dir = script_dir.parent / "test-data" / "noise-emails"

    weights = CorrelationWeights(
        shared_url=0.35,
        shared_domain=0.20,
        text_similarity=0.25,
        shared_ip=0.15,
        temporal_clustering=0.05,
    )
    threshold = 0.40

    print_plain_language_weights(weights)

    engine = CampaignCorrelationEngine(
        weights=weights,
        correlation_threshold=threshold,
        text_duplicate_threshold=0.80,
        temporal_window_hours=48.0,
        db_path=":memory:",
    )

    camp_files = sorted(glob.glob(str(camp_dir / "email*.txt")))
    noise_files = sorted(glob.glob(str(noise_dir / "noise*.txt")))

    all_verdicts: List[EmailVerdict] = []
    for i, fp in enumerate(camp_files, start=1):
        all_verdicts.append(parse_raw_email(fp, i))

    for i, fp in enumerate(noise_files, start=101):
        v = parse_raw_email(fp, i)
        stem = Path(fp).stem
        v.email_id = f"NOISE-{stem}"
        v.stage_verdict = "legitimate" if "spam" not in stem else "phishing"
        all_verdicts.append(v)

    # Ingest all emails
    for v in all_verdicts:
        engine.process_email(v)

    # Pairwise evaluation
    tp, fn, fp, tn = 0, 0, 0, 0
    pairwise_rows = []

    for i in range(len(all_verdicts)):
        for j in range(i + 1, len(all_verdicts)):
            e1, e2 = all_verdicts[i], all_verdicts[j]
            match = engine.correlate_pair(e1, e2)
            fused = match.fused_campaign_confidence
            is_linked = fused >= threshold

            is_c1 = not e1.email_id.startswith("NOISE-")
            is_c2 = not e2.email_id.startswith("NOISE-")
            ground_truth = is_c1 and is_c2

            if ground_truth:
                if is_linked:
                    tp += 1
                    status = "TP (Correct Campaign Link)"
                else:
                    fn += 1
                    status = "FN (Missed Campaign Link)"
            else:
                if is_linked:
                    fp += 1
                    status = "FP (False Positive Link!)"
                else:
                    tn += 1
                    status = "TN (Correctly Unlinked)"

            pairwise_rows.append({
                "pair": f"{e1.email_id} <-> {e2.email_id}",
                "type": "CAMP-CAMP" if ground_truth else ("CAMP-NOISE" if (is_c1 != is_c2) else "NOISE-NOISE"),
                "fused": fused,
                "status": status,
                "scores": match.signal_scores,
            })

    print(f"\n--- PAIRWISE COMPARISONS (Total: {len(pairwise_rows)}) ---")
    print(f"{'Pair':<42} | {'Type':<10} | {'Fused':<6} | {'URL':<5} | {'DOM':<5} | {'TXT':<5} | {'IP':<5} | {'TIME':<5} | {'Status'}")
    print("-" * 110)
    for r in pairwise_rows:
        s = r["scores"]
        print(f"{r['pair']:<42} | {r['type']:<10} | {r['fused']:<6.4f} | {s.shared_url_score:<5.2f} | {s.shared_domain_score:<5.2f} | {s.text_similarity_score:<5.2f} | {s.shared_ip_score:<5.2f} | {s.temporal_score:<5.2f} | {r['status']}")

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

    print("\n" + "=" * 80)
    print(" [*] TRACEMAIL ACCURACY BENCHMARK PERFORMANCE METRICS")
    print("=" * 80)
    print(f"True Positives (Campaign pairs correctly linked) : {tp} / 10")
    print(f"False Negatives (Campaign pairs missed)           : {fn} / 10")
    print(f"False Positives (Noise pairs incorrectly linked)  : {fp} / 35")
    print(f"True Negatives (Noise pairs correctly separate)   : {tn} / 35")
    print(f"Precision : {precision:.4f} ({precision*100:.1f}%)")
    print(f"Recall    : {recall:.4f} ({recall*100:.1f}%)")
    print(f"F1-Score  : {f1:.4f}")

    graph_export = engine.export_graph_json()
    print(f"\nGraph Clusters Discovered: {graph_export['metadata']['campaign_clusters_count']}")
    for cl in graph_export["campaign_clusters"]:
        print(f"  - Cluster #{cl['campaign_index']} (size: {cl['size']}): {cl['email_ids']}")
    print("=" * 80)


def main():
    if "--benchmark" in sys.argv or "-b" in sys.argv:
        run_benchmark()
        return

    script_dir = Path(__file__).parent.resolve()
    # Support both possible data paths
    data_dir = script_dir / "test-data" / "synthetic-campaign"
    if not data_dir.exists():
        data_dir = script_dir.parent / "test-data" / "synthetic-campaign"

    print(f"\n[+] Loading synthetic emails from: {data_dir}")
    email_files = sorted(glob.glob(str(data_dir / "email*.txt")))

    if not email_files:
        print(f"[-] No synthetic email files found in {data_dir}")
        return

    # Clean previous demo database if exists
    db_file = script_dir / "campaign_emails.db"
    if db_file.exists():
        db_file.unlink()

    weights = CorrelationWeights(
        shared_url=0.35,
        shared_domain=0.20,
        text_similarity=0.25,
        shared_ip=0.15,
        temporal_clustering=0.05,
    )

    # Initialize Engine
    engine = CampaignCorrelationEngine(
        weights=weights,
        correlation_threshold=0.40,
        text_duplicate_threshold=0.80,
        temporal_window_hours=48.0,
        db_path=str(db_file),
    )

    # Show weights in plain language
    print_plain_language_weights(weights)

    print(f"\n[+] Processing {len(email_files)} synthetic campaign emails through Stage 6 Engine...\n")

    for i, file_path in enumerate(email_files, start=1):
        verdict = parse_raw_email(file_path, i)
        print("-" * 80)
        print(f"[*] Ingesting Email: {verdict.email_id}")
        print(f"   From:       {verdict.sender}")
        print(f"   IP:         {verdict.sender_ip}")
        print(f"   Subject:    {verdict.subject}")
        print(f"   Timestamp:  {verdict.timestamp}")
        print(f"   URLs:       {verdict.extracted_urls}")

        result = engine.process_email(verdict)

        print(f"\n   Campaign Result:")
        print(f"   -> Assigned Campaign ID : {result.assigned_campaign_id}")
        print(f"   -> Highest Correlation  : {result.highest_confidence:.4f}")

        if result.correlated_prior_emails:
            print(f"\n   Correlated Prior Emails ({len(result.correlated_prior_emails)} evaluated):")
            for match in result.correlated_prior_emails:
                status = "[MATCH]" if match.is_campaign_match else "[NO MATCH]"
                print(f"     {status} vs {match.prior_email_id} ('{match.prior_subject[:40]}...'):")
                print(f"         Fused Campaign Confidence: {match.fused_campaign_confidence:.4f} (Threshold: {result.correlation_threshold})")
                print("         Signal Breakdown:")
                sb = match.signal_scores
                print(f"           - Shared URL        : score {sb.shared_url_score:.2f} * wt {weights.shared_url} = {sb.shared_url_score * weights.shared_url:.3f} | {sb.details.get('shared_url')}")
                print(f"           - Shared Domain     : score {sb.shared_domain_score:.2f} * wt {weights.shared_domain} = {sb.shared_domain_score * weights.shared_domain:.3f} | {sb.details.get('shared_domain')}")
                print(f"           - Text Similarity   : score {sb.text_similarity_score:.2f} * wt {weights.text_similarity} = {sb.text_similarity_score * weights.text_similarity:.3f} | {sb.details.get('text_similarity')}")
                print(f"           - Shared IP         : score {sb.shared_ip_score:.2f} * wt {weights.shared_ip} = {sb.shared_ip_score * weights.shared_ip:.3f} | {sb.details.get('shared_ip')}")
                print(f"           - Temporal Clust.   : score {sb.temporal_score:.2f} * wt {weights.temporal_clustering} = {sb.temporal_score * weights.temporal_clustering:.3f} | {sb.details.get('temporal')}")
        else:
            print("   -> (First email ingested; no prior emails to compare against yet)")

        print()

    # Final Graph Summary and JSON Export
    graph_json_path = script_dir / "campaign_graph.json"
    exported = engine.export_graph_json(str(graph_json_path))

    print("=" * 80)
    print(" [*] NETWORKX CORRELATION GRAPH SUMMARY")
    print("=" * 80)
    print(f"Total Nodes (Emails)      : {exported['metadata']['node_count']}")
    print(f"Total Edges (Correlations): {exported['metadata']['edge_count']}")
    print(f"Campaign Clusters Found   : {exported['metadata']['campaign_clusters_count']}")

    for cluster in exported["campaign_clusters"]:
        print(f"  - Cluster #{cluster['campaign_index']}: {cluster['size']} emails -> {cluster['email_ids']}")

    print(f"\n[OK] Graph exported successfully to JSON: {graph_json_path}")
    print("=" * 80)


if __name__ == "__main__":
    main()
