"""Stage 6: Campaign Correlation Engine.

Identifies coordinated scam/phishing attacks by evaluating multi-signal correlations:
- Shared sender IP / Subnet
- Shared sending domain / Lookalike domain
- Near-duplicate subject/body text (TF-IDF Cosine Similarity >= 0.8)
- Shared URL / Infrastructure reuse
- Temporal clustering (emails within a configurable time window)

Incrementally maintains an attack graph using NetworkX and exports JSON
for frontend rendering.
"""

import math
import re
import json
import sqlite3
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple, Any
from urllib.parse import urlparse
from pathlib import Path
import sys
import networkx as nx

CURRENT_DIR = Path(__file__).parent.resolve()
if str(CURRENT_DIR) not in sys.path:
    sys.path.insert(0, str(CURRENT_DIR))

try:
    from models import (
        CorrelationWeights,
        EmailVerdict,
        SignalBreakdown,
        CorrelatedEmailMatch,
        CampaignCorrelationOutput,
    )
except ImportError:
    from .models import (
        CorrelationWeights,
        EmailVerdict,
        SignalBreakdown,
        CorrelatedEmailMatch,
        CampaignCorrelationOutput,
    )


# Standard lightweight English stopwords for pure-Python TF-IDF
STOPWORDS = {
    "a", "about", "above", "after", "again", "against", "all", "am", "an", "and",
    "any", "are", "aren't", "as", "at", "be", "because", "been", "before", "being",
    "below", "between", "both", "but", "by", "can", "cannot", "could", "couldn't",
    "did", "didn't", "do", "does", "doesn't", "doing", "don't", "down", "during",
    "each", "few", "for", "from", "further", "had", "hadn't", "has", "hasn't",
    "have", "haven't", "having", "he", "her", "here", "hers", "herself", "him",
    "himself", "his", "how", "i", "if", "in", "into", "is", "isn't", "it", "it's",
    "its", "itself", "me", "more", "most", "mustn't", "my", "myself", "no", "nor",
    "not", "of", "off", "on", "once", "only", "or", "other", "ought", "our",
    "ours", "ourselves", "out", "over", "own", "same", "she", "should", "shouldn't",
    "so", "some", "such", "than", "that", "the", "their", "theirs", "them",
    "themselves", "then", "there", "these", "they", "this", "those", "through",
    "to", "too", "under", "until", "up", "very", "was", "wasn't", "we", "were",
    "weren't", "what", "when", "where", "which", "while", "who", "whom", "why",
    "with", "won't", "would", "wouldn't", "you", "your", "yours", "yourself",
}


def extract_domain(email_or_url: str) -> str:
    """Extract normalized lowercase domain name from email or URL."""
    if not email_or_url:
        return ""
    if "@" in email_or_url:
        return email_or_url.split("@")[-1].strip().lower()
    if "://" in email_or_url or email_or_url.startswith("www."):
        parsed = urlparse(email_or_url if "://" in email_or_url else f"http://{email_or_url}")
        netloc = parsed.netloc.split(":")[0].strip().lower()
        return netloc
    return email_or_url.strip().lower()


def tokenize(text: str) -> List[str]:
    """Tokenize text into lowercase alphanumeric words, filtering out stopwords."""
    words = re.findall(r"\b[a-zA-Z0-9_\-\.]{2,}\b", text.lower())
    return [w for w in words if w not in STOPWORDS]


def compute_tfidf_cosine_similarity(text1: str, text2: str) -> float:
    """Compute cosine similarity between two texts using TF-IDF vectorization.

    Implemented in pure Python to eliminate fragile native dependencies while
    delivering high accuracy for near-duplicate text detection.
    """
    tokens1 = tokenize(text1)
    tokens2 = tokenize(text2)
    if not tokens1 or not tokens2:
        return 0.0

    all_tokens = set(tokens1).union(set(tokens2))
    doc_count = 2

    # Term Frequencies
    tf1: Dict[str, float] = {}
    tf2: Dict[str, float] = {}
    for t in tokens1:
        tf1[t] = tf1.get(t, 0) + 1
    for t in tokens2:
        tf2[t] = tf2.get(t, 0) + 1

    # Normalize TF by length
    len1 = len(tokens1)
    len2 = len(tokens2)
    for t in tf1:
        tf1[t] /= len1
    for t in tf2:
        tf2[t] /= len2

    # Compute IDF and TF-IDF vectors
    dot_product = 0.0
    norm1 = 0.0
    norm2 = 0.0

    for token in all_tokens:
        doc_freq = (1 if token in tf1 else 0) + (1 if token in tf2 else 0)
        idf = math.log((doc_count + 1) / (doc_freq + 1)) + 1.0

        v1 = tf1.get(token, 0.0) * idf
        v2 = tf2.get(token, 0.0) * idf

        dot_product += v1 * v2
        norm1 += v1 * v1
        norm2 += v2 * v2

    if norm1 == 0.0 or norm2 == 0.0:
        return 0.0

    return dot_product / (math.sqrt(norm1) * math.sqrt(norm2))


class EmailStore:
    """SQLite persistence store for processed email verdicts."""

    def __init__(self, db_path: str = "emails.db"):
        self.db_path = db_path
        self._persistent_conn = sqlite3.connect(db_path) if db_path == ":memory:" else None
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        if self._persistent_conn is not None:
            return self._persistent_conn
        return sqlite3.connect(self.db_path)

    def _close_if_transient(self, conn: sqlite3.Connection):
        if self._persistent_conn is None:
            conn.close()

    def _init_db(self):
        conn = self._get_conn()
        try:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS processed_emails (
                    email_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    sender TEXT NOT NULL,
                    sender_domain TEXT NOT NULL,
                    sender_ip TEXT,
                    subject TEXT NOT NULL,
                    body TEXT NOT NULL,
                    extracted_urls TEXT NOT NULL,
                    stage_verdict TEXT,
                    threat_score REAL,
                    campaign_id TEXT
                )
            """)
            conn.commit()
        finally:
            self._close_if_transient(conn)

    def save_email(self, verdict: EmailVerdict, campaign_id: Optional[str] = None):
        domain = extract_domain(verdict.sender)
        urls_json = json.dumps(verdict.extracted_urls)
        conn = self._get_conn()
        try:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO processed_emails (
                    email_id, timestamp, sender, sender_domain, sender_ip,
                    subject, body, extracted_urls, stage_verdict, threat_score, campaign_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                verdict.email_id,
                verdict.timestamp,
                verdict.sender,
                domain,
                verdict.sender_ip or "",
                verdict.subject,
                verdict.body,
                urls_json,
                verdict.stage_verdict,
                verdict.threat_score,
                campaign_id,
            ))
            conn.commit()
        finally:
            self._close_if_transient(conn)

    def update_campaign_id(self, email_id: str, campaign_id: str):
        conn = self._get_conn()
        try:
            cursor = conn.cursor()
            cursor.execute("UPDATE processed_emails SET campaign_id = ? WHERE email_id = ?", (campaign_id, email_id))
            conn.commit()
        finally:
            self._close_if_transient(conn)

    def get_all_emails(self, exclude_id: Optional[str] = None) -> List[EmailVerdict]:
        conn = self._get_conn()
        try:
            cursor = conn.cursor()
            if exclude_id:
                cursor.execute("SELECT email_id, timestamp, sender, sender_ip, subject, body, extracted_urls, stage_verdict, threat_score FROM processed_emails WHERE email_id != ?", (exclude_id,))
            else:
                cursor.execute("SELECT email_id, timestamp, sender, sender_ip, subject, body, extracted_urls, stage_verdict, threat_score FROM processed_emails")
            rows = cursor.fetchall()
        finally:
            self._close_if_transient(conn)

        results = []
        for r in rows:
            results.append(EmailVerdict(
                email_id=r[0],
                timestamp=r[1],
                sender=r[2],
                sender_ip=r[3] if r[3] else None,
                subject=r[4],
                body=r[5],
                extracted_urls=json.loads(r[6]) if r[6] else [],
                stage_verdict=r[7],
                threat_score=r[8] if r[8] is not None else 0.9,
            ))
        return results


class CampaignCorrelationEngine:
    """Stage 6 Engine: Correlates incoming email verdicts against previously processed emails.

    Constructs and exports an incremental NetworkX correlation graph.
    """

    def __init__(
        self,
        weights: Optional[CorrelationWeights] = None,
        correlation_threshold: float = 0.40,
        text_duplicate_threshold: float = 0.80,
        temporal_window_hours: float = 48.0,
        db_path: str = "emails.db",
    ):
        self.weights = weights or CorrelationWeights()
        self.correlation_threshold = correlation_threshold
        self.text_duplicate_threshold = text_duplicate_threshold
        self.temporal_window_hours = temporal_window_hours
        self.store = EmailStore(db_path=db_path)

        # NetworkX Incremental Graph
        self.graph = nx.Graph()

    # -------------------------------------------------------------------------
    # Signal Calculators
    # -------------------------------------------------------------------------

    def score_ip(self, ip1: Optional[str], ip2: Optional[str]) -> Tuple[float, str]:
        """Signal 1: Shared sender IP or subnet."""
        if not ip1 or not ip2:
            return 0.0, "Missing IP"
        ip1, ip2 = ip1.strip(), ip2.strip()
        if ip1 == ip2:
            return 1.0, f"Identical IP: {ip1}"

        # Check /24 subnet match (e.g. 198.51.100.*)
        octets1 = ip1.split(".")
        octets2 = ip2.split(".")
        if len(octets1) == 4 and len(octets2) == 4:
            if octets1[:3] == octets2[:3]:
                return 0.6, f"Shared /24 subnet: {'.'.join(octets1[:3])}.0/24"

        return 0.0, "Distinct IPs"

    def score_domain(self, sender1: str, sender2: str) -> Tuple[float, str]:
        """Signal 2: Shared sending domain."""
        dom1 = extract_domain(sender1)
        dom2 = extract_domain(sender2)
        if not dom1 or not dom2:
            return 0.0, "Missing sender domain"

        if dom1 == dom2:
            return 1.0, f"Exact matching domain: {dom1}"

        # Subdomain / apex match (e.g., auth.example.com vs example.com)
        parts1 = dom1.split(".")
        parts2 = dom2.split(".")
        if len(parts1) >= 2 and len(parts2) >= 2:
            apex1 = ".".join(parts1[-2:])
            apex2 = ".".join(parts2[-2:])
            if apex1 == apex2:
                return 0.8, f"Shared root apex domain: {apex1}"

        return 0.0, f"Unrelated domains ({dom1} vs {dom2})"

    def score_text(self, email1: EmailVerdict, email2: EmailVerdict) -> Tuple[float, str]:
        """Signal 3: Near-duplicate subject/body (TF-IDF cosine similarity >= 0.80)."""
        # Combine subject and body for full message context
        text1 = f"{email1.subject} {email1.body}"
        text2 = f"{email2.subject} {email2.body}"

        sim = compute_tfidf_cosine_similarity(text1, text2)

        # Subject-only similarity check to detect template variants
        subj_sim = compute_tfidf_cosine_similarity(email1.subject, email2.subject)
        effective_sim = max(sim, subj_sim)

        if effective_sim >= self.text_duplicate_threshold:
            note = f"Near-duplicate template (TF-IDF Cosine: {effective_sim:.2f} >= {self.text_duplicate_threshold:.2f})"
            return effective_sim, note
        elif effective_sim >= 0.50:
            note = f"Moderate text overlap (TF-IDF Cosine: {effective_sim:.2f})"
            return effective_sim, note
        else:
            return effective_sim, f"Low text similarity ({effective_sim:.2f})"

    def score_url(self, urls1: List[str], urls2: List[str]) -> Tuple[float, str]:
        """Signal 4: Shared URL or infrastructure reuse."""
        if not urls1 or not urls2:
            return 0.0, "No URLs to correlate"

        set1 = set(urls1)
        set2 = set(urls2)
        exact_matches = set1.intersection(set2)
        if exact_matches:
            matched_url = next(iter(exact_matches))
            return 1.0, f"Exact URL match: {matched_url}"

        # Domain and path overlap
        best_score = 0.0
        best_note = "Distinct URLs"

        for u1 in urls1:
            p1 = urlparse(u1)
            d1 = p1.netloc.lower()
            path1 = p1.path.rstrip("/")

            for u2 in urls2:
                p2 = urlparse(u2)
                d2 = p2.netloc.lower()
                path2 = p2.path.rstrip("/")

                if d1 == d2:
                    if path1 == path2:
                        score = 0.85
                        note = f"Shared URL domain and path: {d1}{path1}"
                    else:
                        score = 0.60
                        note = f"Shared URL host domain: {d1}"
                    if score > best_score:
                        best_score = score
                        best_note = note

        return best_score, best_note

    def score_temporal(self, ts1_str: str, ts2_str: str) -> Tuple[float, str]:
        """Signal 5: Temporal proximity within configurable window."""
        try:
            # Parse ISO formats (handles Z or offset)
            clean_ts1 = ts1_str.replace("Z", "+00:00")
            clean_ts2 = ts2_str.replace("Z", "+00:00")
            t1 = datetime.fromisoformat(clean_ts1)
            t2 = datetime.fromisoformat(clean_ts2)
            delta_seconds = abs((t1 - t2).total_seconds())
            delta_hours = delta_seconds / 3600.0

            if delta_hours <= self.temporal_window_hours:
                # Linear decay score from 1.0 down to 0.0 across window
                decay = max(0.0, 1.0 - (delta_hours / self.temporal_window_hours))
                return decay, f"Sent within {delta_hours:.1f}h (window: {self.temporal_window_hours}h)"
            else:
                return 0.0, f"Sent {delta_hours:.1f}h apart (outside {self.temporal_window_hours}h window)"
        except Exception as e:
            return 0.0, f"Timestamp parse error: {e}"

    # -------------------------------------------------------------------------
    # Pairwise & Incremental Correlation
    # -------------------------------------------------------------------------

    def correlate_pair(self, new_email: EmailVerdict, prior_email: EmailVerdict) -> CorrelatedEmailMatch:
        """Evaluate similarity across all 5 signals and compute fused score."""
        ip_score, ip_note = self.score_ip(new_email.sender_ip, prior_email.sender_ip)
        dom_score, dom_note = self.score_domain(new_email.sender, prior_email.sender)
        text_score, text_note = self.score_text(new_email, prior_email)
        url_score, url_note = self.score_url(new_email.extracted_urls, prior_email.extracted_urls)
        time_score, time_note = self.score_temporal(new_email.timestamp, prior_email.timestamp)

        breakdown = SignalBreakdown(
            shared_ip_score=round(ip_score, 4),
            shared_domain_score=round(dom_score, 4),
            text_similarity_score=round(text_score, 4),
            shared_url_score=round(url_score, 4),
            temporal_score=round(time_score, 4),
            details={
                "shared_ip": ip_note,
                "shared_domain": dom_note,
                "text_similarity": text_note,
                "shared_url": url_note,
                "temporal": time_note,
            }
        )

        # Fused campaign confidence calculation:
        # Fused = sum(score_i * weight_i)
        fused = (
            (breakdown.shared_url_score * self.weights.shared_url)
            + (breakdown.shared_domain_score * self.weights.shared_domain)
            + (breakdown.text_similarity_score * self.weights.text_similarity)
            + (breakdown.shared_ip_score * self.weights.shared_ip)
            + (breakdown.temporal_score * self.weights.temporal_clustering)
        )
        fused = round(min(1.0, max(0.0, fused)), 4)
        is_match = fused >= self.correlation_threshold

        return CorrelatedEmailMatch(
            prior_email_id=prior_email.email_id,
            prior_subject=prior_email.subject,
            prior_sender=prior_email.sender,
            prior_timestamp=prior_email.timestamp,
            signal_scores=breakdown,
            fused_campaign_confidence=fused,
            is_campaign_match=is_match,
        )

    def process_email(self, new_email: EmailVerdict) -> CampaignCorrelationOutput:
        """Core API: Correlates a new email verdict against historical SQLite store.

        Updates NetworkX graph incrementally and assigns campaign ID.
        """
        prior_emails = self.store.get_all_emails(exclude_id=new_email.email_id)

        matches: List[CorrelatedEmailMatch] = []
        highest_conf = 0.0
        connected_priors: List[str] = []

        # Add node to NetworkX graph
        self.graph.add_node(
            new_email.email_id,
            sender=new_email.sender,
            sender_ip=new_email.sender_ip or "",
            subject=new_email.subject,
            timestamp=new_email.timestamp,
            threat_score=new_email.threat_score or 0.9,
        )

        for prior in prior_emails:
            match = self.correlate_pair(new_email, prior)
            matches.append(match)

            if match.is_campaign_match:
                if match.fused_campaign_confidence > highest_conf:
                    highest_conf = match.fused_campaign_confidence

                connected_priors.append(prior.email_id)

                # Add weighted edge to NetworkX graph
                self.graph.add_edge(
                    new_email.email_id,
                    prior.email_id,
                    weight=match.fused_campaign_confidence,
                    signals={
                        "shared_ip": match.signal_scores.shared_ip_score,
                        "shared_domain": match.signal_scores.shared_domain_score,
                        "text_similarity": match.signal_scores.text_similarity_score,
                        "shared_url": match.signal_scores.shared_url_score,
                        "temporal": match.signal_scores.temporal_score,
                    }
                )

        # Sort matches by highest fused confidence
        matches.sort(key=lambda m: m.fused_campaign_confidence, reverse=True)

        # Determine campaign cluster ID using graph connected components
        assigned_campaign_id = self._resolve_campaign_id(new_email.email_id)

        # Update node attribute and database for all nodes in this connected component
        component_nodes = nx.node_connected_component(self.graph, new_email.email_id)
        for node_id in component_nodes:
            self.graph.nodes[node_id]["campaign_id"] = assigned_campaign_id
            self.store.update_campaign_id(node_id, assigned_campaign_id)

        # Persist new email and campaign ID to SQLite
        self.store.save_email(new_email, campaign_id=assigned_campaign_id)

        # Count clusters / campaigns
        campaign_count = nx.number_connected_components(self.graph)

        weights_dict = {
            "shared_url": self.weights.shared_url,
            "shared_domain": self.weights.shared_domain,
            "text_similarity": self.weights.text_similarity,
            "shared_ip": self.weights.shared_ip,
            "temporal_clustering": self.weights.temporal_clustering,
        }

        return CampaignCorrelationOutput(
            email_id=new_email.email_id,
            assigned_campaign_id=assigned_campaign_id,
            highest_confidence=round(highest_conf, 4),
            correlated_prior_emails=matches,
            weights_applied=weights_dict,
            correlation_threshold=self.correlation_threshold,
            graph_summary={
                "total_nodes": self.graph.number_of_nodes(),
                "total_edges": self.graph.number_of_edges(),
                "total_campaign_clusters": campaign_count,
            }
        )

    def _resolve_campaign_id(self, email_id: str) -> str:
        """Find the connected component for the email and derive a deterministic campaign ID."""
        if email_id not in self.graph:
            return "CAMPAIGN-001"

        # Find connected component containing email_id
        for idx, component in enumerate(nx.connected_components(self.graph), start=1):
            if email_id in component:
                # If component is a singleton and has no edges, check if it should be standalone
                if len(component) == 1:
                    return f"CAMPAIGN-SINGLETON-{idx:03d}"
                return f"CAMPAIGN-CLUSTER-{idx:03d}"

        return "CAMPAIGN-001"

    # -------------------------------------------------------------------------
    # Frontend Export
    # -------------------------------------------------------------------------

    def export_graph_json(self, output_filepath: Optional[str] = None) -> Dict[str, Any]:
        """Export current graph state to JSON for frontend visualization (e.g. D3.js or Cytoscape)."""
        nodes = []
        for node_id, data in self.graph.nodes(data=True):
            nodes.append({
                "id": node_id,
                "label": data.get("subject", node_id),
                "sender": data.get("sender", ""),
                "sender_ip": data.get("sender_ip", ""),
                "timestamp": data.get("timestamp", ""),
                "campaign_id": data.get("campaign_id", ""),
                "threat_score": data.get("threat_score", 0.9),
            })

        edges = []
        for u, v, data in self.graph.edges(data=True):
            edges.append({
                "source": u,
                "target": v,
                "weight": data.get("weight", 1.0),
                "signals": data.get("signals", {}),
            })

        # Generate cluster summaries
        clusters = []
        for idx, component in enumerate(nx.connected_components(self.graph), start=1):
            clusters.append({
                "campaign_index": idx,
                "size": len(component),
                "email_ids": list(component),
            })

        graph_data = {
            "metadata": {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "node_count": len(nodes),
                "edge_count": len(edges),
                "campaign_clusters_count": len(clusters),
                "weights_configured": {
                    "shared_url": self.weights.shared_url,
                    "shared_domain": self.weights.shared_domain,
                    "text_similarity": self.weights.text_similarity,
                    "shared_ip": self.weights.shared_ip,
                    "temporal_clustering": self.weights.temporal_clustering,
                }
            },
            "nodes": nodes,
            "edges": edges,
            "campaign_clusters": clusters,
        }

        if output_filepath:
            with open(output_filepath, "w", encoding="utf-8") as f:
                json.dump(graph_data, f, indent=2)

        return graph_data
