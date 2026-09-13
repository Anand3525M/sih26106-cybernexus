import unittest
import json
import sys
from pathlib import Path

# Support running tests from repository root or subfolder
CURRENT_DIR = Path(__file__).parent.resolve()
if str(CURRENT_DIR) not in sys.path:
    sys.path.insert(0, str(CURRENT_DIR))

from models import EmailVerdict, CorrelationWeights
from correlation_engine import (
    CampaignCorrelationEngine,
    compute_tfidf_cosine_similarity,
    extract_domain,
)


class TestCampaignCorrelationEngine(unittest.TestCase):

    def setUp(self):
        self.weights = CorrelationWeights(
            shared_url=0.35,
            shared_domain=0.20,
            text_similarity=0.25,
            shared_ip=0.15,
            temporal_clustering=0.05,
        )
        self.db_path = ":memory:"
        self.engine = CampaignCorrelationEngine(
            weights=self.weights,
            correlation_threshold=0.40,
            text_duplicate_threshold=0.80,
            temporal_window_hours=48.0,
            db_path=self.db_path,
        )

    def test_extract_domain(self):
        self.assertEqual(extract_domain("alice@example.com"), "example.com")
        self.assertEqual(extract_domain("http://phish.example.org/path"), "phish.example.org")
        self.assertEqual(extract_domain("https://login.portal.net:8080/auth"), "login.portal.net")

    def test_tfidf_cosine_similarity(self):
        text_a = "Urgent: Mandatory Direct Deposit Verification Required"
        text_b = "Urgent: Action Required - Direct Deposit Verification"
        text_c = "Delicious pizza delivery discount coupon code"

        sim_ab = compute_tfidf_cosine_similarity(text_a, text_b)
        sim_ac = compute_tfidf_cosine_similarity(text_a, text_c)

        self.assertGreater(sim_ab, 0.60)
        self.assertLess(sim_ac, 0.15)

    def test_ip_scoring(self):
        score_exact, _ = self.engine.score_ip("198.51.100.42", "198.51.100.42")
        score_subnet, _ = self.engine.score_ip("198.51.100.42", "198.51.100.99")
        score_diff, _ = self.engine.score_ip("198.51.100.42", "203.0.113.1")

        self.assertEqual(score_exact, 1.0)
        self.assertEqual(score_subnet, 0.6)
        self.assertEqual(score_diff, 0.0)

    def test_domain_scoring(self):
        score_exact, _ = self.engine.score_domain("a@evil.com", "b@evil.com")
        score_apex, _ = self.engine.score_domain("a@sub.evil.com", "b@evil.com")
        score_diff, _ = self.engine.score_domain("a@evil.com", "b@good.com")

        self.assertEqual(score_exact, 1.0)
        self.assertEqual(score_apex, 0.8)
        self.assertEqual(score_diff, 0.0)

    def test_url_scoring(self):
        urls1 = ["http://phish.net/login?token=123"]
        urls2 = ["http://phish.net/login?token=123"]
        urls3 = ["http://phish.net/login?token=456"]
        urls4 = ["http://phish.net/other"]
        urls5 = ["http://different.org/test"]

        score_exact, _ = self.engine.score_url(urls1, urls2)
        score_path, _ = self.engine.score_url(urls1, urls3)
        score_host, _ = self.engine.score_url(urls1, urls4)
        score_none, _ = self.engine.score_url(urls1, urls5)

        self.assertEqual(score_exact, 1.0)
        self.assertEqual(score_path, 0.85)
        self.assertEqual(score_host, 0.60)
        self.assertEqual(score_none, 0.0)

    def test_temporal_scoring(self):
        score_close, _ = self.engine.score_temporal("2026-09-10T10:00:00Z", "2026-09-10T11:00:00Z")
        score_far, _ = self.engine.score_temporal("2026-09-10T10:00:00Z", "2026-09-15T10:00:00Z")

        self.assertGreater(score_close, 0.90)
        self.assertEqual(score_far, 0.0)

    def test_end_to_end_correlation_and_export(self):
        email1 = EmailVerdict(
            email_id="TEST-001",
            timestamp="2026-09-10T08:00:00Z",
            sender="hr@phishcorp.com",
            sender_ip="198.51.100.10",
            subject="Urgent Payroll Notification",
            body="Verify your account at http://phishcorp.com/login",
            extracted_urls=["http://phishcorp.com/login"],
        )
        email2 = EmailVerdict(
            email_id="TEST-002",
            timestamp="2026-09-10T09:00:00Z",
            sender="payroll@phishcorp.com",
            sender_ip="198.51.100.10",
            subject="Urgent Payroll Confirmation",
            body="Verify your account at http://phishcorp.com/login",
            extracted_urls=["http://phishcorp.com/login"],
        )

        res1 = self.engine.process_email(email1)
        self.assertEqual(len(res1.correlated_prior_emails), 0)

        res2 = self.engine.process_email(email2)
        self.assertEqual(len(res2.correlated_prior_emails), 1)
        self.assertTrue(res2.correlated_prior_emails[0].is_campaign_match)
        self.assertGreaterEqual(res2.highest_confidence, 0.8)

        # Graph export test
        exported = self.engine.export_graph_json()
        self.assertEqual(exported["metadata"]["node_count"], 2)
        self.assertEqual(exported["metadata"]["edge_count"], 1)
        self.assertEqual(exported["metadata"]["campaign_clusters_count"], 1)

    def test_benign_corporate_noise_not_correlated(self):
        """Verify that two benign emails sharing domain and subnet within 2.5h do not falsely link."""
        noise1 = EmailVerdict(
            email_id="NOISE-001",
            timestamp="2026-09-10T10:15:00Z",
            sender="vince.kaminski@enron.com",
            sender_ip="192.152.140.9",
            subject="Re: Risk Management Model Documentation Review",
            body="Vince, attached is the updated documentation on the Monte Carlo simulation models.",
            extracted_urls=[],
            stage_verdict="legitimate",
            threat_score=0.05,
        )
        noise2 = EmailVerdict(
            email_id="NOISE-002",
            timestamp="2026-09-10T12:45:00Z",
            sender="jeff.dasovich@enron.com",
            sender_ip="192.152.140.22",
            subject="California Legislative and Regulatory Summary - Sept 10",
            body="Please find the daily summary of hearings at the California Public Utilities Commission.",
            extracted_urls=["http://www.cpuc.ca.gov/proceedings/filings"],
            stage_verdict="legitimate",
            threat_score=0.08,
        )

        match = self.engine.correlate_pair(noise1, noise2)
        # Under tuned weights, fused score must be strictly below threshold (0.40)
        self.assertLess(match.fused_campaign_confidence, self.engine.correlation_threshold)
        self.assertFalse(match.is_campaign_match)


if __name__ == "__main__":
    unittest.main()
