# Day 2 Walkthrough: Protocol Forensics

This walkthrough covers the six baseline header fixtures and the two requested edge cases. The fixtures exercise the Module 1 contract without implementing Modules 2, 3, 4, or 6. External DNS and DKIM results are controlled by the test fixture so the cases are repeatable and do not require internet access.

Run:

```powershell
python -m unittest discover -s tests -p "test_*.py" -v
python tests/run_protocol_walkthrough.py
```

## Expected / observed result table

| Case | SPF | DKIM | DMARC | Alignment | Risk | Observed evidence |
| --- | --- | --- | --- | --- | ---: | --- |
| 1. All authentication passes | pass | pass | pass | strict | 0.000 | No warnings or protocol failure reasons. |
| 2. SPF failure | fail | pass | pass | strict | 0.250 | `SPF validation returned fail`. |
| 3. DKIM failure | pass | fail | pass | strict | 0.250 | `DKIM validation returned fail`. |
| 4. DMARC policy failure | pass | pass | fail | strict | 0.250 | `DMARC validation returned fail`. |
| 5. Received hop without source IP | neutral | pass | pass | strict | 0.125 | Relay hop could not be identified; SPF was neutral because no source IP was available. |
| 6. Missing DKIM and Received headers | neutral | neutral | pass | unknown | 0.000 | No crash; SPF and DKIM remain neutral. |
| 7. Missing DMARC record | pass | pass | neutral | unknown | 0.000 | `DMARC record unavailable`; no artificial mismatch risk is added. |
| 8. Valid DKIM with mismatched signing domain | pass | pass | pass | unknown | 0.250 | DKIM cryptographic pass retained, with explicit signing-domain alignment warning and risk reason. |

## Corrections made after review

1. A missing DMARC record no longer becomes a generic validation error. It returns `neutral` and records an explicit availability warning, preserving the distinction between absent evidence and a failed policy.
2. A DKIM signature that verifies but uses a non-aligning signing domain is no longer treated as clean. The result remains `pass` for cryptographic validity, while DMARC alignment becomes `unknown`, a warning is emitted, and the protocol risk includes a concrete mismatch reason.
3. `checkdmarc` is now included in the root dependency file because Module 1 calls it directly.
