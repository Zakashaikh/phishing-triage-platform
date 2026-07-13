# Modern-corpus validation (recall only)

Every detector run against **8585 modern phishing samples** from [phishing_pot](https://github.com/rf-peixoto/phishing_pot) (honeypot-collected, recipients anonymized by the maintainers); 29 of 8614 samples failed to parse and are excluded.

> **This measures recall only.** The corpus contains no legitimate mail, so nothing here speaks to false positives on modern ham — precision figures come from the historical corpus ([RESULTS.md](RESULTS.md)), and a modern-ham evaluation is future work.

| Detector | Flagged | Recall |
|---|---:|---:|
| Rules, SUSPICIOUS operating point (score ≥ 20) | 2071/8585 | 24.1% |
| Rules, MALICIOUS operating point (score ≥ 50) | 189/8585 | 2.2% |
| ML, p ≥ 0.5 | 8272/8585 | 96.4% |
| Rules OR ML (triage union) | 8337/8585 | 97.1% |

Authentication rules (SPF/DKIM/DMARC) fired on **2174/8585** samples (25.3%) — on the 2003-era corpus they fired on almost none, which is why modern validation exists at all.

## Per-rule fire rates on modern phish

| Rule | Fired | Rate |
|---|---:|---:|
| `urgency_language` | 1951 | 22.7% |
| `return_path_mismatch` | 1746 | 20.3% |
| `reply_to_mismatch` | 1272 | 14.8% |
| `spf_fail` | 1239 | 14.4% |
| `url_shortener` | 1058 | 12.3% |
| `dkim_fail` | 814 | 9.5% |
| `dmarc_fail` | 664 | 7.7% |
| `link_text_mismatch` | 632 | 7.4% |
| `lookalike_domain` | 332 | 3.9% |
| `suspicious_tld` | 252 | 2.9% |
| `raw_ip_url` | 128 | 1.5% |
| `brand_freemail` | 6 | 0.1% |
| `punycode_domain` | 1 | 0.0% |
| `dangerous_attachment` | 1 | 0.0% |

Reproduce: `python evaluation/download_live.py --all` then `python evaluation/validate_modern.py`.
