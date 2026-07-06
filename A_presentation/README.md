# A_presentation/ — AI Threat Engine thesis presentation

Everything for the defense presentation, self-contained.

| File | What it is |
|---|---|
| `AI_Threat_Engine_Presentation.pptx` | **The deck** — 30 slides, dark theme, speaker notes embedded on every slide |
| `script.md` | Full spoken script, per-slide timings + likely Q&A + a walkthrough of the existing frontend |
| `demo_runbook.md` | **10-minute LIVE-DEMO runbook** — ordered most-important-live → least (attack→detect→explain→ML→agent), with timings, one-liners, and contingencies |
| `AI_Threat_Engine_Extended_Report.docx` | Extended report — abstract + securing mobile/AI apps + reliability + pentest plan + guardrails + more-agentic + go-to-market sales plan |
| `Thesis_Improvement_and_Admissions_Guide.docx` | How to strengthen the thesis for ETH Zürich / EPFL / Europe / Australia, better academic titles, per-program positioning |
| `images/` | All 13 generated diagrams/charts (also embedded in the deck) |
| `make_images.py` | Regenerates every image (matplotlib, dark theme) |
| `make_ppt.py` | Regenerates the deck from the images (python-pptx) |
| `make_docs.py` | Regenerates the two `.docx` documents (python-docx) |

## Slide map

1. Title · 2. Motivation · 3. Wazuh integration · 4. Technologies ·
5. **Unsupervised training pipeline** · 6. Feature engineering (16) ·
7. Isolation Forest · 8. Autoencoder · 9. Ensemble & labels ·
10. Score injection (system + RAG) · 11. ML evaluation ·
12. RAG — why it explains · 13. Vector DB (hybrid + RRF) ·
14. PostgreSQL · 15. Grounded answer generation · 16. RAG evaluation ·
17. Agentic CVE workflow · 18. **Full system architecture** ·
19. Results at a glance · 20. Future work & conclusion

## Regenerate after edits

```bash
cd /home/sek/wazuh
./ai_threat_engine_starter/venv/bin/python3 A_presentation/make_images.py
./ai_threat_engine_starter/venv/bin/python3 A_presentation/make_ppt.py
```

## Live ML visualization for the defense

The ML ensemble is an *intrinsic* (invisible) component — hard to demo. The
interactive **ML Engine page** (`improved_UI/ml.html`) makes it visible: pick a
sample alert, press "Score this alert", and watch it flow through 16-feature
extraction → Isolation Forest → Autoencoder → weighted fusion → tier verdict,
followed by the score-separation histogram, confusion matrix and metrics. Use
it in demo step 4 (see `demo_runbook.md`) to show *how* a score is produced.

All numbers in the deck come from the real evaluations
(2026-05-21 ML eval · retrieval eval · 2026-07 generation eval).
If results change, update the constants in the two scripts and regenerate.
