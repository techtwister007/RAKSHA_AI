# 10 · Spin-offs & Roadmap

One slide in the deck; a real roadmap behind it. Each spin-off reuses the same core
(find → prove → report, with ROE and the vaccine) pointed at a different customer. This
shows the jury the idea is a *platform*, not a one-off demo.

| Spin-off | Customer | Why it's a natural extension |
|----------|----------|------------------------------|
| **RAKSHA-Induct** | Procurement / acceptance boards | Vet vendor software *before* induction — SBOM + scan + report. Directly relevant to Make-in-India vendor software that must be cleared before it enters service. |
| **RAKSHA-Gate** | Army software dev teams | A pre-deployment CI gate: nothing ships with a known, fixable vulnerability. |
| **RAKSHA-Range** | EME School, cyber cadres | A training range built from ARVO bugs + red-team self-play. (Instructional technology is our home turf.) |
| **RAKSHA-Firmware** | EME equipment, radios, embedded systems | Binary/firmware analysis of electronic systems — EME's core domain. |
| **RAKSHA-Vaccine** | CERT / central cyber cell | Fleet-wide variant scanning from every fix discovered anywhere in the force. *(Note: the vaccine mechanism itself is a core feature — file 09. This spin-off is that same mechanism operated centrally across the whole force, not a separate build.)* |

## Why this matters for scoring

- Shows **scalability** beyond the demo — the same engine serves procurement, dev teams,
  training, firmware and central defence.
- Shows **operational empathy** — each spin-off maps to a real organisation and a real
  decision they already make.
- Keeps the core **lightweight** — spin-offs are configurations of one platform, not
  five separate builds.

## Roadmap framing (if asked "what's next")

1. **Now (finale):** the core find→fix→prove loop, offline, on 3–4 languages, with the
   console, ROE and vaccine demonstrated.
2. **Near:** harden the offline mirror and the sneakernet refresh; broaden the Python
   sanitizer set; QLoRA self-improvement on-prem.
3. **Later:** the spin-offs above, starting with RAKSHA-Induct (procurement) and
   RAKSHA-Range (training), since both sit naturally at EME School.
