# ClauseWindow

[![CI Status](https://github.com/knarayanareddy/clausewindow/actions/workflows/ci.yml/badge.svg)](https://github.com/knarayanareddy/clausewindow/actions)
![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)
![Python](https://img.shields.io/badge/Python-3.12-blue.svg)

> **Constitutional Rule**: Decision support only. Not legal advice. A qualified lawyer must sign.

Whole-document commercial contract review and corporate legal playbook enforcement without vector chunking. ClauseWindow eliminates RAG blind spots by analyzing full 80+ page agreements in a single context window, identifying hidden liability cap contradictions across appendices (such as Schedule 4 traps), and intercepting adversarial prompt injections.

---

## Quickstart

```bash
# Clone the repository
git clone https://github.com/knarayanareddy/clausewindow.git
cd clausewindow

# Install dependencies
pip install -e .

# Run demo
python main.py demo

# Start API server
python main.py serve --port 8000
```

See [SPEC.md](SPEC.md) for full architectural specifications, fixture benchmarks, and the implementation checklist.
