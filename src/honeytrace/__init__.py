"""HoneyTrace - Linux intrusion deception, detection and evidence framework.

Architecture (see README.md):
    collectors -> normalizer -> rules/correlation -> incident store
                                    |-> evidence journal (append-only JSONL)
                                    |-> response engine (policy-gated)
                                    |-> reports / dashboard (read-only)

Collectors observe. They never block, edit evidence, or write reports.
The report layer reads the incident store and journal; it never writes them.
"""

__version__ = "2.0.0"
__author__ = "HoneyTrace Team"

APP_NAME = "honeytrace"
