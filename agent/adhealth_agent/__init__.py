"""AD forest health triage agent.

Pipeline (each stage is deterministic except the optional narrative):

    ingest  -> verify manifest hashes, validate report.json against the schema contract
    history -> persist report + findings in SQLite (month-over-month trend source)
    triage  -> score, diff vs previous full report, suppressions, urgent rules
    narrate -> Strands agent (Claude) writes the monthly digest from read-only tools;
               falls back to a deterministic template if disabled, failing, or unfaithful
    publish -> Teams (Workflows webhook, Adaptive Card) and SharePoint (Graph); dry-run by default

The LLM never decides what is urgent and never sees account names by default.
"""

__version__ = "1.0.0"
SUPPORTED_SCHEMA_MAJOR = 1
