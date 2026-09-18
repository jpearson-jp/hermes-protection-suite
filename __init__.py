"""Protection Suite — agent-side half of the plugin: deliberately empty.

The whole surface is the web-dashboard extension in ``dashboard/``: a tab that reads the platform
registry, the detection catalog, the kanban ledger, the lake's feed liveness and the exit
measurement, plus two owner write actions (answer / comment) routed through ``hermes_cli.kanban_db``.

It registers no hooks, no agent tools and no CLI commands — a dashboard plugin that quietly taught
an agent to mutate the ledger would be a second, unaudited write path.
"""


def register(ctx):  # noqa: ARG001 — the plugin contract requires the entry point
    """No-op registration: the dashboard extension needs no agent-side wiring."""
