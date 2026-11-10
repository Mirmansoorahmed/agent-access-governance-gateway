"""Approval CLI (task 9) -- list the queue and grant/deny requests.

CLI-first per the approved decision (a web UI is optional and out of scope now).
It operates on a persisted :class:`ApprovalStore` JSON file shared with the
running gateway, so an approver in a separate terminal can act on the queue.

Grants are single-use and scoped to one (agent, tool, args-hash); four-eyes
requires two distinct approver ids; break-glass requires a justification. Every
grant/deny records approver id, timestamp and decision in the store's log for
the evidence trail and the Approvals report.

Usage:
    python -m gateway.cli --store .gateway/approvals.json list
    python -m gateway.cli --store .gateway/approvals.json grant \
        --agent u1 --server crm --tool export_clients --args-hash <h> \
        --tier four-eyes --approver alice --approver bob
    python -m gateway.cli --store .gateway/approvals.json deny \
        --agent u1 --server crm --tool export_clients --args-hash <h> \
        --approver alice --reason "not justified"
"""

from __future__ import annotations

import click

from .approvals import ApprovalError, ApprovalStore


@click.group()
@click.option("--store", "store_path", required=True, help="Path to the approvals JSON store.")
@click.pass_context
def cli(ctx: click.Context, store_path: str) -> None:
    """Access Governance Gateway approval queue CLI."""
    ctx.obj = ApprovalStore(path=store_path)


@cli.command(name="list")
@click.pass_obj
def list_queue(store: ApprovalStore) -> None:
    """List pending approval requests."""
    pending = store.pending()
    if not pending:
        click.echo("No pending approval requests.")
        return
    click.echo(f"{len(pending)} pending request(s):")
    for req in pending:
        click.echo(
            f"  [{req.tier}] agent={req.agent} {req.server}/{req.tool} args_hash={req.args_hash}"
        )


@cli.command()
@click.option("--agent", required=True)
@click.option("--server", required=True)
@click.option("--tool", required=True)
@click.option("--args-hash", "args_hash_", required=True)
@click.option("--tier", required=True, type=click.Choice(["ask", "four-eyes", "break-glass"]))
@click.option(
    "--approver",
    "approvers",
    multiple=True,
    required=True,
    help="Approver id. Repeat for four-eyes (two distinct ids required).",
)
@click.option("--justification", default="", help="Required for break-glass.")
@click.pass_obj
def grant(store: ApprovalStore, agent, server, tool, args_hash_, tier, approvers, justification):
    """Grant a single-use authorization for one (agent, tool, args) call."""
    try:
        record = store.grant(
            agent,
            server,
            tool,
            args_hash_,
            tier,
            approvers=tuple(approvers),
            justification=justification,
        )
    except ApprovalError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(
        f"Granted [{record.tier}] {agent} -> {server}/{tool} "
        f"by {', '.join(record.approvers)} (single-use, ttl={record.ttl_seconds}s)"
    )


@cli.command()
@click.option("--agent", required=True)
@click.option("--server", required=True)
@click.option("--tool", required=True)
@click.option("--args-hash", "args_hash_", required=True)
@click.option("--tier", required=True, type=click.Choice(["ask", "four-eyes", "break-glass"]))
@click.option("--approver", required=True, help="This approver's id.")
@click.option("--justification", default="", help="Required for break-glass.")
@click.pass_obj
def approve(store: ApprovalStore, agent, server, tool, args_hash_, tier, approver, justification):
    """Record one approver's decision (sequential four-eyes: run twice, distinct ids)."""
    try:
        record = store.approve(
            agent,
            server,
            tool,
            args_hash_,
            tier,
            approver=approver,
            justification=justification,
        )
    except ApprovalError as exc:
        raise click.ClickException(str(exc)) from exc
    if record is None:
        so_far = store.partial_approvers(agent, server, tool, args_hash_)
        click.echo(
            f"Recorded approval by {approver} for {agent} -> {server}/{tool}. "
            f"four-eyes needs a second distinct approver (so far: {', '.join(so_far)})."
        )
    else:
        click.echo(
            f"Granted [{record.tier}] {agent} -> {server}/{tool} "
            f"by {', '.join(record.approvers)} (single-use, ttl={record.ttl_seconds}s)"
        )


@cli.command()
@click.option("--agent", required=True)
@click.option("--server", required=True)
@click.option("--tool", required=True)
@click.option("--args-hash", "args_hash_", required=True)
@click.option("--approver", required=True)
@click.option("--reason", default="")
@click.pass_obj
def deny(store: ApprovalStore, agent, server, tool, args_hash_, approver, reason):
    """Reject a pending request."""
    store.reject(agent, server, tool, args_hash_, approver=approver, reason=reason)
    click.echo(f"Denied {agent} -> {server}/{tool} by {approver}")


def main() -> None:  # pragma: no cover - console entrypoint
    cli()


if __name__ == "__main__":  # pragma: no cover
    main()
