"""Agent Access Governance Gateway (fork-only runtime PEP).

Fork of microsoft/apm (Apache-2.0). This package adds a *runtime* Policy
Enforcement Point on top of upstream APM's install-time governance. It never
modifies ``apm_cli``; it only reads the effective policy and lockfile.

The package is deliberately dependency-light: core decision logic uses the
standard library so it is unit-testable without network access. Network-bound
integrations (OPA PDP, OIDC verification, OTLP export, PDF rendering) sit behind
adapters that are wired in CI, where network is available.
"""

from __future__ import annotations

__all__ = ["__version__"]

__version__ = "0.1.0"
