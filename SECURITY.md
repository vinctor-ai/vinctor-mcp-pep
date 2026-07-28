# Security Policy

Vinctor is a runtime authorization layer for AI agents, so we take security
reports seriously. This repository is the MCP enforcement proxy (PEP) — a
resource-side control that authorizes every `tools/call` before it reaches the
MCP server.

## Reporting a Vulnerability

**Please do not open a public issue for a security vulnerability.**

Report it privately through GitHub's
[**Report a vulnerability**](../../security/advisories/new) flow
(the repository's *Security* tab -> *Advisories*). We aim to acknowledge a
report within 5 business days and will keep you updated on remediation.

When you can, include: affected version/commit, a description of the impact, and
a minimal reproduction.

## Scope and Maturity

This is an **early preview** and is labelled as such. Unlike the cooperative
agent-side hooks, this proxy is resource-side: non-bypassable for the MCP path
under the ADR 0011 preconditions (the client's only route to the server is this
proxy's stdio). It is **not** a sandbox — side doors around MCP (direct shell or
network access, ambient credentials) are out of scope, and keeping the proxy on
the path is the deployment's job (see the README's *Config integrity* section).
For the full picture of what Vinctor does and does not defend against, see the
[threat model](https://github.com/vinctor-ai/vinctor-core/blob/main/docs/threat-model.md)
in `vinctor-core`.

## Supported Versions

During the preview period only the latest released version is supported.
