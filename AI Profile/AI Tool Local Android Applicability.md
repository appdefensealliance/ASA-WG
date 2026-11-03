# AI Tool Local Android Applicability

<!-- ai-profile-version: AI-profiles-0.1.0-alpha.1 -->
Version 0.1.0-alpha.1 — 2026-11-03

This alpha defines AI security requirements and assessment procedures within the [AI-only publication scope](AI%20Alpha%20Publication%20Scope.md). A document version alone does not grant assessor authorization or authority to issue ADA certificates.

This Tool-side companion resolves the retained annex's planning labels. `Local` is an invocation/execution boundary; `Mobile` is deployment. Android stdio and AppFunctions are **mobile + local**. Ordinary downstream HTTPS does not reclassify them as public remote Tools; separately exposed remote boundaries are assessed separately.

Use each assertion's actual actor/protocol/feature conditions and explicit source exclusion, not whichever historical column is weaker. The [retained Android annex](AI%20Tool%20Local%20Android%20Requirements.md) remains the source for applicable local Tool strength, definitions and optional-profile conditions. Agent assessment does not certify these Tool internals and requires no Tool certificate.

## Corresponding retained Spec/Guide dispositions

- Tool §1.1.1 / Guide §1.1 remote client-server authentication: retain the explicit Local/Mobile exclusion of that handshake procedure. Descriptive parent-process examples do not invent a new mobile gate; independent Agent/platform caller admission still applies.
- Tool §1.2.2 / Guide §2.2 user-context validation: retain the applicable Local/Mobile requirement, scoped downstream exchange and original strength. This is not Guide §1.5's different identity-propagation clause.
- Tool §2.2.2 / Guide §1.5 multi-user identity propagation: its explicit Mobile exclusion applies to Android despite the Local column. It does not exclude independent authorization/user-context duties in §§1.2.1–1.2.2, Agent protections or MASA.
- Tool §1.3.2 / Guide §1.6 downstream transport, and §§1.5.1–1.5.2 / Guide §§1.3–1.4 redirect/PKCE: retain the explicit Mobile exclusions of those Tool procedures. Applicable released MASA transport/platform requirements and separately exposed remote-component duties still apply.
- Tool §§1.4.2–1.4.3 action idempotency/lifecycle: preserve applicable original Local/Mobile strength. The #544 Agent policy change does not demote the local Tool annex.
- Preserve applicable local consent, secret management, request/user isolation, sandbox, metadata, resource and audit controls and conditional Wire Format adoption. No remote SHOULD overlay weakens them.

The mapping is tied to actual corresponding IDs and source conditions, not a blanket mobile waiver. Any genuinely contradictory assertion must receive explicit WG disposition, not an invented passing exclusion. The [Agent applicability record](AI%20Agent%20Assessment%20Applicability.md) separately maps Agent-owned duties at the invoked interface.

The standalone Tool alpha scope remains remote HTTP plus retained local Android; other local Tool routes are deferred under [AI-only publication scope](AI%20Alpha%20Publication%20Scope.md). Desktop/mobile Agent runtime requirements remain applicable independently.
