# BreachGraph AI

**AI-powered cloud identity security investigator.** BreachGraph finds how an identity
can chain group memberships, role assumptions and permissions to reach a sensitive
resource. It proves each step with evidence and lets you test a least-privilege fix
before you apply it.

> Status: **stage 1 of 11, built during the Meta Global AI Developer Hackathon
> (Oct 26 – Nov 4, 2026).** This stage has the synthetic dataset, the deterministic
> risk engine, the remediation simulator, a CLI and tests. The web dashboard and the
> Meta model integration are not built yet.

## Quick start

Requires Python 3.11 or newer. No cloud account and no API key are needed.

```bash
cd breachgraph/backend
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest -q                          # expect: 38 passed
python -m breachgraph.cli ../data/sample_org.json
python -m breachgraph.cli ../data/sample_org.json --fix ../data/fixes/signature_fix.json
```

## The sample investigation

`data/sample_org.json` describes **Halcyon Payments**, a fictional company. All data is
synthetic. The engine finds this chain:

```
Jordan Reyes (contractor, no MFA)
  -> member of CI Maintainers
  -> can assume role ci-deploy             (policy ci-assume-deploy / AssumeDeployRole)
  -> can assume role data-platform-admin   (ci-deploy-permissions / AssumeAnyRole: sts:AssumeRole on "*",
                                            unused for 140 days)
  -> admin access to customer-pii          (data-platform-full / FullS3: s3:*)
```

If you remove the unused `AssumeAnyRole` statement (`data/fixes/signature_fix.json`):
4 attack paths are broken, no new paths appear, CI keeps its deploy access, and the
attack-path risk sum drops from 516 to 167.

## How the engine works

- **Sessions follow AWS rules.** A user's session holds the user's policies plus the
  user's groups' policies. An assumed role holds only the role's own policies, so a
  deny on the user does not carry over into the role.
- **Role trust.** A trust policy that names the principal is enough on its own. Trust
  in `account:*` hands the decision to the caller's `sts:AssumeRole` permission.
- **Explicit Deny wins** when it fully covers the allowed action. A partial overlap is
  treated as still allowed, which errs on the side of reporting.
- **Search.** Breadth-first search over role assumptions finds the shortest chain to
  every role, with a hop limit and protection against cycles.
- **Attack-path findings.** A path becomes a finding when it reaches a high or
  critical resource and either needs a role chain or starts from a risky identity (no
  MFA, external, inactive for more than 90 days).
- **Scoring.** The score is a visible sum of named factors (sensitivity, access level,
  identity risk, escalation), capped at 100. It is a prioritisation heuristic, not a
  probability.
- **Statement findings.** Wildcard actions or resources, and permissions unused for
  more than 90 days. Each one is linked to the attack paths it enables.

## Known limitations (stage 1)

- This is a simplified IAM model. It has no resource-based policies, permission
  boundaries, SCPs, conditions or `NotAction`, and it does not check that an action's
  service matches the resource type.
- Last-used and last-login values come from the dataset. They are not collected live.
- Data is synthetic only. BreachGraph does not connect to a real cloud account.
