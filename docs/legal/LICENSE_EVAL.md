# License evaluation — echo-core / orin-guard / js-agent

Current license of this monorepo: **MIT**.

## Recommendation for the extracted packages

Keep **MIT** for the first public mirrors so the packages stay compatible
with js-agent and with `rfc8785` / `psutil`.

Apache-2.0 is a later option if patent grants become a release requirement.
That switch needs a dependency license compatibility review of the lockfile
and is **not** done by this document.

## Blockers before Apache-2.0 relicensing

- Confirm every contributor (DCO / CLA).
- Review `rfc8785` and `psutil` license compatibility.
- Record the decision in THIRD_PARTY_NOTICES for each package.
