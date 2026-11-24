# CI

This repository is published as a GitHub Actions Marketplace action. GitHub requires such a repository to contain
no workflow files, so `.github/workflows/verify.yml` was removed (it only ran the action daily against
`www.proofxray.com`). The checks are documented here instead.

## Run the tests locally (no network needed)

```bash
npm test
# = node --test   and   python3 -m unittest discover -s test -p "test_*.py" -v
```

## Check the package contents

```bash
npm pack --dry-run
npm publish --dry-run
```

## Use the action in your own workflow

Copy into `.github/workflows/` of **your** repository:

```yaml
name: PROOF verification
on:
  schedule:
    - cron: '0 0 * * *'
jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: monsieureka/autonomous-enterprise-standard@v1.0.0
        with:
          domain: example.com
          min_score: '80'
```

To run this repository's own tests in CI, add a workflow in a fork or in a separate repository that checks this
repository out and runs `npm test`.
