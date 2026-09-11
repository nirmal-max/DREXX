# Repository regression gate

The `repository-wide-regression.yml` workflow discovers every tracked `tests` directory, compiles Python sources, and executes each discovered pytest suite 100 consecutive times. A successful run proves repeatable software-test stability on the GitHub Actions runner; it does not qualify physical storage hardware or prove physical destruction.