# Changelog

## UNRELEASED

- Add your updates here :)

## [2.0.3] 2022-10-23

- Run yarn-audit-fix to upgrade dependencies with security issues (minimist, node-fetch)
- CI: Upgrade MegaLinter to v6

## [2.0.2] 2022-01-30

- Update License to MIT

## [2.0.1] 2022-01-12

- Update JSON schema to <http://json.schemastore.org/sarif-2.1.0-rtm.5.json>

## [2.0.0] 2022-01-12

- Mandatory properties `toolDriverName` and `toolDriverVersion` for SarifRunBuilder
- Change default schema version to <https://www.schemastore.org/schemas/json/sarif-2.1.0-rtm.5.json>
- When possible, automatically populate SARIF properties:
  - `artifact.sourceLanguage`
  - `result.locations.location.physicalLocation.artifactLocation.index`
  - `result.ruleIndex`
- Fix bug when initSimple is called without region properties

## [1.0.0] 2022-01-11

- Initial version
