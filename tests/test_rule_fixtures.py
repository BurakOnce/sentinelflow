import pytest

from detections.engine.fixtures import (
    FIXTURES_DIR,
    CaseResult,
    load_fixture,
    missing_positive_fixtures,
    run_fixtures,
)
from detections.engine.loader import RuleSet, load_rules
from enrichment.geo import NetworkTableGeoLookup


@pytest.fixture(scope="module")
def rules() -> RuleSet:
    return load_rules()


@pytest.fixture(scope="module")
def results(rules: RuleSet) -> list[CaseResult]:
    return run_fixtures(rules, NetworkTableGeoLookup.from_fixtures())


def test_every_alerting_rule_has_a_positive_fixture(
    rules: RuleSet, results: list[CaseResult]
) -> None:
    assert missing_positive_fixtures(rules, results) == []


def test_every_fixture_targets_an_alerting_rule(rules: RuleSet) -> None:
    names = {rule.meta.name for rule in rules.alerting}
    for path in FIXTURES_DIR.glob("*.yml"):
        assert load_fixture(path).rule in names, path.name


def test_fixture_cases_behave_as_expected(results: list[CaseResult]) -> None:
    failures = [result for result in results if not result.passed]
    assert failures == []
    assert {result.expected for result in results} == {"alert", "no_alert"}
