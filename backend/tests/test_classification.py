"""Unit tests: rule evaluation + classification order."""

from assessment.engine import classify, evaluate_social_engineering, evaluate_technical


class TestSocialEngineering:
    def test_urgency_en(self):
        _evidence, rules = evaluate_social_engineering("Act now! Your account blocked!")
        assert "SE_URGENCY_EN" in rules
        assert "SE_AUTHORITY_EN" in rules

    def test_urgency_hi(self):
        _evidence, rules = evaluate_social_engineering("तुरंत खाता बंद होगा")
        assert "SE_URGENCY_HI" in rules

    def test_financial_bait(self):
        _, rules = evaluate_social_engineering("You won a lottery prize!")
        assert "SE_FINANCIAL_BAIT_EN" in rules

    def test_credential_request(self):
        _, rules = evaluate_social_engineering("Enter OTP to verify")
        assert "SE_CREDENTIAL_EN" in rules

    def test_clean_text(self):
        _evidence, rules = evaluate_social_engineering("Meeting at 3pm tomorrow")
        assert rules == []


class TestTechnical:
    def test_new_domain_weak(self):
        _evidence, rules = evaluate_technical(["new.example"], [], domain_age_days=5)
        assert "TECH_NEW_DOMAIN" in rules
        # Weak signal alone must not produce HIGH_RISK (checked via classify)

    def test_old_domain(self):
        _, rules = evaluate_technical(["old.example"], [], domain_age_days=400)
        assert "TECH_NEW_DOMAIN" not in rules


class TestClassify:
    def test_confirmed(self):
        assert classify(has_verified_match=True, corroborating_categories={"threat_intel"}, se_rule_count=0, has_weak_technical=False, all_providers_responded=True) == "CONFIRMED_MALICIOUS"

    def test_high_risk(self):
        assert classify(has_verified_match=False, corroborating_categories={"threat_intel", "social_engineering"}, se_rule_count=1, has_weak_technical=False, all_providers_responded=True) == "HIGH_RISK"

    def test_suspicious_se(self):
        assert classify(has_verified_match=False, corroborating_categories={"social_engineering"}, se_rule_count=1, has_weak_technical=False, all_providers_responded=True) == "SUSPICIOUS"

    def test_suspicious_weak(self):
        assert classify(has_verified_match=False, corroborating_categories={"structural"}, se_rule_count=0, has_weak_technical=True, all_providers_responded=True) == "SUSPICIOUS"

    def test_no_threat(self):
        assert classify(has_verified_match=False, corroborating_categories=set(), se_rule_count=0, has_weak_technical=False, all_providers_responded=True) == "NO_KNOWN_THREAT_DETECTED"

    def test_inconclusive(self):
        assert classify(has_verified_match=False, corroborating_categories=set(), se_rule_count=0, has_weak_technical=False, all_providers_responded=False) == "INCONCLUSIVE"

    def test_domain_age_never_high_risk_alone(self):
        # Single weak technical → SUSPICIOUS max, never HIGH_RISK
        result = classify(has_verified_match=False, corroborating_categories={"structural"}, se_rule_count=0, has_weak_technical=True, all_providers_responded=True)
        assert result != "HIGH_RISK"
