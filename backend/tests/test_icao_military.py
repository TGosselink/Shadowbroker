"""Tests for ICAO country enrichment and military type classification."""
import pytest
from services.fetchers.military import _enrich_country, _classify_military_type


class TestEnrichCountry:
    def test_china_range(self):
        assert _enrich_country("780000", "Unknown") == ("China", "PLA")

    def test_japan_range(self):
        assert _enrich_country("840000", "Unknown") == ("Japan", "JSDF")

    def test_taiwan_range(self):
        assert _enrich_country("E80000", "Unknown") == ("Taiwan", "ROC")

    def test_south_korea_range(self):
        assert _enrich_country("700000", "Unknown") == ("South Korea", "ROK")

    def test_out_of_range_unknown_flag(self):
        assert _enrich_country("A00000", "Unknown") == ("Unknown", "")

    def test_valid_flag_preserved(self):
        country, force = _enrich_country("780000", "United States")
        assert country == "United States"
        assert force == ""

    def test_empty_flag_uses_icao(self):
        assert _enrich_country("840000", "") == ("Japan", "JSDF")

    def test_military_asset_flag_uses_icao(self):
        assert _enrich_country("E80000", "Military Asset") == ("Taiwan", "ROC")

    def test_invalid_hex_with_unknown(self):
        assert _enrich_country("ZZZZ", "Unknown") == ("Unknown", "")

    def test_invalid_hex_with_empty(self):
        assert _enrich_country("ZZZZ", "") == ("Military Asset", "")


class TestClassifyMilitaryType:
    @pytest.mark.parametrize("model,expected", [
        ("J-20", "fighter"),
        ("Y-20", "cargo"),
        ("KJ-500", "recon"),
        ("YY-20", "tanker"),
        ("F-15J", "fighter"),
        ("FA-50", "fighter"),
        ("E-2K", "recon"),
        ("F16", "fighter"),
        ("C17", "cargo"),
        ("P8", "recon"),
        ("H60", "heli"),
        ("K35", "tanker"),
        ("Boeing 737", "default"),
    ])
    def test_classification(self, model: str, expected: str):
        assert _classify_military_type(model) == expected
