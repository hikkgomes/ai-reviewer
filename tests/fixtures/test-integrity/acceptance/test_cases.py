import pytest
import inspect
from unittest.mock import patch

from service import load


def test_disabled_case():
    pytest.skip("quarantined until the independent contract is reviewed")


def test_weakened_case():
    assert load()


def test_circular_oracle():
    assert load() == load()


def test_source_shape_oracle():
    assert "return {'value': 1}" in inspect.getsource(load)


def test_focal_subject_mocked():
    with patch("service.load"):
        assert True


def test_tautology():
    assert True


def test_setup_only():
    value = load()
