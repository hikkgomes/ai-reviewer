from unittest.mock import Mock

from service import load


def test_external_boundary_mock():
    client = Mock()
    client.fetch.return_value = {"value": 1}
    assert load(client) == {"value": 1}


def test_independent_contract():
    assert load() == {"value": 1}


def test_compile_contract():
    compile("value = 1", "fixture.py", "exec")
