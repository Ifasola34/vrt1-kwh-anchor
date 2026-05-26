"""Shared fixtures for vrt1-kwh-anchor tests."""

import time

import pytest

from veritas.crypto import OracleKey
from vrt1_kwh.attestation import KwhMeasurement, sign_measurement


@pytest.fixture
def oracle_key():
    return OracleKey.from_hex("1111111111111111111111111111111111111111111111111111111111111111")


@pytest.fixture
def make_signed_measurement(oracle_key):
    def _make(idx: int = 0, device_key: OracleKey | None = None):
        key = device_key or oracle_key
        m = KwhMeasurement(
            device=key.xonly_pubkey_hex,
            window_start=1700000000 + idx * 300,
            window_end=1700000000 + idx * 300 + 30,
            kwh=round(0.05 + idx * 0.01, 9),
            source="stub",
            model_id="vrt1.kwh.stub.v1",
            v=1,
        )
        return sign_measurement(m, key)

    return _make


@pytest.fixture
def sample_corpus(make_signed_measurement):
    return [make_signed_measurement(i) for i in range(5)]
