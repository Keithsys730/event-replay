"""Smoke test for event-replay package bootstrap."""

from __future__ import annotations
import event_replay


def test_package_metadata():
    assert event_replay.__version__ == "0.1.0"
