import pytest

from cyberowl.sources import CYBEROWL_SOURCES


def test_sources():
    """
    Tests if CYBEROWL_SOURCES is a list of 2 element lists.
    """
    for source in CYBEROWL_SOURCES:
        assert len(source) == 2
