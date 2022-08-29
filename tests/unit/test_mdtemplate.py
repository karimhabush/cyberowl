"""Tests for the MDTemplate class."""
import os

import pytest

from cyberowl.mdtemplate import MDTemplate


def test_new_line():
    """Test new_line method."""
    mdtest = MDTemplate("test.md")
    mdtest.new_line("test")
    assert mdtest.buffer == "\ntest"


def test_new_header():
    """Test new_header method."""
    for level in range(1, 5):
        mdtest = MDTemplate("test.md")
        mdtest.new_header(level, "test")
        assert mdtest.buffer == f"\n\n{'#'*level} test\n"


def test_new_header_x():
    """Test new_header method."""
    mdtest = MDTemplate("test.md")
    mdtest.new_header(55, "test")
    assert mdtest.buffer == "\ntest\n"


def test_generate_table():
    """Test generate_table method."""
    mdtest = MDTemplate("test.md")
    mdtest.generate_table(
        [["Title", "Description", "Date"], ["Title1", "Description1", "Date1"]]
    )
    assert (
        mdtest.buffer
        == "\n|Title|Description|Date|\n|---|---|---|\n|Title1|Description1|Date1|"
    )


def test_create_md_file():
    """Test create_md_file method.

    Test if the file exists after the method is called.
    """
    mdtest = MDTemplate("test.md")
    mdtest.create_md_file()

    assert os.path.exists("test.md") is True
    if os.path.exists("test.md"):
        os.remove("test.md")
