import libdsec


def test_package_docstring_cites_paper():
    assert "2609.22978" in libdsec.__doc__
