"""Shared pytest configuration for the taylor Python tests."""

import inspect


def pytest_collection_modifyitems(items):
    # Each test's docstring becomes a "description" property in JUnit XML reports (--junitxml).
    for item in items:
        doc = inspect.getdoc(getattr(item, "function", None))
        if doc:
            item.user_properties.append(("description", doc))
