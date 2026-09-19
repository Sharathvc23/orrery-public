"""The local API token file: generated on absence, 0600, stable across reads."""

from __future__ import annotations

import os
import stat

import pytest

from community_member import local_auth

pytestmark = pytest.mark.no_local_token


@pytest.fixture(autouse=True)
def _no_env_override(monkeypatch):
    monkeypatch.delenv(local_auth.TOKEN_ENV_VAR, raising=False)


def test_a_token_is_generated_when_none_exists(tmp_path):
    token = local_auth.load_or_create_token(tmp_path)
    assert token
    assert (tmp_path / local_auth.TOKEN_FILENAME).read_text().strip() == token


def test_the_token_file_is_not_readable_by_other_users(tmp_path):
    local_auth.load_or_create_token(tmp_path)
    mode = stat.S_IMODE(os.stat(tmp_path / local_auth.TOKEN_FILENAME).st_mode)
    assert mode == 0o600, f"mode is {oct(mode)}"


def test_the_same_token_is_returned_on_the_next_start(tmp_path):
    """An existing install keeps its token; a restart does not invalidate a
    client that already has one."""
    first = local_auth.load_or_create_token(tmp_path)
    assert local_auth.load_or_create_token(tmp_path) == first


def test_an_install_with_no_token_file_gets_one_with_no_operator_action(tmp_path):
    """The upgrade path: a home directory that predates this file."""
    (tmp_path / "config.json").write_text("{}")
    assert not (tmp_path / local_auth.TOKEN_FILENAME).exists()
    assert local_auth.load_or_create_token(tmp_path)
    assert (tmp_path / local_auth.TOKEN_FILENAME).exists()


def test_an_empty_token_file_is_replaced(tmp_path):
    """A truncated write must not leave the API accepting the empty string."""
    path = tmp_path / local_auth.TOKEN_FILENAME
    path.write_text("")
    token = local_auth.load_or_create_token(tmp_path)
    assert token
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


def test_two_tokens_differ(tmp_path):
    a = local_auth.load_or_create_token(tmp_path / "a")
    b = local_auth.load_or_create_token(tmp_path / "b")
    assert a != b


def test_the_env_var_overrides_the_file(tmp_path, monkeypatch):
    local_auth.load_or_create_token(tmp_path)
    monkeypatch.setenv(local_auth.TOKEN_ENV_VAR, "from-the-environment")
    assert local_auth.load_or_create_token(tmp_path) == "from-the-environment"


def test_a_blank_env_var_falls_back_to_the_file(tmp_path, monkeypatch):
    on_disk = local_auth.load_or_create_token(tmp_path)
    monkeypatch.setenv(local_auth.TOKEN_ENV_VAR, "   ")
    assert local_auth.load_or_create_token(tmp_path) == on_disk


def test_generation_is_reported_only_on_the_start_that_created_it(tmp_path):
    """The CLI prints the file's location once. Printing it every start puts it
    into every scrollback, log capture and screen share for no further benefit."""
    local_auth.load_or_create_token(tmp_path)
    assert local_auth.was_generated_this_process() is True
    local_auth.load_or_create_token(tmp_path)
    assert local_auth.was_generated_this_process() is False


def test_an_env_supplied_token_does_not_report_generation(tmp_path, monkeypatch):
    monkeypatch.setenv(local_auth.TOKEN_ENV_VAR, "from-the-environment")
    local_auth.load_or_create_token(tmp_path)
    assert local_auth.was_generated_this_process() is False
