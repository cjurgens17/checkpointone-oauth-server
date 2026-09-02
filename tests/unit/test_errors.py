"""Tests for utility.errors."""

from utility.errors import SessionUserNotFoundError


class TestSessionUserNotFoundError:
    def test_names_the_session_when_one_is_given(self):
        error = SessionUserNotFoundError("abc123")
        assert "abc123" in str(error)
        assert error.session_id == "abc123"

    def test_falls_back_to_a_generic_message(self):
        error = SessionUserNotFoundError()
        assert "no matching user" in str(error)
        assert error.session_id is None

    def test_is_raisable_and_catchable(self):
        import pytest

        with pytest.raises(SessionUserNotFoundError):
            raise SessionUserNotFoundError("abc123")

    def test_is_an_exception(self):
        assert issubclass(SessionUserNotFoundError, Exception)
