"""Testes das excecoes customizadas."""
import exceptions
from exceptions import BCAPIError, VendorNotSupportedError, _mask_url


def test_mask_url_hides_basic_auth_credentials():
    masked = _mask_url("https://user:secret@example.com/api")
    assert "secret" not in masked
    assert "***" in masked


def test_mask_url_handles_invalid_url_with_at_sign(monkeypatch):
    def raise_invalid(url):
        raise ValueError("invalid")

    monkeypatch.setattr(exceptions.httpx, "URL", raise_invalid)

    assert _mask_url("not-a-url@token") == "not-a-url***@token"


def test_bc_api_error_includes_status_and_truncated_response():
    err = BCAPIError(
        "Falha",
        "https://user:secret@example.com/api",
        status_code=500,
        response_text="x" * 400,
    )

    text = str(err)
    assert "HTTP 500" in text
    assert "secret" not in text
    assert len(text) < 380


def test_vendor_not_supported_error_message_lists_known_drivers():
    err = VendorNotSupportedError("juniper")

    assert err.vendor == "juniper"
    assert "juniper" in str(err)
    assert "mikrotik" in str(err)
