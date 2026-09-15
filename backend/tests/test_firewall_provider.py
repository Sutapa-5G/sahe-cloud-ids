import pytest

from backend.app.firewall.provider import (
    SimulatedFirewallProvider,
    IptablesFirewallProvider,
    get_firewall_provider,
)


def test_get_firewall_provider_defaults_to_simulated():
    provider = get_firewall_provider("simulated")
    assert isinstance(provider, SimulatedFirewallProvider)


def test_get_firewall_provider_unknown_mode_defaults_to_simulated():
    """Fails safe: an unrecognized mode string should not accidentally
    activate the real iptables provider."""
    provider = get_firewall_provider("something-unexpected")
    assert isinstance(provider, SimulatedFirewallProvider)


def test_get_firewall_provider_explicit_iptables():
    provider = get_firewall_provider("iptables")
    assert isinstance(provider, IptablesFirewallProvider)


def test_simulated_block_unblock():
    provider = SimulatedFirewallProvider()
    result = provider.block("10.0.0.1", "test reason")
    assert result.success is True
    assert result.mode == "simulated"

    rules = provider.list_rules()
    assert len(rules) == 1
    assert rules[0]["ip"] == "10.0.0.1"

    result2 = provider.unblock("10.0.0.1")
    assert result2.success is True
    assert provider.list_rules() == []


def test_simulated_invalid_ip_raises():
    provider = SimulatedFirewallProvider()
    with pytest.raises(ValueError):
        provider.block("not-an-ip", "test")


def test_simulated_duplicate_block_no_error():
    provider = SimulatedFirewallProvider()
    provider.block("10.0.0.1", "first reason")
    result = provider.block("10.0.0.1", "second reason")
    assert result.success is True
    assert "already blocked" in result.message


def test_simulated_unblock_nonexistent_ip_no_error():
    provider = SimulatedFirewallProvider()
    result = provider.unblock("10.0.0.99")
    assert result.success is True
    assert "not currently blocked" in result.message


def test_iptables_provider_fails_safely_without_privileges():
    """
    In this sandboxed environment, the process does not have privileges
    to run real iptables commands. This test verifies the provider fails
    SAFELY (success=False with an error message) rather than raising an
    uncaught exception or crashing.
    """
    provider = IptablesFirewallProvider()
    result = provider.block("10.0.0.1", "test")
    # Either it succeeds (if iptables happens to be available and
    # permitted) or it fails safely — either way, no exception propagates
    # and `result` is a well-formed FirewallActionResult.
    assert result.ip == "10.0.0.1"
    assert result.mode == "iptables"
    assert isinstance(result.success, bool)
    if not result.success:
        assert "Failed to apply iptables rule" in result.message
