from services.mesh.mesh_fleet_defaults import (
    FLEET_PEER_PUSH_SECRET,
    effective_bootstrap_signer_public_key_b64,
    effective_peer_push_secret,
    infonet_fleet_join_enabled,
)


def test_fleet_defaults_apply_when_join_enabled(monkeypatch):
    from services.config import get_settings

    monkeypatch.delenv("MESH_BOOTSTRAP_SIGNER_PUBLIC_KEY", raising=False)
    monkeypatch.delenv("MESH_PEER_PUSH_SECRET", raising=False)
    monkeypatch.setenv("MESH_INFONET_FLEET_JOIN", "true")
    get_settings.cache_clear()
    try:
        assert infonet_fleet_join_enabled() is True
        assert effective_bootstrap_signer_public_key_b64()
        assert effective_peer_push_secret() == FLEET_PEER_PUSH_SECRET
    finally:
        get_settings.cache_clear()


def test_fleet_defaults_disabled(monkeypatch):
    from services.config import get_settings

    monkeypatch.setenv("MESH_BOOTSTRAP_SIGNER_PUBLIC_KEY", "")
    monkeypatch.setenv("MESH_PEER_PUSH_SECRET", "")
    monkeypatch.setenv("MESH_INFONET_FLEET_JOIN_DISABLED", "true")
    get_settings.cache_clear()
    try:
        assert infonet_fleet_join_enabled() is False
        assert effective_peer_push_secret() == ""
    finally:
        get_settings.cache_clear()
