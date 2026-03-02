# tests/test_integration.py
import pytest
from unittest.mock import AsyncMock, Mock
from uuid import uuid4

from rbac.integration import (
    LDAPProvider,
    LDAPConfig,
    KeycloakProvider,
    KeycloakConfig,
    IdentitySyncService,
    ExternalUser,
)

pytestmark = pytest.mark.asyncio


class TestLDAPIntegration:

    async def test_ldap_config(self):
        """Test LDAP configuration"""
        config = LDAPConfig(
            server_uri="ldap://localhost:389",
            base_dn="dc=example,dc=com",
            bind_dn="cn=admin,dc=example,dc=com",
            bind_password="secret",
        )

        assert config.server_uri == "ldap://localhost:389"
        assert config.base_dn == "dc=example,dc=com"

    async def test_ldap_provider_initialization(self):
        """Test LDAP provider initialization"""
        config = LDAPConfig(
            server_uri="ldap://localhost:389",
            base_dn="dc=example,dc=com",
            bind_dn="cn=admin,dc=example,dc=com",
            bind_password="secret",
        )

        provider = LDAPProvider(config)
        assert provider.config == config


class TestKeycloakIntegration:

    async def test_keycloak_config(self):
        """Test Keycloak configuration"""
        config = KeycloakConfig(
            server_url="http://localhost:8080",
            realm="master",
            client_id="admin-cli",
            client_secret="secret",
        )

        assert config.server_url == "http://localhost:8080"
        assert config.realm == "master"

    async def test_keycloak_provider_initialization(self):
        """Test Keycloak provider initialization"""
        config = KeycloakConfig(
            server_url="http://localhost:8080",
            realm="master",
            client_id="admin-cli",
            client_secret="secret",
        )

        provider = KeycloakProvider(config)
        assert provider.config == config


class TestSyncService:

    async def test_sync_service_initialization(self, role_service, assignment_service):
        """Test sync service initialization"""
        mock_provider = AsyncMock()

        sync_service = IdentitySyncService(
            provider=mock_provider,
            role_service=role_service,
            assignment_service=assignment_service,
            role_mapping={"admin": "Administrator"},
            auto_sync_interval=3600,
        )

        assert sync_service.role_mapping == {"admin": "Administrator"}
        assert sync_service.auto_sync_interval == 3600

    async def test_set_role_mapping(self, role_service, assignment_service):
        """Test setting role mapping"""
        mock_provider = AsyncMock()

        sync_service = IdentitySyncService(
            provider=mock_provider,
            role_service=role_service,
            assignment_service=assignment_service,
        )

        sync_service.set_role_mapping("external_role", "internal_role")
        assert sync_service.role_mapping["external_role"] == "internal_role"

    async def test_get_stats(self, role_service, assignment_service):
        """Test getting sync statistics"""
        mock_provider = AsyncMock()

        sync_service = IdentitySyncService(
            provider=mock_provider,
            role_service=role_service,
            assignment_service=assignment_service,
        )

        stats = sync_service.get_stats()
        assert "total_syncs" in stats
        assert "users_created" in stats
        assert "users_updated" in stats
