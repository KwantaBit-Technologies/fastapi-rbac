# rbac/integration/__init__.py
from .base import IdentityProvider, ExternalUser, ExternalGroup, IdentityProviderHook
from .sync_service import (
    IdentitySyncService,
    SyncStrategy,
    SyncDirection,
    SyncConflictResolution,
)


def __getattr__(name):
    if name in {"LDAPProvider", "LDAPConfig"}:
        try:
            from .ldap_provider import LDAPProvider, LDAPConfig
        except ImportError as exc:
            raise ImportError("Install fastapi-rbac[ldap] to use LDAP integration") from exc
        return {"LDAPProvider": LDAPProvider, "LDAPConfig": LDAPConfig}[name]

    if name in {"KeycloakProvider", "KeycloakConfig"}:
        try:
            from .keycloak_provider import KeycloakProvider, KeycloakConfig
        except ImportError as exc:
            raise ImportError("Install fastapi-rbac[keycloak] to use Keycloak integration") from exc
        return {"KeycloakProvider": KeycloakProvider, "KeycloakConfig": KeycloakConfig}[name]

    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

__all__ = [
    "IdentityProvider",
    "ExternalUser",
    "ExternalGroup",
    "IdentityProviderHook",
    "LDAPProvider",
    "LDAPConfig",
    "KeycloakProvider",
    "KeycloakConfig",
    "IdentitySyncService",
    "SyncStrategy",
    "SyncDirection",
    "SyncConflictResolution",
]
