# rbac/integration/__init__.py
from .base import ExternalGroup, ExternalUser, IdentityProvider, IdentityProviderHook
from .sync_service import (
    IdentitySyncService,
    SyncConflictResolution,
    SyncDirection,
    SyncStrategy,
)


def __getattr__(name):
    if name in {"LDAPProvider", "LDAPConfig"}:
        try:
            from .ldap_provider import LDAPConfig, LDAPProvider
        except ImportError as exc:
            raise ImportError("Install kb-fastapi-rbac[ldap] to use LDAP integration") from exc
        return {"LDAPProvider": LDAPProvider, "LDAPConfig": LDAPConfig}[name]

    if name in {"KeycloakProvider", "KeycloakConfig"}:
        try:
            from .keycloak_provider import KeycloakConfig, KeycloakProvider
        except ImportError as exc:
            raise ImportError(
                "Install kb-fastapi-rbac[keycloak] to use Keycloak integration"
            ) from exc
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
