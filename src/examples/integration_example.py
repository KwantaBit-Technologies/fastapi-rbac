# examples/integration_example.py
from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks
from uuid import uuid4
import uvicorn

from core.database import Database
from services.role_service import RoleService
from services.assignment_service import AssignmentService
from services.permission_service import PermissionService
from integration import (
    LDAPProvider,
    LDAPConfig,
    KeycloakProvider,
    KeycloakConfig,
    IdentitySyncService,
    SyncStrategy,
)

app = FastAPI()

# Initialize services
db = Database("postgresql://user:pass@localhost/rbac")
permission_service = PermissionService(db)
role_service = RoleService(db, permission_service)
assignment_service = AssignmentService(db, role_service, permission_service)

# Configure LDAP provider
ldap_config = LDAPConfig(
    server_uri="ldap://localhost:389",
    base_dn="dc=example,dc=com",
    bind_dn="cn=admin,dc=example,dc=com",
    bind_password="admin_password",
    user_search_base="ou=users,dc=example,dc=com",
    group_search_base="ou=groups,dc=example,dc=com",
)
ldap_provider = LDAPProvider(ldap_config)

# Configure Keycloak provider
keycloak_config = KeycloakConfig(
    server_url="http://localhost:8080",
    realm="myrealm",
    client_id="myclient",
    client_secret="client_secret",
    admin_username="admin",
    admin_password="admin_password",
)
keycloak_provider = KeycloakProvider(keycloak_config)

# Create sync service with LDAP
sync_service = IdentitySyncService(
    provider=ldap_provider,
    role_service=role_service,
    assignment_service=assignment_service,
    strategy=SyncStrategy.INCREMENTAL,
    role_mapping={
        "admin": "Administrator",
        "user": "Regular User",
        "manager": "Manager",
    },
    group_mapping={
        "cn=admins,ou=groups,dc=example,dc=com": "Administrator",
        "cn=users,ou=groups,dc=example,dc=com": "Regular User",
    },
    auto_sync_interval=3600,  # Sync every hour
)


@app.on_event("startup")
async def startup():
    await db.connect()
    await sync_service.start_auto_sync()


@app.on_event("shutdown")
async def shutdown():
    await sync_service.stop_auto_sync()
    await db.disconnect()


# Authentication endpoints
@app.post("/auth/ldap/login")
async def ldap_login(username: str, password: str):
    """Authenticate with LDAP"""
    user = await ldap_provider.authenticate(
        {"username": username, "password": password}
    )

    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Sync user data
    sync_result = await sync_service.sync_user(user.external_id)

    return {
        "message": "Login successful",
        "user": {
            "username": user.username,
            "email": user.email,
            "groups": user.groups,
            "roles": user.roles,
        },
        "sync_result": sync_result,
    }


@app.post("/auth/keycloak/login")
async def keycloak_login(username: str, password: str):
    """Authenticate with Keycloak"""
    user = await keycloak_provider.authenticate(
        {"username": username, "password": password}
    )

    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    return {
        "message": "Login successful",
        "user": {
            "username": user.username,
            "email": user.email,
            "groups": user.groups,
            "roles": user.roles,
        },
    }


# User management endpoints
@app.get("/users/external/{user_id}")
async def get_external_user(user_id: str):
    """Get user from external provider"""
    user = await ldap_provider.get_user(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return user


@app.get("/users/external/by-username/{username}")
async def get_external_user_by_username(username: str):
    """Get user from external provider by username"""
    user = await ldap_provider.get_user_by_username(username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return user


@app.get("/users/external/{user_id}/groups")
async def get_external_user_groups(user_id: str):
    """Get groups for external user"""
    groups = await ldap_provider.get_user_groups(user_id)
    return {"user_id": user_id, "groups": [g.dict() for g in groups]}


# Synchronization endpoints
@app.post("/sync/manual")
async def manual_sync(background_tasks: BackgroundTasks):
    """Trigger manual synchronization"""
    background_tasks.add_task(sync_service.sync_now)
    return {"message": "Sync started in background"}


@app.post("/sync/user/{user_id}")
async def sync_user(user_id: str):
    """Synchronize a specific user"""
    result = await sync_service.sync_user(user_id)
    if not result:
        raise HTTPException(status_code=404, detail="User not found")

    return result


@app.get("/sync/status")
async def sync_status():
    """Get sync status and statistics"""
    return sync_service.get_stats()


# Role mapping management
@app.post("/mappings/role")
async def add_role_mapping(external_role: str, internal_role: str):
    """Add role mapping"""
    sync_service.set_role_mapping(external_role, internal_role)
    return {
        "message": "Role mapping added",
        "external_role": external_role,
        "internal_role": internal_role,
    }


@app.delete("/mappings/role/{external_role}")
async def remove_role_mapping(external_role: str):
    """Remove role mapping"""
    sync_service.remove_role_mapping(external_role)
    return {"message": f"Role mapping removed for {external_role}"}


@app.post("/mappings/group")
async def add_group_mapping(external_group: str, internal_role: str):
    """Add group mapping"""
    sync_service.set_group_mapping(external_group, internal_role)
    return {
        "message": "Group mapping added",
        "external_group": external_group,
        "internal_role": internal_role,
    }


@app.delete("/mappings/group/{external_group}")
async def remove_group_mapping(external_group: str):
    """Remove group mapping"""
    sync_service.remove_group_mapping(external_group)
    return {"message": f"Group mapping removed for {external_group}"}


# Provider configuration endpoints
@app.get("/provider/ldap/test")
async def test_ldap_connection():
    """Test LDAP connection"""
    try:
        user = await ldap_provider.get_user_by_username("testuser")
        return {"status": "connected", "test_user_found": user is not None}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Connection failed: {e}")


@app.get("/provider/keycloak/test")
async def test_keycloak_connection():
    """Test Keycloak connection"""
    try:
        user = await keycloak_provider.get_user_by_username("testuser")
        return {"status": "connected", "test_user_found": user is not None}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Connection failed: {e}")


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
