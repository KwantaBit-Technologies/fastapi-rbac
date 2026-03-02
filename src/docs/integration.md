
### docs/integration.md

```markdown
# External Identity Provider Integration

This guide covers integrating external identity providers like LDAP/Active Directory and Keycloak with your FastAPI RBAC system.

## Overview

The integration layer allows you to:

- **Authenticate users** against external identity providers
- **Synchronize users and groups** automatically
- **Map external groups/roles** to internal RBAC roles
- **Provision/deprovision users** based on external changes
- **Maintain identity** across multiple systems

## Supported Providers

- **LDAP/Active Directory** - For corporate directory integration
- **Keycloak** - For modern identity and access management
- **Extensible** - Easy to add custom providers

## Installation

```bash
# Install with LDAP support
pip install "fastapi-rbac[ldap]"

# Install with Keycloak support
pip install "fastapi-rbac[keycloak]"

# Install both
pip install "fastapi-rbac[ldap,keycloak]"

# Or with uv
uv pip install "fastapi-rbac[all]"

LDAP Integration
Configuration
python
from rbac.integration import LDAPProvider, LDAPConfig

# LDAP Configuration
ldap_config = LDAPConfig(
    # Server connection
    server_uri="ldap://localhost:389",  # or ldaps:// for SSL
    base_dn="dc=example,dc=com",
    bind_dn="cn=admin,dc=example,dc=com",
    bind_password="admin_password",
    
    # Search bases
    user_search_base="ou=users,dc=example,dc=com",
    group_search_base="ou=groups,dc=example,dc=com",
    
    # Object classes
    user_object_class="person",
    group_object_class="group",
    
    # Filters
    user_filter="(objectClass=person)",
    group_filter="(objectClass=group)",
    
    # Attribute mapping
    attributes_map={
        "uid": "uid",           # User ID attribute
        "cn": "cn",              # Common name
        "sn": "sn",              # Surname
        "givenName": "givenName", # First name
        "mail": "mail",          # Email
        "memberOf": "memberOf"   # Group membership
    },
    
    # Connection settings
    use_ssl=True,
    connect_timeout=10
)

# Create provider instance
ldap_provider = LDAPProvider(ldap_config)
Authentication
python
from fastapi import APIRouter, HTTPException

router = APIRouter(prefix="/auth/ldap", tags=["ldap"])

@router.post("/login")
async def ldap_login(username: str, password: str):
    """Authenticate user with LDAP"""
    
    user = await ldap_provider.authenticate({
        "username": username,
        "password": password
    })
    
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Create JWT token
    access_token = create_access_token(
        data={"sub": str(user.external_id)},
        tenant_id=user.tenant_id
    )
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "username": user.username,
            "email": user.email,
            "groups": user.groups
        }
    }

@router.get("/user/{user_id}")
async def get_ldap_user(user_id: str):
    """Get user details from LDAP"""
    user = await ldap_provider.get_user(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

@router.get("/user/by-username/{username}")
async def get_ldap_user_by_username(username: str):
    """Get user by username from LDAP"""
    user = await ldap_provider.get_user_by_username(username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

@router.get("/user/{user_id}/groups")
async def get_user_groups(user_id: str):
    """Get groups for a user from LDAP"""
    groups = await ldap_provider.get_user_groups(user_id)
    return {"user_id": user_id, "groups": [g.dict() for g in groups]}
Keycloak Integration
Configuration
python
from rbac.integration import KeycloakProvider, KeycloakConfig

# Keycloak Configuration
keycloak_config = KeycloakConfig(
    # Server connection
    server_url="http://localhost:8080",
    realm="myrealm",
    
    # Client credentials
    client_id="myclient",
    client_secret="client-secret",
    
    # Admin credentials (optional, for admin operations)
    admin_username="admin",
    admin_password="admin",
    
    # Connection settings
    verify_ssl=True,
    timeout=30
)

# Create provider instance
keycloak_provider = KeycloakProvider(keycloak_config)
Authentication
python
@router.post("/auth/keycloak/login")
async def keycloak_login(username: str, password: str):
    """Authenticate user with Keycloak"""
    
    user = await keycloak_provider.authenticate({
        "username": username,
        "password": password
    })
    
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Get user roles and groups
    groups = await keycloak_provider.get_user_groups(user.external_id)
    
    # Create JWT token
    access_token = create_access_token(
        data={"sub": str(user.external_id)},
        tenant_id=user.tenant_id
    )
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "username": user.username,
            "email": user.email,
            "groups": [g.name for g in groups],
            "roles": user.roles
        }
    }
Identity Synchronization Service
The IdentitySyncService provides automatic synchronization between external providers and your local RBAC system.

Basic Setup
python
from rbac.integration import IdentitySyncService, SyncStrategy, SyncDirection

# Create sync service
sync_service = IdentitySyncService(
    provider=ldap_provider,  # or keycloak_provider
    role_service=role_service,
    assignment_service=assignment_service,
    
    # Role/Group mappings
    role_mapping={
        "admin": "Administrator",        # External role -> internal role
        "user": "Regular User",
        "manager": "Manager"
    },
    group_mapping={
        "cn=admins,ou=groups,dc=example,dc=com": "Administrator",
        "cn=users,ou=groups,dc=example,dc=com": "Regular User",
        "cn=managers,ou=groups,dc=example,dc=com": "Manager"
    },
    
    # Sync configuration
    strategy=SyncStrategy.INCREMENTAL,  # or FULL
    direction=SyncDirection.IMPORT,     # or EXPORT, BIDIRECTIONAL
    conflict_resolution=SyncConflictResolution.EXTERNAL_WINS,
    auto_sync_interval=3600  # Auto-sync every hour
)

# Start auto-sync on startup
@app.on_event("startup")
async def startup():
    await db.connect()
    await redis_cache.initialize()
    await sync_service.start_auto_sync()

# Stop auto-sync on shutdown
@app.on_event("shutdown")
async def shutdown():
    await sync_service.stop_auto_sync()
    await redis_cache.close()
    await db.disconnect()
Manual Sync Operations
python
@router.post("/sync/manual")
async def manual_sync(background_tasks: BackgroundTasks):
    """Trigger manual synchronization"""
    background_tasks.add_task(sync_service.sync_now)
    return {"message": "Sync started in background"}

@router.post("/sync/user/{user_id}")
async def sync_user(user_id: str):
    """Synchronize a specific user"""
    result = await sync_service.sync_user(user_id)
    if not result:
        raise HTTPException(status_code=404, detail="User not found")
    return result

@router.get("/sync/status")
async def sync_status():
    """Get sync status and statistics"""
    return sync_service.get_stats()
Role and Group Mapping
python
@router.post("/mappings/role")
async def add_role_mapping(external_role: str, internal_role: str):
    """Add mapping from external role to internal role"""
    sync_service.set_role_mapping(external_role, internal_role)
    return {
        "message": "Role mapping added",
        "external_role": external_role,
        "internal_role": internal_role
    }

@router.delete("/mappings/role/{external_role}")
async def remove_role_mapping(external_role: str):
    """Remove role mapping"""
    sync_service.remove_role_mapping(external_role)
    return {"message": f"Role mapping removed for {external_role}"}

@router.post("/mappings/group")
async def add_group_mapping(external_group: str, internal_role: str):
    """Add mapping from external group to internal role"""
    sync_service.set_group_mapping(external_group, internal_role)
    return {
        "message": "Group mapping added",
        "external_group": external_group,
        "internal_role": internal_role
    }

@router.get("/mappings")
async def list_mappings():
    """List all role and group mappings"""
    return {
        "role_mappings": sync_service.role_mapping,
        "group_mappings": sync_service.group_mapping
    }
Custom Hooks
You can add custom hooks to control the synchronization process:

python
from rbac.integration import IdentityProviderHook

class CustomSyncHook(IdentityProviderHook):
    """Custom hooks for synchronization"""
    
    async def before_user_create(self, user: ExternalUser) -> ExternalUser:
        """Modify user data before creation"""
        # Add custom attributes
        user.attributes["source"] = "ldap"
        user.attributes["sync_timestamp"] = datetime.utcnow().isoformat()
        
        # Set tenant based on domain
        if user.email and user.email.endswith("@acme.com"):
            user.tenant_id = "tenant-acme"
        elif user.email and user.email.endswith("@example.com"):
            user.tenant_id = "tenant-example"
        
        return user
    
    async def after_user_create(self, user: ExternalUser, local_user_id: UUID):
        """Send notification after user creation"""
        await send_welcome_email(user.email)
        await audit_service.log_action(
            user_id=local_user_id,
            action="USER_CREATED",
            resource_type="user",
            metadata={"source": "ldap_sync"}
        )
    
    async def before_role_assign(self, user_id: UUID, role_name: str) -> bool:
        """Validate before assigning role"""
        # Don't assign admin role to external users
        if role_name == "Administrator":
            # Check if user is actually an admin in external system
            external_user = await ldap_provider.get_user(str(user_id))
            return "admin" in external_user.roles
        return True

# Use custom hook
sync_service = IdentitySyncService(
    provider=ldap_provider,
    role_service=role_service,
    assignment_service=assignment_service,
    hook=CustomSyncHook(),
    role_mapping=role_mapping
)
Advanced Sync Strategies
Full Sync
python
# Sync all users from external system
sync_service = IdentitySyncService(
    strategy=SyncStrategy.FULL,
    auto_sync_interval=86400  # Daily full sync
)

# Manual full sync
await sync_service.sync_now()  # Syncs all users
Incremental Sync
python
# Only sync changed users
sync_service = IdentitySyncService(
    strategy=SyncStrategy.INCREMENTAL,
    auto_sync_interval=3600  # Hourly incremental sync
)

# Syncs only users changed since last sync
await sync_service.sync_now()
Bidirectional Sync
python
# Sync in both directions
sync_service = IdentitySyncService(
    provider=ldap_provider,
    direction=SyncDirection.BIDIRECTIONAL,
    conflict_resolution=SyncConflictResolution.LATEST_WINS
)
Conflict Resolution
python
from rbac.integration import SyncConflictResolution

# External changes take precedence
sync_service = IdentitySyncService(
    conflict_resolution=SyncConflictResolution.EXTERNAL_WINS
)

# Local changes take precedence
sync_service = IdentitySyncService(
    conflict_resolution=SyncConflictResolution.LOCAL_WINS
)

# Latest timestamp wins
sync_service = IdentitySyncService(
    conflict_resolution=SyncConflictResolution.LATEST_WINS
)

# Manual resolution (requires intervention)
sync_service = IdentitySyncService(
    conflict_resolution=SyncConflictResolution.MANUAL
)
Error Handling and Retries
python
class ResilientSyncService(IdentitySyncService):
    """Sync service with retry logic"""
    
    async def sync_user(self, user_id: str, max_retries: int = 3):
        for attempt in range(max_retries):
            try:
                return await super().sync_user(user_id)
            except Exception as e:
                if attempt == max_retries - 1:
                    raise
                wait_time = 2 ** attempt  # Exponential backoff
                logger.warning(f"Sync failed (attempt {attempt+1}), retrying in {wait_time}s")
                await asyncio.sleep(wait_time)
        
        # Log to dead letter queue
        await self._log_to_dlq(user_id, str(e))
        return None
Monitoring and Alerts
python
@router.get("/sync/health")
async def sync_health():
    """Check sync service health"""
    stats = sync_service.get_stats()
    
    # Check for issues
    issues = []
    if stats.get("errors", 0) > 10:
        issues.append("High error rate")
    
    if stats.get("last_sync") and (
        datetime.utcnow() - stats["last_sync"]
    ).total_seconds() > sync_service.auto_sync_interval * 2:
        issues.append("Sync stalled")
    
    return {
        "status": "healthy" if not issues else "degraded",
        "issues": issues,
        "stats": stats
    }

# Set up alerts (example with Prometheus)
from prometheus_client import Counter, Gauge

sync_errors = Counter('rbac_sync_errors_total', 'Total sync errors')
last_sync_time = Gauge('rbac_last_sync_timestamp', 'Last sync timestamp')

@app.on_event("startup")
async def setup_metrics():
    async def update_metrics():
        while True:
            stats = sync_service.get_stats()
            last_sync_time.set(stats.get("last_sync", 0))
            await asyncio.sleep(60)
    
    asyncio.create_task(update_metrics())
Complete Integration Example
python
from fastapi import FastAPI, Depends, BackgroundTasks
from contextlib import asynccontextmanager
import uvicorn

from rbac.core.database import Database
from rbac.services import PermissionService, RoleService, AssignmentService
from rbac.integration import (
    LDAPProvider, LDAPConfig,
    KeycloakProvider, KeycloakConfig,
    IdentitySyncService, SyncStrategy,
    IdentityProviderHook
)
from rbac.dependencies.auth import RBACDependencies, require_roles

# Initialize services
db = Database("postgresql://user:pass@localhost/rbac")
permission_service = PermissionService(db)
role_service = RoleService(db, permission_service)
assignment_service = AssignmentService(db, role_service, permission_service)

# Configure LDAP
ldap_config = LDAPConfig(
    server_uri="ldap://localhost:389",
    base_dn="dc=example,dc=com",
    bind_dn="cn=admin,dc=example,dc=com",
    bind_password="admin"
)
ldap_provider = LDAPProvider(ldap_config)

# Configure Keycloak (optional)
keycloak_config = KeycloakConfig(
    server_url="http://localhost:8080",
    realm="myrealm",
    client_id="myclient",
    client_secret="secret"
)
keycloak_provider = KeycloakProvider(keycloak_config)

# Role mappings
role_mapping = {
    "admin": "Administrator",
    "user": "Regular User",
    "manager": "Manager"
}

group_mapping = {
    "cn=admins,ou=groups,dc=example,dc=com": "Administrator",
    "cn=users,ou=groups,dc=example,dc=com": "Regular User"
}

# Create sync service
sync_service = IdentitySyncService(
    provider=ldap_provider,  # Use LDAP as primary
    role_service=role_service,
    assignment_service=assignment_service,
    role_mapping=role_mapping,
    group_mapping=group_mapping,
    strategy=SyncStrategy.INCREMENTAL,
    auto_sync_interval=3600  # Sync every hour
)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    await db.connect()
    await role_service.initialize_default_roles()
    await sync_service.start_auto_sync()
    yield
    # Shutdown
    await sync_service.stop_auto_sync()
    await db.disconnect()

app = FastAPI(lifespan=lifespan)

# RBAC dependencies
rbac = RBACDependencies(
    permission_service=permission_service,
    assignment_service=assignment_service,
    secret_key="your-secret-key"
)

# Authentication endpoints
@app.post("/auth/ldap/login")
async def ldap_login(username: str, password: str):
    user = await ldap_provider.authenticate({"username": username, "password": password})
    if not user:
        raise HTTPException(401, "Invalid credentials")
    
    # Sync user
    await sync_service.sync_user(user.external_id)
    
    return {"message": "Login successful", "user": user}

@app.post("/auth/keycloak/login")
async def keycloak_login(username: str, password: str):
    user = await keycloak_provider.authenticate({"username": username, "password": password})
    if not user:
        raise HTTPException(401, "Invalid credentials")
    
    return {"message": "Login successful", "user": user}

# Sync management (admin only)
@app.post("/admin/sync/manual")
@require_roles(["admin"])
async def manual_sync(background_tasks: BackgroundTasks):
    background_tasks.add_task(sync_service.sync_now)
    return {"message": "Sync started"}

@app.post("/admin/sync/user/{user_id}")
@require_roles(["admin"])
async def sync_specific_user(user_id: str):
    result = await sync_service.sync_user(user_id)
    if not result:
        raise HTTPException(404, "User not found")
    return result

@app.get("/admin/sync/status")
@require_roles(["admin"])
async def sync_status():
    return sync_service.get_stats()

@app.post("/admin/mappings/role")
@require_roles(["admin"])
async def add_role_mapping(external_role: str, internal_role: str):
    sync_service.set_role_mapping(external_role, internal_role)
    return {"message": "Role mapping added"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
Best Practices
Use secure connections - Always use LDAPS or SSL/TLS

Implement retry logic - Handle transient failures

Monitor sync health - Set up alerts for failures

Start with incremental sync - Test before full sync

Map groups, not individual users - Scale better

Handle deprovisioning - Deactivate users when removed

Log everything - Audit all sync operations

Test conflict resolution - Ensure predictable behavior

Rate limit syncs - Don't overwhelm external systems

Have fallback auth - Maintain local auth for emergencies

With these integration patterns, you can seamlessly connect your RBAC system to existing identity infrastructure!