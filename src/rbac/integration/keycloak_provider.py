# rbac/integration/keycloak_provider.py
from typing import Optional, List, Dict, Any, Tuple
from datetime import datetime, timezone
import httpx
import jwt
from jwt.algorithms import RSAAlgorithm
from utils.logger import setup_logger


from .base import IdentityProvider, ExternalUser, ExternalGroup

logger = setup_logger("keycloak_provider")


class KeycloakConfig:
    """Keycloak connection configuration"""

    def __init__(
        self,
        server_url: str,
        realm: str,
        client_id: str,
        client_secret: str,
        admin_username: Optional[str] = None,
        admin_password: Optional[str] = None,
        verify_ssl: bool = True,
        timeout: int = 30,
    ):
        self.server_url = server_url.rstrip("/")
        self.realm = realm
        self.client_id = client_id
        self.client_secret = client_secret
        self.admin_username = admin_username
        self.admin_password = admin_password
        self.verify_ssl = verify_ssl
        self.timeout = timeout


class KeycloakProvider(IdentityProvider):
    """Keycloak identity provider implementation"""

    def __init__(self, config: KeycloakConfig):
        self.config = config
        self._access_token = None
        self._token_expiry = None
        self._public_keys = None
        self._http_client = httpx.AsyncClient(
            verify=config.verify_ssl, timeout=config.timeout
        )

    async def authenticate(self, credentials: Dict[str, Any]) -> Optional[ExternalUser]:
        """Authenticate user with Keycloak"""
        username = credentials.get("username")
        password = credentials.get("password")

        if not username or not password:
            return None

        try:
            token_url = f"{self.config.server_url}/realms/{self.config.realm}/protocol/openid-connect/token"

            data = {
                "client_id": self.config.client_id,
                "client_secret": self.config.client_secret,
                "grant_type": "password",
                "username": username,
                "password": password,
            }

            response = await self._http_client.post(token_url, data=data)

            if response.status_code == 200:
                token_data = response.json()
                access_token = token_data.get("access_token")

                # Decode token to get user info
                user_info = await self._decode_token(access_token)
                if user_info:
                    return await self.get_user(user_info.get("sub"))

            return None

        except Exception as e:
            logger.error(f"Keycloak authentication error: {e}")
            return None

    async def get_user(self, user_id: str) -> Optional[ExternalUser]:
        """Get user by ID from Keycloak"""
        try:
            token = await self._get_admin_token()

            url = f"{self.config.server_url}/admin/realms/{self.config.realm}/users/{user_id}"

            response = await self._http_client.get(
                url, headers={"Authorization": f"Bearer {token}"}
            )

            if response.status_code == 200:
                user_data = response.json()
                return await self._keycloak_to_external_user(user_data)

            return None

        except Exception as e:
            logger.error(f"Error getting Keycloak user: {e}")
            return None

    async def get_user_by_username(self, username: str) -> Optional[ExternalUser]:
        """Get user by username from Keycloak"""
        try:
            token = await self._get_admin_token()

            url = f"{self.config.server_url}/admin/realms/{self.config.realm}/users"
            params = {"username": username, "exact": "true"}

            response = await self._http_client.get(
                url, headers={"Authorization": f"Bearer {token}"}, params=params
            )

            if response.status_code == 200:
                users = response.json()
                if users:
                    return await self._keycloak_to_external_user(users[0])

            return None

        except Exception as e:
            logger.error(f"Error getting Keycloak user by username: {e}")
            return None

    async def get_user_groups(self, user_id: str) -> List[ExternalGroup]:
        """Get groups for a user from Keycloak"""
        try:
            token = await self._get_admin_token()

            url = f"{self.config.server_url}/admin/realms/{self.config.realm}/users/{user_id}/groups"

            response = await self._http_client.get(
                url, headers={"Authorization": f"Bearer {token}"}
            )

            if response.status_code == 200:
                groups_data = response.json()
                return [self._keycloak_to_external_group(g) for g in groups_data]

            return []

        except Exception as e:
            logger.error(f"Error getting Keycloak user groups: {e}")
            return []

    async def sync_users(self, last_sync: Optional[datetime] = None) -> Tuple[int, int]:
        """Sync users from Keycloak"""
        created = 0
        updated = 0

        try:
            token = await self._get_admin_token()

            # Build query
            url = f"{self.config.server_url}/admin/realms/{self.config.realm}/users"
            params = {"max": 1000}

            if last_sync:
                # Keycloak uses 'lastName' or you might need to track this separately
                params["lastName"] = last_sync.strftime("%Y-%m-%d")

            response = await self._http_client.get(
                url, headers={"Authorization": f"Bearer {token}"}, params=params
            )

            if response.status_code == 200:
                users_data = response.json()

                for user_data in users_data:
                    user = await self._keycloak_to_external_user(user_data)

                    # Here you would integrate with your user service
                    # to create or update users in your local database

                    # For counting:
                    # if exists: updated += 1 else: created += 1
                    pass

            return created, updated

        except Exception as e:
            logger.error(f"Error syncing Keycloak users: {e}")
            return created, updated

    async def _get_admin_token(self) -> str:
        """Get admin access token for Keycloak API"""
        if (
            self._access_token
            and self._token_expiry
            and datetime.now(timezone.utc) < self._token_expiry
        ):
            return self._access_token

        token_url = f"{self.config.server_url}/realms/{self.config.realm}/protocol/openid-connect/token"

        data = {
            "client_id": self.config.client_id,
            "client_secret": self.config.client_secret,
            "grant_type": "client_credentials",
        }

        if self.config.admin_username and self.config.admin_password:
            data = {
                "client_id": self.config.client_id,
                "grant_type": "password",
                "username": self.config.admin_username,
                "password": self.config.admin_password,
            }

        response = await self._http_client.post(token_url, data=data)

        if response.status_code == 200:
            token_data = response.json()
            self._access_token = token_data.get("access_token")
            expires_in = token_data.get("expires_in", 300)
            self._token_expiry = datetime.now(timezone.utc).timestamp() + expires_in
            return self._access_token

        raise Exception(f"Failed to get admin token: {response.text}")

    async def _get_public_keys(self) -> Dict:
        """Get public keys for token verification"""
        if self._public_keys:
            return self._public_keys

        certs_url = f"{self.config.server_url}/realms/{self.config.realm}/protocol/openid-connect/certs"

        response = await self._http_client.get(certs_url)

        if response.status_code == 200:
            self._public_keys = response.json()
            return self._public_keys

        raise Exception("Failed to get public keys")

    async def _decode_token(self, token: str) -> Optional[Dict]:
        """Decode and verify JWT token"""
        try:
            # Get public keys
            public_keys = await self._get_public_keys()

            # Get key ID from token header
            unverified_header = jwt.get_unverified_header(token)
            kid = unverified_header.get("kid")

            # Find matching public key
            key_data = None
            for key in public_keys.get("keys", []):
                if key.get("kid") == kid:
                    key_data = key
                    break

            if not key_data:
                raise Exception("No matching public key found")

            # Construct public key
            public_key = RSAAlgorithm.from_jwk(key_data)

            # Decode and verify token
            payload = jwt.decode(
                token,
                public_key,
                algorithms=["RS256"],
                audience=self.config.client_id,
                options={"verify_exp": True},
            )

            return payload

        except Exception as e:
            logger.error(f"Token decode error: {e}")
            return None

    async def _keycloak_to_external_user(self, user_data: Dict) -> ExternalUser:
        """Convert Keycloak user data to ExternalUser"""

        # Get user groups
        groups = await self.get_user_groups(user_data.get("id"))

        # Get user roles (from realm and client)
        token = await self._get_admin_token()

        # Get realm roles
        roles_url = f"{self.config.server_url}/admin/realms/{self.config.realm}/users/{user_data.get('id')}/role-mappings/realm"
        roles_response = await self._http_client.get(
            roles_url, headers={"Authorization": f"Bearer {token}"}
        )

        roles = []
        if roles_response.status_code == 200:
            roles_data = roles_response.json()
            roles = [r.get("name") for r in roles_data]

        return ExternalUser(
            external_id=user_data.get("id"),
            username=user_data.get("username"),
            email=user_data.get("email"),
            first_name=user_data.get("firstName"),
            last_name=user_data.get("lastName"),
            full_name=f"{user_data.get('firstName', '')} {user_data.get('lastName', '')}".strip(),
            groups=[g.name for g in groups],
            roles=roles,
            attributes=user_data.get("attributes", {}),
            is_active=user_data.get("enabled", True),
            metadata={
                "created_timestamp": user_data.get("createdTimestamp"),
                "email_verified": user_data.get("emailVerified"),
            },
        )

    def _keycloak_to_external_group(self, group_data: Dict) -> ExternalGroup:
        """Convert Keycloak group data to ExternalGroup"""
        return ExternalGroup(
            external_id=group_data.get("id"),
            name=group_data.get("name"),
            description=group_data.get("path"),
            attributes=group_data.get("attributes", {}),
            parent_id=group_data.get("parentId"),
        )

    async def close(self):
        """Close HTTP client"""
        await self._http_client.aclose()
