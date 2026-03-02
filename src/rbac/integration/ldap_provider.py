# rbac/integration/ldap_provider.py
from typing import Optional, List, Dict, Any, Tuple
from datetime import datetime
import ldap3
from ldap3 import Server, Connection, ALL, SUBTREE
import hashlib
import base64

from .base import IdentityProvider, ExternalUser, ExternalGroup
from utils.logger import setup_logger

logger = setup_logger("ldap_provider")


class LDAPConfig:
    """LDAP connection configuration"""

    def __init__(
        self,
        server_uri: str,
        base_dn: str,
        bind_dn: str,
        bind_password: str,
        user_search_base: Optional[str] = None,
        group_search_base: Optional[str] = None,
        user_object_class: str = "person",
        group_object_class: str = "group",
        user_filter: str = "(objectClass=person)",
        group_filter: str = "(objectClass=group)",
        attributes_map: Dict[str, str] = None,
        use_ssl: bool = True,
        connect_timeout: int = 10,
    ):
        self.server_uri = server_uri
        self.base_dn = base_dn
        self.bind_dn = bind_dn
        self.bind_password = bind_password
        self.user_search_base = user_search_base or base_dn
        self.group_search_base = group_search_base or base_dn
        self.user_object_class = user_object_class
        self.group_object_class = group_object_class
        self.user_filter = user_filter
        self.group_filter = group_filter
        self.attributes_map = attributes_map or {
            "uid": "uid",
            "cn": "cn",
            "sn": "sn",
            "givenName": "givenName",
            "mail": "mail",
            "memberOf": "memberOf",
        }
        self.use_ssl = use_ssl
        self.connect_timeout = connect_timeout


class LDAPProvider(IdentityProvider):
    """LDAP identity provider implementation"""

    def __init__(self, config: LDAPConfig):
        self.config = config
        self._connection_pool: list = []
        self._server = Server(
            config.server_uri,
            use_ssl=config.use_ssl,
            connect_timeout=config.connect_timeout,
            get_info=ALL,
        )

    async def authenticate(self, credentials: Dict[str, Any]) -> Optional[ExternalUser]:
        """Authenticate user with LDAP"""
        username = credentials.get("username")
        password = credentials.get("password")

        if not username or not password:
            return None

        try:
            # First, find the user's DN
            conn = self._get_connection()
            user_dn = await self._find_user_dn(conn, username)

            if not user_dn:
                logger.warning(f"User not found in LDAP: {username}")
                return None

            # Try to bind with user's credentials
            user_conn = Connection(
                self._server, user=user_dn, password=password, auto_bind=True
            )

            # If successful, get user details
            user = await self._get_user_from_dn(user_dn)
            user_conn.unbind()

            return user

        except Exception as e:
            logger.error(f"LDAP authentication error: {e}")
            return None

    async def get_user(self, user_id: str) -> Optional[ExternalUser]:
        """Get user by ID (uid)"""
        conn = self._get_connection()

        search_filter = f"(&{self.config.user_filter}(uid={user_id}))"

        conn.search(
            search_base=self.config.user_search_base,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=list(self.config.attributes_map.values()),
        )

        if conn.entries:
            return self._ldap_to_external_user(conn.entries[0])

        return None

    async def get_user_by_username(self, username: str) -> Optional[ExternalUser]:
        """Get user by username"""
        return await self.get_user(username)

    async def get_user_groups(self, user_id: str) -> List[ExternalGroup]:
        """Get groups for a user"""
        conn = self._get_connection()
        groups: list = []

        # Find user first
        user = await self.get_user(user_id)
        if not user:
            return groups

        # Search for groups that have this user as member
        search_filter = f"(&{self.config.group_filter}(member={user.external_id}))"

        conn.search(
            search_base=self.config.group_search_base,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=["cn", "description", "member"],
        )

        for entry in conn.entries:
            groups.append(self._ldap_to_external_group(entry))

        return groups

    async def sync_users(self, last_sync: Optional[datetime] = None) -> Tuple[int, int]:
        """Sync users from LDAP"""
        conn = self._get_connection()
        created = 0
        updated = 0

        # Build sync filter
        sync_filter = self.config.user_filter
        if last_sync:
            # LDAP doesn't have standard modification timestamps
            # might need to use 'modifyTimestamp' or similar
            sync_filter = f"(&{sync_filter}(modifyTimestamp>={last_sync.strftime('%Y%m%d%H%M%SZ')}))"

        conn.search(
            search_base=self.config.user_search_base,
            search_filter=sync_filter,
            search_scope=SUBTREE,
            attributes=list(self.config.attributes_map.values()),
        )

        for entry in conn.entries:
            user = self._ldap_to_external_user(entry)

            # Here you would integrate with your user service
            # to create or update users in your local database

            # For now, just count
            # if user exists: updated += 1 else: created += 1
            pass

        return created, updated

    def _get_connection(self) -> Connection:
        """Get LDAP connection from pool or create new"""
        try:
            # Try to get from pool
            if self._connection_pool:
                conn = self._connection_pool.pop()
                if conn.bound:
                    return conn

            # Create new connection
            conn = Connection(
                self._server,
                user=self.config.bind_dn,
                password=self.config.bind_password,
                auto_bind=True,
            )
            return conn

        except Exception as e:
            logger.error(f"Failed to create LDAP connection: {e}")
            raise

    def _return_connection(self, conn: Connection):
        """Return connection to pool"""
        if len(self._connection_pool) < 10:  # Max pool size
            self._connection_pool.append(conn)
        else:
            conn.unbind()

    async def _find_user_dn(self, conn: Connection, username: str) -> Optional[str]:
        """Find user's DN by username"""
        search_filter = f"(&{self.config.user_filter}(uid={username}))"

        conn.search(
            search_base=self.config.user_search_base,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=["dn"],
        )

        if conn.entries:
            return conn.entries[0].entry_dn

        return None

    async def _get_user_from_dn(self, dn: str) -> Optional[ExternalUser]:
        """Get user details from DN"""
        conn = self._get_connection()

        conn.search(
            search_base=dn,
            search_filter="(objectClass=*)",
            search_scope=SUBTREE,
            attributes=list(self.config.attributes_map.values()),
        )

        if conn.entries:
            return self._ldap_to_external_user(conn.entries[0])

        return None

    def _ldap_to_external_user(self, entry) -> ExternalUser:
        """Convert LDAP entry to ExternalUser"""
        attrs = entry.entry_attributes_as_dict

        return ExternalUser(
            external_id=str(attrs.get("uid", [""])[0]),
            username=str(attrs.get("uid", [""])[0]),
            email=str(attrs.get("mail", [""])[0]) if attrs.get("mail") else None,
            first_name=(
                str(attrs.get("givenName", [""])[0]) if attrs.get("givenName") else None
            ),
            last_name=str(attrs.get("sn", [""])[0]) if attrs.get("sn") else None,
            full_name=str(attrs.get("cn", [""])[0]) if attrs.get("cn") else None,
            groups=[str(g) for g in attrs.get("memberOf", [])],
            attributes={
                "dn": entry.entry_dn,
                **{k: str(v[0]) if v else None for k, v in attrs.items()},
            },
            is_active=True,
        )

    def _ldap_to_external_group(self, entry) -> ExternalGroup:
        """Convert LDAP entry to ExternalGroup"""
        attrs = entry.entry_attributes_as_dict

        return ExternalGroup(
            external_id=entry.entry_dn,
            name=str(attrs.get("cn", [""])[0]),
            description=(
                str(attrs.get("description", [""])[0])
                if attrs.get("description")
                else None
            ),
            members=[str(m) for m in attrs.get("member", [])],
            attributes=dict(attrs),
        )
