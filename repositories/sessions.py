import json
from dataclasses import asdict
from uuid import UUID

from redis.asyncio import Redis
from redis.exceptions import RedisError

from services.contracts import SessionRecord
from services.errors import StorageUnavailable

ROTATE_SCRIPT = """
local raw = redis.call('GET', KEYS[1])
if not raw then return 0 end
local session = cjson.decode(raw)
if session.session_id ~= ARGV[1] then return 0 end
if session.refresh_digest ~= ARGV[2] then
    redis.call('DEL', KEYS[1])
    return -1
end
session.refresh_digest = ARGV[3]
redis.call('SET', KEYS[1], cjson.encode(session), 'EXAT', session.expires_at)
return 1
"""

THROTTLE_SCRIPT = """
local account = redis.call('INCR', KEYS[1])
if account == 1 then redis.call('EXPIRE', KEYS[1], 300) end
local client = redis.call('INCR', KEYS[2])
if client == 1 then redis.call('EXPIRE', KEYS[2], 300) end
if account > 10 or client > 100 then return 0 end
return 1
"""


class RedisSessionStore:
    def __init__(self, client: Redis):
        self.client = client

    @staticmethod
    def _key(user_uuid: UUID) -> str:
        return f"active_session:{user_uuid}"

    async def replace(self, user_uuid: UUID, session: SessionRecord) -> None:
        try:
            await self.client.set(
                self._key(user_uuid),
                json.dumps(asdict(session)),
                exat=session.expires_at,
            )
        except RedisError as error:
            raise StorageUnavailable() from error

    async def get(self, user_uuid: UUID) -> SessionRecord | None:
        try:
            raw = await self.client.get(self._key(user_uuid))
            return SessionRecord(**json.loads(raw)) if raw else None
        except (RedisError, TypeError, ValueError) as error:
            raise StorageUnavailable() from error

    async def rotate(
        self,
        user_uuid: UUID,
        session_id: str,
        previous_digest: str,
        next_digest: str,
    ) -> bool:
        try:
            # Comparación y rotación atómicas; un replay invalida la sesión.
            result = await self.client.eval(
                ROTATE_SCRIPT, 1, self._key(user_uuid),
                session_id, previous_digest, next_digest,
            )
            return result == 1
        except RedisError as error:
            raise StorageUnavailable() from error

    async def revoke(self, user_uuid: UUID) -> None:
        try:
            await self.client.delete(self._key(user_uuid))
        except RedisError as error:
            raise StorageUnavailable() from error

    async def allow_login(self, account_key: str, client_key: str) -> bool:
        try:
            result = await self.client.eval(
                THROTTLE_SCRIPT, 2,
                f"login:account:{account_key}", f"login:client:{client_key}",
            )
            return result == 1
        except RedisError as error:
            raise StorageUnavailable() from error
