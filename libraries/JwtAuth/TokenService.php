<?php
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class JwtAuth_TokenService
{
    private const ACCESS_TTL  = 900;       // 15 min
    private const REFRESH_TTL = 2592000;   // 30 days
    private const ALGO        = 'HS256';

    private const ACCESS_COOKIE  = 'auth_token';
    private const REFRESH_COOKIE = 'refresh_token';

    // Issue a new access token + refresh token for the given user.
    // Returns ['access_token' => string, 'refresh_token' => string]
    public static function issue(int $userId, string $role): array
    {
        $now = time();

        $accessToken = JWT::encode([
            'iss'     => self::_issuer(),
            'iat'     => $now,
            'exp'     => $now + self::ACCESS_TTL,
            'user_id' => $userId,
            'role'    => $role,
        ], self::_secret(), self::ALGO);

        $refreshToken = bin2hex(random_bytes(32));
        $tokenHash    = hash('sha256', $refreshToken);

        self::_purgeStaleTokens($now);

        self::_db()->insert('JwtRefreshToken', [
            'token_hash' => $tokenHash,
            'user_id'    => $userId,
            'expires_at' => date('Y-m-d H:i:s', $now + self::REFRESH_TTL),
            'revoked'    => 0,
            'created_at' => date('Y-m-d H:i:s', $now),
        ]);

        return [
            'access_token'  => $accessToken,
            'refresh_token' => $refreshToken,
        ];
    }

    // Rotate a refresh token: revoke the presented token, then issue a fresh
    // access + refresh pair. Prevents a stolen refresh token from remaining
    // valid after the legitimate client has rotated past it.
    public static function rotate(int $userId, string $role, string $oldRawToken): array
    {
        self::revokeRefreshToken($oldRawToken);
        return self::issue($userId, $role);
    }

    // Validate the access token cookie. Returns claims array or null.
    public static function validateAccessCookie(\Zend_Controller_Request_Http $request): ?array
    {
        $token = $_COOKIE[self::ACCESS_COOKIE] ?? null;
        if (!$token) {
            return null;
        }

        try {
            $decoded = (array) JWT::decode($token, new Key(self::_secret(), self::ALGO));
            // Reject tokens minted for a different site sharing the same secret
            if (($decoded['iss'] ?? null) !== self::_issuer()) {
                return null;
            }
            return $decoded;
        } catch (\Exception $e) {
            return null;
        }
    }

    // Validate a refresh token cookie. Returns user_id or null.
    public static function validateRefreshCookie(\Zend_Controller_Request_Http $request): ?int
    {
        $token = $_COOKIE[self::REFRESH_COOKIE] ?? null;
        if (!$token) {
            return null;
        }

        $tokenHash = hash('sha256', $token);
        $row = self::_db()->getTable('JwtRefreshToken')->findByTokenHash($tokenHash);

        if (!$row || $row->revoked || strtotime($row->expires_at) <= time()) {
            return null;
        }

        return (int) $row->user_id;
    }

    // Revoke a refresh token by its raw cookie value.
    public static function revokeRefreshToken(string $rawToken): void
    {
        $tokenHash = hash('sha256', $rawToken);
        self::_db()->getTable('JwtRefreshToken')->revokeByTokenHash($tokenHash);
    }

    // Delete rows that can no longer authenticate anything: expired tokens,
    // and revoked tokens past a 7-day grace window (kept briefly so a future
    // reuse-detection pass has something to look at).
    private static function _purgeStaleTokens(int $now): void
    {
        $db = self::_db();
        $db->getAdapter()->delete(
            "{$db->prefix}jwt_refresh_tokens",
            sprintf(
                "expires_at < %s OR (revoked = 1 AND created_at < %s)",
                $db->getAdapter()->quote(date('Y-m-d H:i:s', $now)),
                $db->getAdapter()->quote(date('Y-m-d H:i:s', $now - 604800))
            )
        );
    }

    private static function _db(): Omeka_Db
    {
        return Zend_Registry::get('bootstrap')->getResource('Db');
    }

    private static function _secret(): string
    {
        $config = Zend_Registry::get('bootstrap')->getResource('Config');
        $secret = $config->jwtauth->secret ?? null;
        // Fall back to environment variable (useful in Docker)
        if (!$secret) {
            $secret = getenv('JWT_SECRET') ?: null;
        }
        if (!$secret) {
            throw new \RuntimeException('JwtAuth: jwt secret not configured.');
        }
        if (APPLICATION_ENV !== 'development'
            && (strlen($secret) < 32 || in_array($secret, self::WEAK_SECRETS, true))
        ) {
            throw new \RuntimeException(
                'JwtAuth: JWT secret is too weak for a non-development environment. '
                . 'Set a random secret of at least 32 characters.'
            );
        }
        return $secret;
    }

    // Known committed/dev secrets that must never be accepted outside development.
    private const WEAK_SECRETS = [
        'dev-secret-change-in-production-xx',
    ];

    private static function _issuer(): string
    {
        return WEB_ROOT;
    }
}
