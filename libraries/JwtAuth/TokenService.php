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

    // Validate the access token cookie. Returns claims array or null.
    public static function validateAccessCookie(\Zend_Controller_Request_Http $request): ?array
    {
        $token = $_COOKIE[self::ACCESS_COOKIE] ?? null;
        if (!$token) {
            return null;
        }

        try {
            $decoded = JWT::decode($token, new Key(self::_secret(), self::ALGO));
            return (array) $decoded;
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
        return $secret;
    }

    private static function _issuer(): string
    {
        return WEB_ROOT;
    }
}
