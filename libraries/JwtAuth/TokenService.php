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

        // TODO: persist $tokenHash to jwt_refresh_tokens table

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

        // TODO: look up $tokenHash in jwt_refresh_tokens table
        // TODO: check revoked = 0 and expires_at > NOW()
        // TODO: return user_id if valid, null otherwise
        return null;
    }

    // Revoke a refresh token by its raw cookie value.
    public static function revokeRefreshToken(string $rawToken): void
    {
        $tokenHash = hash('sha256', $rawToken);
        // TODO: set revoked = 1 on the matching jwt_refresh_tokens row
    }

    private static function _secret(): string
    {
        // JWT secret read from Omeka config, never hardcoded
        $config = Zend_Registry::get('bootstrap')->getResource('Config');
        $secret = $config->jwtauth->secret ?? null;
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
