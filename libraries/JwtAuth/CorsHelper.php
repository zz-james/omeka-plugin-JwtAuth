<?php
class JwtAuth_CorsHelper
{
    private const ACCESS_COOKIE  = 'auth_token';
    private const REFRESH_COOKIE = 'refresh_token';

    // Set CORS headers and httponly auth cookies on the response.
    public static function setHeaders(
        \Zend_Controller_Request_Http $request,
        \Zend_Controller_Response_Http $response
    ): void {
        $origin = $request->getHeader('Origin') ?? '';

        if (self::_isAllowedOrigin($origin)) {
            $response->setHeader('Access-Control-Allow-Origin', $origin);
            $response->setHeader('Access-Control-Allow-Credentials', 'true');
            $response->setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
            $response->setHeader('Access-Control-Allow-Headers', 'Content-Type');
        }
    }

    // Set httponly auth cookies on the response.
    public static function setAuthCookies(
        \Zend_Controller_Response_Http $response,
        array $tokens
    ): void {
        $secure   = self::_isHttps();
        $sameSite = $secure ? 'None' : 'Lax';

        self::_setCookie($response, self::ACCESS_COOKIE,  $tokens['access_token'],  900,     $secure, $sameSite);
        self::_setCookie($response, self::REFRESH_COOKIE, $tokens['refresh_token'], 2592000, $secure, $sameSite);
    }

    // Clear auth cookies by setting them expired.
    public static function clearAuthCookies(\Zend_Controller_Response_Http $response): void
    {
        $secure   = self::_isHttps();
        $sameSite = $secure ? 'None' : 'Lax';
        self::_setCookie($response, self::ACCESS_COOKIE,  '', -1, $secure, $sameSite);
        self::_setCookie($response, self::REFRESH_COOKIE, '', -1, $secure, $sameSite);
    }

    private static function _setCookie(
        \Zend_Controller_Response_Http $response,
        string $name,
        string $value,
        int $maxAge,
        bool $secure,
        string $sameSite
    ): void {
        $cookie = sprintf(
            '%s=%s; Max-Age=%d; Path=/; HttpOnly; SameSite=%s%s',
            $name,
            rawurlencode($value),
            $maxAge,
            $sameSite,
            $secure ? '; Secure' : ''
        );

        if (PHP_SAPI === 'cli') {
            // Test environment: store on the response object for inspection
            $response->setRawHeader('Set-Cookie: ' . $cookie);
            return;
        }

        // Real requests must NOT go through the response object: ZF1's
        // sendHeaders() replays raw headers via header() with replace=true,
        // so a second Set-Cookie would overwrite the first and only one
        // cookie would ever reach the browser. header() with replace=false
        // is the only way to emit multiple Set-Cookie headers.
        header('Set-Cookie: ' . $cookie, false);
    }

    private static function _isAllowedOrigin(string $origin): bool
    {
        $allowed = self::_allowedOrigins();
        return in_array($origin, $allowed, true);
    }

    // Comma-separated list from Omeka config (jwtauth.allowed_origins) or the
    // JWT_ALLOWED_ORIGINS env var; localhost fallback covers local dev.
    private static function _allowedOrigins(): array
    {
        $configured = null;
        try {
            $config     = Zend_Registry::get('bootstrap')->getResource('Config');
            $configured = $config->jwtauth->allowed_origins ?? null;
        } catch (\Exception $e) {
            // Config resource unavailable — fall through to env
        }
        if (!$configured) {
            $configured = getenv('JWT_ALLOWED_ORIGINS') ?: null;
        }
        if ($configured) {
            return array_values(array_filter(array_map('trim', explode(',', $configured))));
        }
        return [
            'http://localhost:5173',
            'http://localhost:3000',
        ];
    }

    // Detect the actual request scheme rather than trusting APPLICATION_ENV.
    // X-Forwarded-Proto is honoured because erring toward Secure is the safe
    // direction — worst case is a dropped cookie behind a misconfigured proxy.
    private static function _isHttps(): bool
    {
        if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
            return true;
        }
        return ($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https';
    }
}
