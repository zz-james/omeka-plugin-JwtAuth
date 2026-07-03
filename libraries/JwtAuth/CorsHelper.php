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
        $secure   = !self::_isDev();
        $sameSite = $secure ? 'None' : 'Lax';

        self::_setCookie($response, self::ACCESS_COOKIE,  $tokens['access_token'],  900,     $secure, $sameSite);
        self::_setCookie($response, self::REFRESH_COOKIE, $tokens['refresh_token'], 2592000, $secure, $sameSite);
    }

    // Clear auth cookies by setting them expired.
    public static function clearAuthCookies(\Zend_Controller_Response_Http $response): void
    {
        $secure   = !self::_isDev();
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
        // setRawHeader stores in ZF1's response object (works in tests too)
        $response->setRawHeader('Set-Cookie: ' . $cookie);
    }

    private static function _isAllowedOrigin(string $origin): bool
    {
        $allowed = self::_allowedOrigins();
        return in_array($origin, $allowed, true);
    }

    private static function _allowedOrigins(): array
    {
        // TODO: load from Omeka config (jwtauth.allowed_origins)
        // Fallback covers local dev
        return [
            'http://localhost:5173',
            'http://localhost:3000',
        ];
    }

    private static function _isDev(): bool
    {
        return defined('APPLICATION_ENV') && APPLICATION_ENV === 'development';
    }
}
