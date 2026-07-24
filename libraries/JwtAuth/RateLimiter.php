<?php
// DB-backed fixed-window rate limiter for auth endpoints.
// Keys are opaque strings, e.g. "login:ip:1.2.3.4" or "login:email:<sha256>".
class JwtAuth_RateLimiter
{
    public static function tooManyAttempts(string $key, int $max, int $windowSeconds): bool
    {
        $db    = self::_db();
        $count = (int) $db->getAdapter()->fetchOne(
            "SELECT COUNT(*) FROM `{$db->prefix}jwt_auth_attempts`
             WHERE identity = ? AND attempted_at > ?",
            [$key, date('Y-m-d H:i:s', time() - $windowSeconds)]
        );
        return $count >= $max;
    }

    public static function hit(string $key): void
    {
        $db = self::_db();
        $db->getAdapter()->insert("{$db->prefix}jwt_auth_attempts", [
            'identity'     => $key,
            'attempted_at' => date('Y-m-d H:i:s'),
        ]);
        // Opportunistic cleanup so the table can't grow unbounded.
        $db->getAdapter()->delete(
            "{$db->prefix}jwt_auth_attempts",
            $db->getAdapter()->quoteInto(
                'attempted_at < ?',
                date('Y-m-d H:i:s', time() - 86400)
            )
        );
    }

    public static function clear(string $key): void
    {
        $db = self::_db();
        $db->getAdapter()->delete(
            "{$db->prefix}jwt_auth_attempts",
            $db->getAdapter()->quoteInto('identity = ?', $key)
        );
    }

    private static function _db(): Omeka_Db
    {
        return Zend_Registry::get('bootstrap')->getResource('Db');
    }
}
