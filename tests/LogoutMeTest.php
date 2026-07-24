<?php
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class JwtAuth_LogoutMeTest extends Omeka_Test_AppTestCase
{
    protected $_isAdminTest = false;

    const TEST_SECRET = 'test-secret-that-is-at-least-32-bytes-long';

    public function setUpLegacy()
    {
        parent::setUpLegacy();
        putenv('JWT_SECRET=' . self::TEST_SECRET);

        $helper = new Omeka_Test_Helper_Plugin;
        $helper->setUp('JwtAuth');

        unset($_COOKIE['auth_token'], $_COOKIE['refresh_token']);
    }

    // AC: GET /auth/me with valid cookie returns {id, name, email, role}
    public function testMeWithValidCookieReturnsUser()
    {
        $userId = Omeka_Test_Resource_Db::DEFAULT_USER_ID;
        $user   = $this->db->getTable('User')->find($userId);
        $tokens = JwtAuth_TokenService::issue($userId, $user->role);
        $_COOKIE['auth_token'] = $tokens['access_token'];

        $this->dispatch('/auth/me');

        $this->assertEquals(200, $this->getResponse()->getHttpResponseCode());
        $body = json_decode($this->getResponse()->outputBody(), true);
        $this->assertEquals($userId, $body['id']);
        $this->assertArrayHasKey('name', $body);
        $this->assertArrayHasKey('email', $body);
        $this->assertArrayHasKey('role', $body);
    }

    // AC: GET /auth/me without cookie returns 401
    public function testMeWithNoCookieReturns401()
    {
        $this->dispatch('/auth/me');
        $this->assertEquals(401, $this->getResponse()->getHttpResponseCode());
    }

    // AC: expired auth_token + valid refresh_token → 200 + new auth_token cookie set
    public function testMeWithExpiredAccessButValidRefreshReturnsUser()
    {
        $userId = Omeka_Test_Resource_Db::DEFAULT_USER_ID;
        $user   = $this->db->getTable('User')->find($userId);

        $tokens = JwtAuth_TokenService::issue($userId, $user->role);

        $expiredAccess = JWT::encode([
            'user_id' => $userId,
            'role'    => $user->role,
            'exp'     => time() - 100,
        ], self::TEST_SECRET, 'HS256');

        $_COOKIE['auth_token']    = $expiredAccess;
        $_COOKIE['refresh_token'] = $tokens['refresh_token'];

        $this->dispatch('/auth/me');

        $this->assertEquals(200, $this->getResponse()->getHttpResponseCode());
        $body = json_decode($this->getResponse()->outputBody(), true);
        $this->assertEquals($userId, $body['id']);

        $rawHeaders = $this->getResponse()->getRawHeaders();
        $newCookie  = array_filter($rawHeaders, function ($h) {
            return strpos($h, 'Set-Cookie: auth_token=') !== false
                && strpos($h, 'Max-Age=-1') === false;
        });
        $this->assertNotEmpty($newCookie, 'new auth_token cookie not set in response');
    }

    // AC: expired auth_token + revoked refresh_token → 401
    public function testMeWithExpiredAccessAndRevokedRefreshReturns401()
    {
        $userId = Omeka_Test_Resource_Db::DEFAULT_USER_ID;
        $user   = $this->db->getTable('User')->find($userId);

        $tokens = JwtAuth_TokenService::issue($userId, $user->role);
        JwtAuth_TokenService::revokeRefreshToken($tokens['refresh_token']);

        $expiredAccess = JWT::encode([
            'user_id' => $userId,
            'role'    => $user->role,
            'exp'     => time() - 100,
        ], self::TEST_SECRET, 'HS256');

        $_COOKIE['auth_token']    = $expiredAccess;
        $_COOKIE['refresh_token'] = $tokens['refresh_token'];

        $this->dispatch('/auth/me');

        $this->assertEquals(401, $this->getResponse()->getHttpResponseCode());
    }

    // AC: POST /auth/logout marks refresh token revoked = 1 in DB
    public function testLogoutRevokesRefreshToken()
    {
        $userId = Omeka_Test_Resource_Db::DEFAULT_USER_ID;
        $user   = $this->db->getTable('User')->find($userId);
        $tokens = JwtAuth_TokenService::issue($userId, $user->role);

        $_COOKIE['auth_token']    = $tokens['access_token'];
        $_COOKIE['refresh_token'] = $tokens['refresh_token'];

        $this->getRequest()->setMethod('POST');
        $this->dispatch('/auth/logout');

        $this->assertEquals(204, $this->getResponse()->getHttpResponseCode());

        $tokenHash = hash('sha256', $tokens['refresh_token']);
        $rows = $this->db->getAdapter()->fetchAll(
            'SELECT revoked FROM omeka_jwt_refresh_tokens WHERE token_hash = ?',
            [$tokenHash]
        );
        $this->assertCount(1, $rows);
        $this->assertEquals(1, (int) $rows[0]['revoked']);
    }

    // AC: POST /auth/logout clears both cookies in the response
    public function testLogoutClearsCookies()
    {
        $userId = Omeka_Test_Resource_Db::DEFAULT_USER_ID;
        $user   = $this->db->getTable('User')->find($userId);
        $tokens = JwtAuth_TokenService::issue($userId, $user->role);

        $_COOKIE['auth_token']    = $tokens['access_token'];
        $_COOKIE['refresh_token'] = $tokens['refresh_token'];

        $this->getRequest()->setMethod('POST');
        $this->dispatch('/auth/logout');

        $rawHeaders     = $this->getResponse()->getRawHeaders();
        $accessCleared  = array_filter($rawHeaders, function ($h) {
            return strpos($h, 'Set-Cookie: auth_token=') !== false
                && strpos($h, 'Max-Age=-1') !== false;
        });
        $refreshCleared = array_filter($rawHeaders, function ($h) {
            return strpos($h, 'Set-Cookie: refresh_token=') !== false
                && strpos($h, 'Max-Age=-1') !== false;
        });

        $this->assertNotEmpty($accessCleared, 'auth_token cookie not cleared');
        $this->assertNotEmpty($refreshCleared, 'refresh_token cookie not cleared');
    }
}
