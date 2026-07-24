<?php
use Firebase\JWT\JWT;

class JwtAuth_SecurityTest extends Omeka_Test_AppTestCase
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

    // H1: silent refresh must revoke the presented refresh token (rotation)
    public function testSilentRefreshRevokesOldRefreshToken()
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

        $oldHash = hash('sha256', $tokens['refresh_token']);
        $revoked = $this->db->getAdapter()->fetchOne(
            'SELECT revoked FROM omeka_jwt_refresh_tokens WHERE token_hash = ?',
            [$oldHash]
        );
        $this->assertEquals(1, (int) $revoked, 'old refresh token not revoked on rotation');

        // A replacement token row must exist and be live
        $live = $this->db->getAdapter()->fetchOne(
            'SELECT COUNT(*) FROM omeka_jwt_refresh_tokens WHERE user_id = ? AND revoked = 0',
            [$userId]
        );
        $this->assertEquals(1, (int) $live, 'no live replacement refresh token issued');
    }

    // H1: a rotated-away (revoked) refresh token must not authenticate again
    public function testRotatedRefreshTokenCannotBeReused()
    {
        $userId = Omeka_Test_Resource_Db::DEFAULT_USER_ID;
        $user   = $this->db->getTable('User')->find($userId);
        $tokens = JwtAuth_TokenService::rotate($userId, $user->role, 'unused-raw-token');

        // Rotate once more; the first token is now superseded
        JwtAuth_TokenService::rotate($userId, $user->role, $tokens['refresh_token']);

        $_COOKIE['refresh_token'] = $tokens['refresh_token'];
        $this->dispatch('/auth/me');
        $this->assertEquals(401, $this->getResponse()->getHttpResponseCode());
    }

    // H2: >5 failed logins for one email → 429, even with correct password
    public function testLoginLockoutAfterRepeatedFailures()
    {
        for ($i = 0; $i < 5; $i++) {
            $this->_postJson('/auth/login', [
                'email'    => Omeka_Test_Resource_Db::SUPER_EMAIL,
                'password' => 'wrongpassword',
            ]);
            $this->assertEquals(401, $this->getResponse()->getHttpResponseCode());
            $this->_resetDispatch();
        }

        $this->_postJson('/auth/login', [
            'email'    => Omeka_Test_Resource_Db::SUPER_EMAIL,
            'password' => Omeka_Test_Resource_Db::SUPER_PASSWORD,
        ]);
        $this->assertEquals(429, $this->getResponse()->getHttpResponseCode());
    }

    // H2: successful login clears the per-email failure counter
    public function testSuccessfulLoginClearsFailureCounter()
    {
        for ($i = 0; $i < 4; $i++) {
            $this->_postJson('/auth/login', [
                'email'    => Omeka_Test_Resource_Db::SUPER_EMAIL,
                'password' => 'wrongpassword',
            ]);
            $this->_resetDispatch();
        }

        $this->_postJson('/auth/login', [
            'email'    => Omeka_Test_Resource_Db::SUPER_EMAIL,
            'password' => Omeka_Test_Resource_Db::SUPER_PASSWORD,
        ]);
        $this->assertEquals(200, $this->getResponse()->getHttpResponseCode());
        $this->_resetDispatch();

        // Counter reset — a following bad attempt is a plain 401, not 429
        $this->_postJson('/auth/login', [
            'email'    => Omeka_Test_Resource_Db::SUPER_EMAIL,
            'password' => 'wrongpassword',
        ]);
        $this->assertEquals(401, $this->getResponse()->getHttpResponseCode());
    }

    // H2: >5 register attempts per IP per hour → 429
    public function testRegisterThrottledPerIp()
    {
        for ($i = 0; $i < 5; $i++) {
            $this->_postJson('/auth/register', [
                'name'     => "User $i",
                'email'    => "user$i@example.com",
                'password' => 'password123',
            ]);
            $this->assertEquals(201, $this->getResponse()->getHttpResponseCode());
            $this->_resetDispatch();
        }

        $this->_postJson('/auth/register', [
            'name'     => 'User 6',
            'email'    => 'user6@example.com',
            'password' => 'password123',
        ]);
        $this->assertEquals(429, $this->getResponse()->getHttpResponseCode());
    }

    // H3: secrets under 32 chars are rejected outside development
    public function testShortSecretRejected()
    {
        putenv('JWT_SECRET=too-short');
        try {
            $this->expectException(RuntimeException::class);
            JwtAuth_TokenService::issue(Omeka_Test_Resource_Db::DEFAULT_USER_ID, 'super');
        } finally {
            putenv('JWT_SECRET=' . self::TEST_SECRET);
        }
    }

    // H3: the committed dev default is rejected outside development
    public function testKnownDevSecretRejected()
    {
        putenv('JWT_SECRET=dev-secret-change-in-production-xx');
        try {
            $this->expectException(RuntimeException::class);
            JwtAuth_TokenService::issue(Omeka_Test_Resource_Db::DEFAULT_USER_ID, 'super');
        } finally {
            putenv('JWT_SECRET=' . self::TEST_SECRET);
        }
    }

    // M1: passwords under 8 chars rejected on register
    public function testRegisterRejectsShortPassword()
    {
        $this->_postJson('/auth/register', [
            'name'     => 'Short Pass',
            'email'    => 'shortpass@example.com',
            'password' => 'abc123',
        ]);
        $this->assertEquals(422, $this->getResponse()->getHttpResponseCode());

        $count = $this->db->getAdapter()->fetchOne(
            'SELECT COUNT(*) FROM omeka_users WHERE email = ?',
            ['shortpass@example.com']
        );
        $this->assertEquals(0, (int) $count, 'user created despite short password');
    }

    // M2: deactivated user with a still-valid access token gets 401
    public function testDeactivatedUserWithValidTokenGets401()
    {
        $userId = Omeka_Test_Resource_Db::DEFAULT_USER_ID;
        $user   = $this->db->getTable('User')->find($userId);
        $tokens = JwtAuth_TokenService::issue($userId, $user->role);

        $this->db->getAdapter()->update(
            'omeka_users',
            ['active' => 0],
            $this->db->getAdapter()->quoteInto('id = ?', $userId)
        );

        $_COOKIE['auth_token'] = $tokens['access_token'];
        $this->dispatch('/auth/me');

        $this->assertEquals(401, $this->getResponse()->getHttpResponseCode());
    }

    // M2/L1: deleted user with a still-valid access token gets 401, not a 500
    public function testDeletedUserWithValidTokenGets401()
    {
        $userId = Omeka_Test_Resource_Db::DEFAULT_USER_ID;
        $user   = $this->db->getTable('User')->find($userId);
        $tokens = JwtAuth_TokenService::issue($userId, $user->role);

        $this->db->getAdapter()->delete(
            'omeka_users',
            $this->db->getAdapter()->quoteInto('id = ?', $userId)
        );

        $_COOKIE['auth_token'] = $tokens['access_token'];
        $this->dispatch('/auth/me');

        $this->assertEquals(401, $this->getResponse()->getHttpResponseCode());
    }

    // M3: auth POSTs without a JSON Content-Type are rejected (CSRF guard)
    public function testNonJsonLoginRejected()
    {
        $this->getRequest()
            ->setMethod('POST')
            ->setHeader('Content-Type', 'application/x-www-form-urlencoded')
            ->setRawBody('email=a@b.c&password=x');
        $this->dispatch('/auth/login');
        $this->assertEquals(415, $this->getResponse()->getHttpResponseCode());
    }

    public function testNonJsonLogoutRejected()
    {
        $userId = Omeka_Test_Resource_Db::DEFAULT_USER_ID;
        $user   = $this->db->getTable('User')->find($userId);
        $tokens = JwtAuth_TokenService::issue($userId, $user->role);
        $_COOKIE['refresh_token'] = $tokens['refresh_token'];

        $this->getRequest()->setMethod('POST');
        $this->dispatch('/auth/logout');

        $this->assertEquals(415, $this->getResponse()->getHttpResponseCode());

        // Token must NOT have been revoked by the rejected request
        $revoked = $this->db->getAdapter()->fetchOne(
            'SELECT revoked FROM omeka_jwt_refresh_tokens WHERE token_hash = ?',
            [hash('sha256', $tokens['refresh_token'])]
        );
        $this->assertEquals(0, (int) $revoked);
    }

    // L3: issuing a token purges expired rows and old revoked rows
    public function testIssuePurgesStaleTokenRows()
    {
        $userId = Omeka_Test_Resource_Db::DEFAULT_USER_ID;

        $this->db->getAdapter()->insert('omeka_jwt_refresh_tokens', [
            'token_hash' => str_repeat('a', 64),
            'user_id'    => $userId,
            'expires_at' => date('Y-m-d H:i:s', time() - 100),
            'revoked'    => 0,
            'created_at' => date('Y-m-d H:i:s', time() - 200),
        ]);
        $this->db->getAdapter()->insert('omeka_jwt_refresh_tokens', [
            'token_hash' => str_repeat('b', 64),
            'user_id'    => $userId,
            'expires_at' => date('Y-m-d H:i:s', time() + 86400),
            'revoked'    => 1,
            'created_at' => date('Y-m-d H:i:s', time() - 691200), // 8 days old
        ]);

        JwtAuth_TokenService::issue($userId, 'super');

        $hashes = $this->db->getAdapter()->fetchCol(
            'SELECT token_hash FROM omeka_jwt_refresh_tokens WHERE user_id = ?',
            [$userId]
        );
        $this->assertNotContains(str_repeat('a', 64), $hashes, 'expired row not purged');
        $this->assertNotContains(str_repeat('b', 64), $hashes, 'old revoked row not purged');
        $this->assertCount(1, $hashes, 'freshly issued row missing');
    }

    // L4: token with a foreign iss claim is rejected despite a valid signature
    public function testForeignIssuerTokenRejected()
    {
        $userId = Omeka_Test_Resource_Db::DEFAULT_USER_ID;

        $_COOKIE['auth_token'] = JWT::encode([
            'iss'     => 'http://other-site.example.com',
            'iat'     => time(),
            'exp'     => time() + 900,
            'user_id' => $userId,
            'role'    => 'super',
        ], self::TEST_SECRET, 'HS256');

        $this->dispatch('/auth/me');
        $this->assertEquals(401, $this->getResponse()->getHttpResponseCode());
    }

    // L5: auth responses are marked non-cacheable
    public function testAuthResponsesSendNoStore()
    {
        $this->_postJson('/auth/login', [
            'email'    => Omeka_Test_Resource_Db::SUPER_EMAIL,
            'password' => Omeka_Test_Resource_Db::SUPER_PASSWORD,
        ]);

        $cacheControl = null;
        foreach ($this->getResponse()->getHeaders() as $h) {
            if ($h['name'] === 'Cache-Control') {
                $cacheControl = $h['value'];
            }
        }
        $this->assertEquals('no-store', $cacheControl);
    }

    // L6: CORS allowlist is configurable via JWT_ALLOWED_ORIGINS
    public function testCorsAllowlistConfigurableViaEnv()
    {
        putenv('JWT_ALLOWED_ORIGINS=https://archive.example.com, https://staging.example.com');
        try {
            $this->getRequest()
                ->setMethod('OPTIONS')
                ->setHeader('Origin', 'https://staging.example.com');
            $this->dispatch('/auth/login');

            $headers = [];
            foreach ($this->getResponse()->getHeaders() as $h) {
                $headers[$h['name']] = $h['value'];
            }
            $this->assertEquals('https://staging.example.com', $headers['Access-Control-Allow-Origin'] ?? null);

            // The default localhost origins are no longer allowed once configured
            $this->_resetDispatch();
            $this->getRequest()
                ->setMethod('OPTIONS')
                ->setHeader('Origin', 'http://localhost:5173');
            $this->dispatch('/auth/login');

            $headers = [];
            foreach ($this->getResponse()->getHeaders() as $h) {
                $headers[$h['name']] = $h['value'];
            }
            $this->assertArrayNotHasKey('Access-Control-Allow-Origin', $headers);
        } finally {
            putenv('JWT_ALLOWED_ORIGINS');
        }
    }

    // L7: cookie Secure/SameSite follow the actual request scheme
    public function testCookiesSecureOverHttpsLaxOverHttp()
    {
        // http (test default): no Secure flag, SameSite=Lax
        $this->_postJson('/auth/login', [
            'email'    => Omeka_Test_Resource_Db::SUPER_EMAIL,
            'password' => Omeka_Test_Resource_Db::SUPER_PASSWORD,
        ]);
        $cookies = $this->_authCookieHeaders();
        $this->assertNotEmpty($cookies);
        foreach ($cookies as $c) {
            $this->assertStringNotContainsString('Secure', $c);
            $this->assertStringContainsString('SameSite=Lax', $c);
        }

        // https: Secure + SameSite=None
        $this->_resetDispatch();
        $_SERVER['HTTPS'] = 'on';
        try {
            $this->_postJson('/auth/login', [
                'email'    => Omeka_Test_Resource_Db::SUPER_EMAIL,
                'password' => Omeka_Test_Resource_Db::SUPER_PASSWORD,
            ]);
            $cookies = $this->_authCookieHeaders();
            $this->assertNotEmpty($cookies);
            foreach ($cookies as $c) {
                $this->assertStringContainsString('Secure', $c);
                $this->assertStringContainsString('SameSite=None', $c);
            }
        } finally {
            unset($_SERVER['HTTPS']);
        }
    }

    // --- helpers ---

    private function _authCookieHeaders(): array
    {
        return array_values(array_filter(
            $this->getResponse()->getRawHeaders(),
            function ($h) {
                return strpos($h, 'Set-Cookie: auth_token=') !== false
                    || strpos($h, 'Set-Cookie: refresh_token=') !== false;
            }
        ));
    }

    private function _postJson(string $path, array $body): void
    {
        $this->getRequest()
            ->setMethod('POST')
            ->setHeader('Content-Type', 'application/json')
            ->setHeader('Origin', 'http://localhost:5173')
            ->setRawBody(json_encode($body));

        $this->dispatch($path);
    }

    private function _resetDispatch(): void
    {
        $this->resetRequest();
        $this->resetResponse();
    }
}
