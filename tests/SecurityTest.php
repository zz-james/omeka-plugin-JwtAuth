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

    // --- helpers ---

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
