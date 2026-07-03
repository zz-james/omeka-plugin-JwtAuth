<?php
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class JwtAuth_LoginTest extends Omeka_Test_AppTestCase
{
    protected $_isAdminTest = false;

    const TEST_SECRET = 'test-secret-that-is-at-least-32-bytes-long';

    public function setUpLegacy()
    {
        parent::setUpLegacy();

        putenv('JWT_SECRET=' . self::TEST_SECRET);

        $helper = new Omeka_Test_Helper_Plugin;
        $helper->setUp('JwtAuth');
    }

    // AC: Plugin activates without errors; jwt_refresh_tokens table exists
    public function testInstallCreatesRefreshTokenTable()
    {
        $rows = $this->db->getAdapter()->fetchCol(
            "SHOW TABLES LIKE 'omeka_jwt_refresh_tokens'"
        );
        $this->assertCount(1, $rows);
    }

    // AC: POST /auth/login with valid credentials returns 200 + user JSON
    public function testValidLoginReturns200WithUserJson()
    {
        $this->_postLogin(
            Omeka_Test_Resource_Db::SUPER_EMAIL,
            Omeka_Test_Resource_Db::SUPER_PASSWORD
        );

        $this->assertEquals(200, $this->getResponse()->getHttpResponseCode());

        $body = json_decode($this->getResponse()->outputBody(), true);
        $this->assertEquals(Omeka_Test_Resource_Db::SUPER_EMAIL, $body['email']);
        $this->assertArrayHasKey('id', $body);
        $this->assertArrayHasKey('name', $body);
        $this->assertArrayHasKey('role', $body);
    }

    // AC: POST /auth/login with invalid credentials returns 401, no cookies set
    public function testInvalidPasswordReturns401()
    {
        $this->_postLogin(
            Omeka_Test_Resource_Db::SUPER_EMAIL,
            'wrongpassword'
        );

        $this->assertEquals(401, $this->getResponse()->getHttpResponseCode());
    }

    public function testUnknownEmailReturns401()
    {
        $this->_postLogin('nobody@example.com', 'anything');

        $this->assertEquals(401, $this->getResponse()->getHttpResponseCode());
    }

    // AC: Refresh token row written to jwt_refresh_tokens with correct user_id and expires_at
    public function testLoginPersistsRefreshTokenToDb()
    {
        $before = time();
        $this->_postLogin(
            Omeka_Test_Resource_Db::SUPER_EMAIL,
            Omeka_Test_Resource_Db::SUPER_PASSWORD
        );
        $after = time();

        $rows = $this->db->getAdapter()->fetchAll(
            "SELECT * FROM omeka_jwt_refresh_tokens WHERE user_id = ?",
            [Omeka_Test_Resource_Db::DEFAULT_USER_ID]
        );

        $this->assertCount(1, $rows);
        $this->assertEquals(0, (int) $rows[0]['revoked']);

        $expiresAt = strtotime($rows[0]['expires_at']);
        // 30 days TTL — check within a 2-second window
        $this->assertGreaterThanOrEqual($before + 2592000, $expiresAt);
        $this->assertLessThanOrEqual($after + 2592000, $expiresAt);
    }

    // AC: OPTIONS /auth/login returns 204 + CORS headers (Access-Control-Allow-Credentials: true)
    public function testOptionsReturns204()
    {
        $this->getRequest()
            ->setMethod('OPTIONS')
            ->setHeader('Origin', 'http://localhost:5173')
            ->setHeader('Access-Control-Request-Method', 'POST');

        $this->dispatch('/auth/login');

        $this->assertEquals(204, $this->getResponse()->getHttpResponseCode());
    }

    public function testOptionsIncludesCredentialsCorsHeader()
    {
        $this->getRequest()
            ->setMethod('OPTIONS')
            ->setHeader('Origin', 'http://localhost:5173');

        $this->dispatch('/auth/login');

        $headers = $this->_responseHeaderMap();
        $this->assertEquals('true', $headers['Access-Control-Allow-Credentials']);
        $this->assertEquals('http://localhost:5173', $headers['Access-Control-Allow-Origin']);
    }

    // AC: JWT payload contains user_id, role, exp (15 min from issue time)
    public function testIssuedJwtContainsRequiredClaims()
    {
        $before = time();
        $tokens = JwtAuth_TokenService::issue(
            Omeka_Test_Resource_Db::DEFAULT_USER_ID,
            'super'
        );
        $after = time();

        $decoded = JWT::decode(
            $tokens['access_token'],
            new Key(self::TEST_SECRET, 'HS256')
        );

        $this->assertEquals(Omeka_Test_Resource_Db::DEFAULT_USER_ID, $decoded->user_id);
        $this->assertEquals('super', $decoded->role);
        // exp should be ~15 min from now
        $this->assertGreaterThanOrEqual($before + 900, $decoded->exp);
        $this->assertLessThanOrEqual($after + 900, $decoded->exp);
    }

    // --- helpers ---

    private function _postLogin(string $email, string $password): void
    {
        $this->getRequest()
            ->setMethod('POST')
            ->setHeader('Content-Type', 'application/json')
            ->setHeader('Origin', 'http://localhost:5173')
            ->setRawBody(json_encode(compact('email', 'password')));

        $this->dispatch('/auth/login');
    }

    private function _responseHeaderMap(): array
    {
        $map = [];
        foreach ($this->getResponse()->getHeaders() as $h) {
            $map[$h['name']] = $h['value'];
        }
        return $map;
    }
}
