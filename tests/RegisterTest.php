<?php
class JwtAuth_RegisterTest extends Omeka_Test_AppTestCase
{
    protected $_isAdminTest = false;

    const TEST_SECRET  = 'test-secret-that-is-at-least-32-bytes-long';
    const TEST_EMAIL   = 'newuser@example.com';
    const TEST_NAME    = 'New User';
    const TEST_PASS    = 'password123';

    public function setUpLegacy()
    {
        parent::setUpLegacy();
        putenv('JWT_SECRET=' . self::TEST_SECRET);

        $helper = new Omeka_Test_Helper_Plugin;
        $helper->setUp('JwtAuth');

        unset($_COOKIE['auth_token'], $_COOKIE['refresh_token']);
    }

    // AC: POST /auth/register with valid data creates User with role=contributor, active=1
    public function testRegisterCreatesContributorUser()
    {
        $this->_postRegister(self::TEST_NAME, self::TEST_EMAIL, self::TEST_PASS);

        $this->assertEquals(201, $this->getResponse()->getHttpResponseCode());

        $body = json_decode($this->getResponse()->outputBody(), true);
        $this->assertEquals(self::TEST_EMAIL, $body['email']);
        $this->assertEquals('contributor', $body['role']);

        $row = $this->db->getAdapter()->fetchRow(
            'SELECT role, active FROM omeka_users WHERE email = ?',
            [self::TEST_EMAIL]
        );
        $this->assertNotEmpty($row);
        $this->assertEquals('contributor', $row['role']);
        $this->assertEquals(1, (int) $row['active']);
    }

    // AC: Response sets auth_token and refresh_token cookies
    public function testRegisterSetsCookies()
    {
        $this->_postRegister(self::TEST_NAME, self::TEST_EMAIL, self::TEST_PASS);

        $rawHeaders     = $this->getResponse()->getRawHeaders();
        $accessCookie   = array_filter($rawHeaders, function ($h) {
            return strpos($h, 'Set-Cookie: auth_token=') !== false
                && strpos($h, 'Max-Age=-1') === false;
        });
        $refreshCookie  = array_filter($rawHeaders, function ($h) {
            return strpos($h, 'Set-Cookie: refresh_token=') !== false
                && strpos($h, 'Max-Age=-1') === false;
        });

        $this->assertNotEmpty($accessCookie, 'auth_token cookie not set');
        $this->assertNotEmpty($refreshCookie, 'refresh_token cookie not set');
    }

    // AC: GET /auth/me immediately after register returns the new user's info
    public function testMeReturnsRegisteredUser()
    {
        $this->_postRegister(self::TEST_NAME, self::TEST_EMAIL, self::TEST_PASS);
        $this->assertEquals(201, $this->getResponse()->getHttpResponseCode());

        $body   = json_decode($this->getResponse()->outputBody(), true);
        $userId = (int) $body['id'];

        $this->resetResponse();
        unset($_COOKIE['auth_token'], $_COOKIE['refresh_token']);

        $user   = $this->db->getTable('User')->find($userId);
        $tokens = JwtAuth_TokenService::issue($userId, $user->role);
        $_COOKIE['auth_token'] = $tokens['access_token'];

        $this->dispatch('/auth/me');

        $meBody = json_decode($this->getResponse()->outputBody(), true);
        $this->assertEquals(self::TEST_EMAIL, $meBody['email']);
        $this->assertEquals('contributor', $meBody['role']);
    }

    // AC: POST /auth/register with duplicate email returns 422
    public function testDuplicateEmailReturns422()
    {
        // Use the pre-seeded super user's email — guaranteed to exist
        $this->_postRegister('Duplicate', Omeka_Test_Resource_Db::SUPER_EMAIL, self::TEST_PASS);

        $this->assertEquals(422, $this->getResponse()->getHttpResponseCode());

        $body = json_decode($this->getResponse()->outputBody(), true);
        $this->assertArrayHasKey('error', $body);
    }

    // AC: POST /auth/register with missing fields returns 422
    public function testMissingFieldsReturns422()
    {
        $this->getRequest()
            ->setMethod('POST')
            ->setHeader('Content-Type', 'application/json')
            ->setRawBody(json_encode(['name' => 'No Email']));

        $this->dispatch('/auth/register');

        $this->assertEquals(422, $this->getResponse()->getHttpResponseCode());
    }

    // --- helpers ---

    private function _postRegister(string $name, string $email, string $password): void
    {
        $this->getRequest()
            ->setMethod('POST')
            ->setHeader('Content-Type', 'application/json')
            ->setRawBody(json_encode(compact('name', 'email', 'password')));

        $this->dispatch('/auth/register');
    }
}
