<?php
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class JwtAuth_ApiAuthTest extends Omeka_Test_AppTestCase
{
    protected $_isAdminTest = false;

    const TEST_SECRET = 'test-secret-that-is-at-least-32-bytes-long';

    public function setUpLegacy()
    {
        parent::setUpLegacy();

        putenv('JWT_SECRET=' . self::TEST_SECRET);

        $helper = new Omeka_Test_Helper_Plugin;
        $helper->setUp('JwtAuth');

        // Flag as API request so ApiAuth::preDispatch() doesn't bail early
        $this->frontController->setParam('api', true);
    }

    // AC: valid auth_token cookie → current user injected into registry
    public function testValidCookieInjectsUser()
    {
        $userId = Omeka_Test_Resource_Db::DEFAULT_USER_ID;
        $user   = $this->db->getTable('User')->findActiveById($userId);
        $tokens = JwtAuth_TokenService::issue($userId, $user->role);
        $_COOKIE['auth_token'] = $tokens['access_token'];

        $this->_runPreDispatch();

        $bootstrap = Zend_Registry::get('bootstrap');
        $injected  = $bootstrap->getResource('CurrentUser');
        $this->assertNotNull($injected);
        $this->assertEquals($userId, (int) $injected->id);
    }

    // AC: no cookie → request proceeds as anonymous (no injection, no error)
    public function testNoCookieLeavesAnonymous()
    {
        $this->_runPreDispatch();

        $bootstrap = Zend_Registry::get('bootstrap');
        $this->assertNull($bootstrap->getResource('CurrentUser'));
    }

    // AC: tampered cookie → anonymous, not a 500
    public function testTamperedCookieIsAnonymous()
    {
        $_COOKIE['auth_token'] = 'this.is.not.a.valid.jwt';

        $this->_runPreDispatch();

        $bootstrap = Zend_Registry::get('bootstrap');
        $this->assertNull($bootstrap->getResource('CurrentUser'));
    }

    // AC: expired access cookie with no refresh cookie → anonymous, not a 500
    public function testExpiredCookieIsAnonymous()
    {
        $userId = Omeka_Test_Resource_Db::DEFAULT_USER_ID;
        $user   = $this->db->getTable('User')->findActiveById($userId);

        $expiredToken = JWT::encode([
            'user_id' => $userId,
            'role'    => $user->role,
            'exp'     => time() - 100,
        ], self::TEST_SECRET, 'HS256');

        $_COOKIE['auth_token'] = $expiredToken;

        $this->_runPreDispatch();

        $bootstrap = Zend_Registry::get('bootstrap');
        $this->assertNull($bootstrap->getResource('CurrentUser'));
    }

    // AC: JWT signed with wrong secret → anonymous
    public function testWrongSecretCookieIsAnonymous()
    {
        $userId = Omeka_Test_Resource_Db::DEFAULT_USER_ID;

        $wrongToken = JWT::encode([
            'user_id' => $userId,
            'role'    => 'super',
            'exp'     => time() + 900,
        ], 'completely-wrong-secret-key-here', 'HS256');

        $_COOKIE['auth_token'] = $wrongToken;

        $this->_runPreDispatch();

        $bootstrap = Zend_Registry::get('bootstrap');
        $this->assertNull($bootstrap->getResource('CurrentUser'));
    }

    // AC: no cookie → plugin does not set currentuser → legacy ?key= flow is unimpeded
    public function testNoCookieDoesNotOverrideExistingUser()
    {
        $defaultUser = $this->db->getTable('User')->findActiveById(
            Omeka_Test_Resource_Db::DEFAULT_USER_ID
        );
        // Simulate key-based auth having already set the user
        $bootstrap = Zend_Registry::get('bootstrap');
        $bootstrap->getContainer()->offsetSet('currentuser', $defaultUser);

        // No JWT cookie — our plugin must not clear what's already there
        $this->_runPreDispatch();

        $still = $bootstrap->getResource('CurrentUser');
        $this->assertNotNull($still);
        $this->assertEquals($defaultUser->id, $still->id);
    }

    // --- helpers ---

    private function _runPreDispatch(): void
    {
        $plugin = new JwtAuth_Controller_Plugin_ApiAuth();
        $plugin->setRequest($this->getRequest());
        $plugin->setResponse($this->getResponse());
        $plugin->preDispatch($this->getRequest());
    }
}
