<?php
class JwtAuthPlugin extends Omeka_Plugin_AbstractPlugin
{
    protected $_hooks = [
        'install',
        'upgrade',
        'uninstall',
        'initialize',
        'define_routes',
    ];

    public function hookInstall()
    {
        $prefix = $this->_db->prefix;
        $this->_db->query("
            CREATE TABLE IF NOT EXISTS `{$prefix}jwt_refresh_tokens` (
                `id`          INT UNSIGNED    NOT NULL AUTO_INCREMENT PRIMARY KEY,
                `token_hash`  VARCHAR(128)    NOT NULL UNIQUE,
                `user_id`     INT UNSIGNED    NOT NULL,
                `expires_at`  DATETIME        NOT NULL,
                `revoked`     TINYINT(1)      NOT NULL DEFAULT 0,
                `created_at`  DATETIME        NOT NULL
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        ");
        $this->_createAttemptsTable();
    }

    public function hookUpgrade($args)
    {
        if (version_compare($args['old_version'], '0.2.0', '<')) {
            $this->_createAttemptsTable();
        }
    }

    public function hookUninstall()
    {
        $this->_db->query("DROP TABLE IF EXISTS `{$this->_db->prefix}jwt_refresh_tokens`");
        $this->_db->query("DROP TABLE IF EXISTS `{$this->_db->prefix}jwt_auth_attempts`");
    }

    private function _createAttemptsTable()
    {
        $prefix = $this->_db->prefix;
        $this->_db->query("
            CREATE TABLE IF NOT EXISTS `{$prefix}jwt_auth_attempts` (
                `id`           INT UNSIGNED  NOT NULL AUTO_INCREMENT PRIMARY KEY,
                `identity`     VARCHAR(191)  NOT NULL,
                `attempted_at` DATETIME      NOT NULL,
                KEY `identity_attempted` (`identity`, `attempted_at`)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        ");
    }

    public function hookInitialize()
    {
        // Load Composer deps (firebase/php-jwt)
        require_once dirname(__FILE__) . '/vendor/autoload.php';

        $pluginDir = dirname(__FILE__);
        set_include_path(
            $pluginDir . '/models'
            . PATH_SEPARATOR . $pluginDir . '/libraries'
            . PATH_SEPARATOR . get_include_path()
        );
        Zend_Loader_Autoloader::getInstance()->registerNamespace('JwtAuth_');

        $front = Zend_Controller_Front::getInstance();

        // Register plugin controller directory under module 'jwt-auth'
        // ZF1 maps module 'jwt-auth' -> class prefix 'JwtAuth_'
        $front->addControllerDirectory(dirname(__FILE__) . '/controllers', 'jwt-auth');

        // Register front controller plugin to validate JWT cookies on /api/* routes
        $front->registerPlugin(new JwtAuth_Controller_Plugin_ApiAuth());
    }

    public function hookDefineRoutes($args)
    {
        // define_routes only fires for non-API requests, which is correct —
        // /auth/* endpoints are separate from /api/*
        $router = $args['router'];

        $routes = [
            'jwt-auth_login'    => ['auth/login',    'login'],
            'jwt-auth_logout'   => ['auth/logout',   'logout'],
            'jwt-auth_me'       => ['auth/me',       'me'],
            'jwt-auth_register' => ['auth/register', 'register'],
        ];

        foreach ($routes as $name => [$path, $action]) {
            $router->addRoute($name, new Zend_Controller_Router_Route(
                $path,
                ['module' => 'jwt-auth', 'controller' => 'auth', 'action' => $action]
            ));
        }
    }
}
