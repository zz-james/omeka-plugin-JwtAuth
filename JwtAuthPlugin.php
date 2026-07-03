<?php
class JwtAuthPlugin extends Omeka_Plugin_AbstractPlugin
{
    protected $_hooks = [
        'install',
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
    }

    public function hookUninstall()
    {
        $this->_db->query("DROP TABLE IF EXISTS `{$this->_db->prefix}jwt_refresh_tokens`");
    }

    public function hookInitialize()
    {
        // Load Composer deps (firebase/php-jwt)
        require_once dirname(__FILE__) . '/vendor/autoload.php';

        // Add libraries/ to include path for JwtAuth_ class autoloading
        set_include_path(get_include_path() . PATH_SEPARATOR . dirname(__FILE__) . '/libraries');
        Zend_Loader_Autoloader::getInstance()->registerNamespace('JwtAuth_');

        $front = Zend_Controller_Front::getInstance();

        // Register plugin controller directory under module 'jwt_auth'
        // ZF1 maps module 'jwt_auth' -> class prefix 'JwtAuth_'
        $front->addControllerDirectory(dirname(__FILE__) . '/controllers', 'jwt_auth');

        // Register front controller plugin to validate JWT cookies on /api/* routes
        $front->registerPlugin(new JwtAuth_Controller_Plugin_ApiAuth());
    }

    public function hookDefineRoutes($args)
    {
        // define_routes only fires for non-API requests, which is correct —
        // /auth/* endpoints are separate from /api/*
        $router = $args['router'];

        $routes = [
            'jwt_auth_login'    => ['auth/login',    'login'],
            'jwt_auth_logout'   => ['auth/logout',   'logout'],
            'jwt_auth_me'       => ['auth/me',       'me'],
            'jwt_auth_register' => ['auth/register', 'register'],
        ];

        foreach ($routes as $name => [$path, $action]) {
            $router->addRoute($name, new Zend_Controller_Router_Route(
                $path,
                ['module' => 'jwt_auth', 'controller' => 'auth', 'action' => $action]
            ));
        }
    }
}
