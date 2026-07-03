<?php
// Intercepts all /api/* requests and authenticates them via JWT cookie,
// replacing Omeka's default ?key= mechanism when a valid cookie is present.
class JwtAuth_Controller_Plugin_ApiAuth extends Zend_Controller_Plugin_Abstract
{
    public function preDispatch(\Zend_Controller_Request_Abstract $request): void
    {
        $front = Zend_Controller_Front::getInstance();

        // Only gate API requests
        if (!$front->getParam('api')) {
            return;
        }

        $httpRequest = $request instanceof \Zend_Controller_Request_Http ? $request : null;
        if (!$httpRequest) {
            return;
        }

        // Set CORS headers on every API response
        JwtAuth_CorsHelper::setHeaders($httpRequest, $this->getResponse());

        $claims = JwtAuth_TokenService::validateAccessCookie($httpRequest);

        if (!$claims) {
            // Access token missing or expired — attempt silent refresh
            $userId = JwtAuth_TokenService::validateRefreshCookie($httpRequest);
            if ($userId) {
                $user  = $this->_loadUser($userId);
                $tokens = JwtAuth_TokenService::issue($userId, $user->role);
                JwtAuth_CorsHelper::setAuthCookies($this->getResponse(), $tokens);
                $claims = ['user_id' => $userId];
            }
        }

        if ($claims) {
            $this->_injectCurrentUser((int) $claims['user_id']);
        }
        // No valid token: request proceeds as anonymous.
        // Omeka's ACL will return 403 for any privileged operation.
    }

    private function _injectCurrentUser(int $userId): void
    {
        $bootstrap = Zend_Registry::get('bootstrap');
        $db        = $bootstrap->getResource('Db');
        $user      = $db->getTable('User')->findActiveById($userId);

        if (!$user) {
            return;
        }

        // Replace the cached CurrentUser bootstrap resource value so that
        // Omeka's ACL checks (in ApiController::_validateUser) see our user.
        $bootstrap->getContainer()->offsetSet('currentuser', $user);
    }

    private function _loadUser(int $userId)
    {
        $db = Zend_Registry::get('bootstrap')->getResource('Db');
        return $db->getTable('User')->findActiveById($userId);
    }
}
