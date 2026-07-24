<?php
// Module 'jwt_auth' -> ZF1 class prefix 'JwtAuth_'
class JwtAuth_AuthController extends Omeka_Controller_AbstractActionController
{
    public function init()
    {
        $this->_helper->viewRenderer->setNoRender();
        JwtAuth_CorsHelper::setHeaders($this->getRequest(), $this->getResponse());
    }

    // POST /auth/login
    public function loginAction()
    {
        if ($this->getRequest()->getMethod() === 'OPTIONS') {
            $this->getResponse()->setHttpResponseCode(204);
            return;
        }
        if (!$this->getRequest()->isPost()) {
            return $this->_sendError('Method not allowed', 405);
        }

        $body = $this->_parseJsonBody();
        if (!isset($body['email'], $body['password'])) {
            return $this->_sendError('email and password required', 422);
        }

        $user = $this->_helper->db->getTable('User')->findByEmail($body['email']);

        if (!$user || !$user->active || !password_verify($body['password'], $user->password)) {
            return $this->_sendError('Invalid credentials', 401);
        }

        $tokens = JwtAuth_TokenService::issue((int) $user->id, $user->role);
        JwtAuth_CorsHelper::setAuthCookies($this->getResponse(), $tokens);
        $this->_sendJson($this->_userPayload((int) $user->id));
    }

    // POST /auth/logout
    public function logoutAction()
    {
        if ($this->getRequest()->getMethod() === 'OPTIONS') {
            $this->getResponse()->setHttpResponseCode(204);
            return;
        }
        if (!$this->getRequest()->isPost()) {
            return $this->_sendError('Method not allowed', 405);
        }

        $refreshToken = $_COOKIE['refresh_token'] ?? null;
        if ($refreshToken) {
            JwtAuth_TokenService::revokeRefreshToken($refreshToken);
        }
        JwtAuth_CorsHelper::clearAuthCookies($this->getResponse());
        $this->getResponse()->setHttpResponseCode(204);
    }

    // GET /auth/me
    public function meAction()
    {
        if ($this->getRequest()->getMethod() === 'OPTIONS') {
            $this->getResponse()->setHttpResponseCode(204);
            return;
        }

        $claims = JwtAuth_TokenService::validateAccessCookie($this->getRequest());
        if ($claims) {
            return $this->_sendJson($this->_userPayload((int) $claims['user_id']));
        }

        // Silent refresh: expired access token but valid refresh token
        $userId = JwtAuth_TokenService::validateRefreshCookie($this->getRequest());
        if (!$userId) {
            return $this->_sendError('Unauthorized', 401);
        }

        $user = $this->_helper->db->getTable('User')->findActiveById($userId);
        if (!$user) {
            return $this->_sendError('Unauthorized', 401);
        }

        $tokens = JwtAuth_TokenService::issue((int) $user->id, $user->role);
        JwtAuth_CorsHelper::setAuthCookies($this->getResponse(), $tokens);
        $this->_sendJson($this->_userPayload((int) $user->id));
    }

    // POST /auth/register
    public function registerAction()
    {
        if ($this->getRequest()->getMethod() === 'OPTIONS') {
            $this->getResponse()->setHttpResponseCode(204);
            return;
        }
        if (!$this->getRequest()->isPost()) {
            return $this->_sendError('Method not allowed', 405);
        }

        $body     = $this->_parseJsonBody();
        $name     = isset($body['name'])     ? trim($body['name'])  : '';
        $email    = isset($body['email'])    ? trim($body['email']) : '';
        $password = $body['password'] ?? '';

        if (!$name || !$email || !$password) {
            return $this->_sendError('name, email, and password required', 422);
        }

        if ($this->_helper->db->getTable('User')->findByEmail($email)) {
            return $this->_sendError('That email address has already been claimed.', 422);
        }

        $user           = new User();
        $user->name     = $name;
        $user->email    = $email;
        $user->role     = 'contributor';
        $user->active   = 1;
        $user->username = $this->_generateUsername($email);
        $user->setPassword($password);

        try {
            $user->save();
        } catch (Omeka_Validate_Exception $e) {
            return $this->_sendError($e->getMessage(), 422);
        }

        $tokens = JwtAuth_TokenService::issue((int) $user->id, $user->role);
        JwtAuth_CorsHelper::setAuthCookies($this->getResponse(), $tokens);
        $this->_sendJson($this->_userPayload((int) $user->id), 201);
    }

    // OPTIONS preflight (CORS)
    public function optionsAction()
    {
        $this->getResponse()->setHttpResponseCode(204);
    }

    private function _parseJsonBody(): array
    {
        $raw = $this->getRequest()->getRawBody();
        return json_decode($raw, true) ?? [];
    }

    private function _sendJson(array $data, int $status = 200): void
    {
        $this->getResponse()
            ->setHttpResponseCode($status)
            ->setHeader('Content-Type', 'application/json');
        echo json_encode($data);
    }

    private function _sendError(string $message, int $status = 400): void
    {
        $this->_sendJson(['error' => $message], $status);
    }

    private function _userPayload(int $userId): array
    {
        $user = $this->_helper->db->getTable('User')->find($userId);
        return [
            'id'    => (int) $user->id,
            'name'  => $user->name,
            'email' => $user->email,
            'role'  => $user->role,
        ];
    }

    private function _generateUsername(string $email): string
    {
        $base   = substr(preg_replace('/[^a-z0-9]/', '', strtolower(explode('@', $email)[0])), 0, 28);
        $base   = $base ?: 'user';
        $table  = $this->_helper->db->getTable('User');
        $name   = $base;
        $suffix = 1;
        while ($table->findBySql('username = ?', [$name], true)) {
            $name = $base . $suffix++;
        }
        return $name;
    }
}
