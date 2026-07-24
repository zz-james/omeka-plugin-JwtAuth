<?php
// Module 'jwt_auth' -> ZF1 class prefix 'JwtAuth_'
class JwtAuth_AuthController extends Omeka_Controller_AbstractActionController
{
    // Bcrypt hash of a random throwaway string. Verified against when the
    // email is unknown so response timing doesn't reveal account existence.
    private const DUMMY_HASH = '$2y$10$Oe1RlAaYfiYhx/fCo2ORBucShEay0rAorbkQz1DkS.JP8QZ3G1Vz.';

    private const PASSWORD_MIN_LENGTH = 8;

    public function init()
    {
        $this->_helper->viewRenderer->setNoRender();
        // Auth responses carry credentials and user data — never cacheable
        $this->getResponse()->setHeader('Cache-Control', 'no-store');
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
        if (!$this->_isJsonRequest()) {
            return $this->_sendError('Content-Type must be application/json', 415);
        }

        $body = $this->_parseJsonBody();
        if (!isset($body['email'], $body['password'])
            || !is_string($body['email']) || !is_string($body['password'])
        ) {
            return $this->_sendError('email and password required', 422);
        }

        $ipKey    = 'login:ip:' . $this->_clientIp();
        $emailKey = 'login:email:' . hash('sha256', strtolower(trim($body['email'])));
        if (JwtAuth_RateLimiter::tooManyAttempts($ipKey, 20, 900)
            || JwtAuth_RateLimiter::tooManyAttempts($emailKey, 5, 900)
        ) {
            return $this->_sendError('Too many attempts. Try again later.', 429);
        }

        $user = $this->_helper->db->getTable('User')->findByEmail($body['email']);

        // Always run bcrypt so unknown emails take as long as wrong passwords
        $hash          = $user ? $user->password : self::DUMMY_HASH;
        $passwordValid = password_verify($body['password'], $hash);

        if (!$user || !$user->active || !$passwordValid) {
            JwtAuth_RateLimiter::hit($ipKey);
            JwtAuth_RateLimiter::hit($emailKey);
            return $this->_sendError('Invalid credentials', 401);
        }

        JwtAuth_RateLimiter::clear($emailKey);
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
        // CSRF guard: cross-site HTML forms cannot send application/json
        if (!$this->_isJsonRequest()) {
            return $this->_sendError('Content-Type must be application/json', 415);
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
            $payload = $this->_userPayload((int) $claims['user_id']);
            if ($payload) {
                return $this->_sendJson($payload);
            }
            // User deactivated or deleted since the token was issued —
            // fall through to the refresh path, which re-checks the DB
            // and returns 401.
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

        $tokens = JwtAuth_TokenService::rotate(
            (int) $user->id,
            $user->role,
            $_COOKIE['refresh_token']
        );
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
        if (!$this->_isJsonRequest()) {
            return $this->_sendError('Content-Type must be application/json', 415);
        }

        $ipKey = 'register:ip:' . $this->_clientIp();
        if (JwtAuth_RateLimiter::tooManyAttempts($ipKey, 5, 3600)) {
            return $this->_sendError('Too many attempts. Try again later.', 429);
        }
        JwtAuth_RateLimiter::hit($ipKey);

        $body     = $this->_parseJsonBody();
        $name     = is_string($body['name'] ?? null)  ? trim($body['name'])  : '';
        $email    = is_string($body['email'] ?? null) ? trim($body['email']) : '';
        $password = is_string($body['password'] ?? null) ? $body['password'] : '';

        if (!$name || !$email || !$password) {
            return $this->_sendError('name, email, and password required', 422);
        }

        if (strlen($password) < self::PASSWORD_MIN_LENGTH) {
            return $this->_sendError(
                'Password must be at least ' . self::PASSWORD_MIN_LENGTH . ' characters.',
                422
            );
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

    // Returns null when the user no longer exists or has been deactivated,
    // so a still-valid JWT can't represent a disabled account.
    private function _userPayload(int $userId): ?array
    {
        $user = $this->_helper->db->getTable('User')->findActiveById($userId);
        if (!$user) {
            return null;
        }
        return [
            'id'    => (int) $user->id,
            'name'  => $user->name,
            'email' => $user->email,
            'role'  => $user->role,
        ];
    }

    private function _isJsonRequest(): bool
    {
        $contentType = $this->getRequest()->getHeader('Content-Type') ?? '';
        return stripos($contentType, 'application/json') === 0;
    }

    private function _clientIp(): string
    {
        // false = do not trust X-Forwarded-For (spoofable without a
        // configured trusted proxy)
        return $this->getRequest()->getClientIp(false) ?: 'unknown';
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
