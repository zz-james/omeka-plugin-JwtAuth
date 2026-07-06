# JwtAuth

An Omeka Classic plugin that adds JWT-based authentication via HttpOnly cookies to the REST API.

## What it does

- Exposes `/auth/login`, `/auth/logout`, `/auth/me`, and `/auth/register` endpoints handled by a dedicated `AuthController` (outside the core Omeka API controller)
- Intercepts all `/api/*` dispatches via a Zend front controller plugin; validates the `auth_token` cookie and injects the current user into `Zend_Registry` so Omeka's existing ACL runs unchanged
- Issues short-lived access tokens (JWT, HS256, 15 min) in an `auth_token` HttpOnly cookie and long-lived refresh tokens (opaque, 30 days) in a `refresh_token` HttpOnly cookie
- Handles CORS for cross-subdomain deployments (frontend and backend on different subdomains of the same root domain)
- Leaves the legacy `?key=` API param working for server-to-server use

## Requirements

- Omeka Classic 2.0+
- PHP 7.4+
- Composer

## Installation

```bash
cd plugins/JwtAuth
composer install --no-dev
```

Activate the plugin from the Omeka admin panel. On activation it creates the `jwt_refresh_tokens` table.

## Configuration

The JWT signing secret must be set in one of two places — never hardcode it in the plugin source.

**Option 1 — `db.ini`** (or a dedicated config file readable by Omeka):

```ini
[jwtauth]
secret = "your-strong-random-secret"
```

**Option 2 — environment variable** (useful in Docker):

```
JWT_SECRET=your-strong-random-secret
```

The plugin reads the env variable as a fallback when the config key is absent.

## Cookie config

Both cookies are set `HttpOnly; Path=/`.

In production (`APPLICATION_ENV != development`): `Secure; SameSite=None` so that the frontend subdomain can send them cross-site.

In development: `SameSite=Lax`, no `Secure` flag, so they work over plain HTTP on localhost.

## API endpoints

| Method | Path             | Auth required | Description                                            |
| ------ | ---------------- | ------------- | ------------------------------------------------------ |
| POST   | `/auth/login`    | No            | Validates credentials, issues access + refresh cookies |
| POST   | `/auth/logout`   | Yes           | Revokes refresh token, clears cookies                  |
| GET    | `/auth/me`       | Yes           | Returns `{id, name, email, role}`                      |
| POST   | `/auth/register` | No            | Creates a `contributor`-role user, issues cookies      |

## Database schema

One table is added on plugin activation:

```sql
CREATE TABLE jwt_refresh_tokens (
  id          INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  token_hash  VARCHAR(128) NOT NULL UNIQUE,
  user_id     INT UNSIGNED NOT NULL,
  expires_at  DATETIME NOT NULL,
  revoked     TINYINT(1) NOT NULL DEFAULT 0,
  created_at  DATETIME NOT NULL
);
```

## Running tests

// coming soon
