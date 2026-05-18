# Authentication — AI Skill Reference

> Module: `auth` | Router: `app/routers/auth.py` | Version: api_v1.9.6-7

## Overview

Handles JWT-based authentication for the Samba AD DC Management API. Supports login with username/password, token refresh, current user inspection, and credential validation. All other API modules require a valid JWT obtained through this module.

## Endpoints

| Method | Path | Permission | Description |
|--------|------|------------|-------------|
| POST | `/api/v1/auth/login` | _(none)_ | Authenticate and receive JWT access + refresh tokens |
| POST | `/api/v1/auth/refresh` | _(none)_ | Refresh an expired access token using a valid refresh token |
| GET | `/api/v1/auth/me` | `auth.me` | Get the currently authenticated user's profile and permissions |
| POST | `/api/v1/auth/check` | `auth.check` | Validate credentials without issuing a token |

## Key Parameters

| Parameter | Type | Used In | Description |
|-----------|------|---------|-------------|
| `username` | string | `/login`, `/check` | AD username (sAMAccountName or UPN) |
| `password` | string | `/login`, `/check` | User password |
| `refresh_token` | string | `/refresh` | Valid refresh token from a previous login |

## Usage Examples

```bash
# Login and obtain JWT tokens
curl -s -X POST https://dc.example.com/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "administrator", "password": "S3cur3P@ss"}'

# Refresh an expired access token
curl -s -X POST https://dc.example.com/api/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "eyJhbGciOiJIUzI1NiIs..."}'

# Get current user info and permissions
curl -s -H "Authorization: Bearer $TOKEN" \
  https://dc.example.com/api/v1/auth/me
```

## Batch Methods

Not available in batch operations.

## Notes

- The `/login` endpoint is the only one that does not require a JWT.
- Access tokens have a configurable expiration (default: 15–30 minutes). Refresh tokens last longer.
- `/check` validates credentials against AD but does not return a token — useful for verifying a user's password without creating a session.
- `/me` returns the user's assigned permissions, which can be used to conditionally enable/disable UI features.
