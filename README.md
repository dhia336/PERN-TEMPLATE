# PERN Authentication Template

A learning project demonstrating a React/Vite frontend and an Express/PostgreSQL backend with password hashing, short-lived access tokens, refresh-token cookies, and a protected route.

> **Status:** Educational starter project, not production-ready. Review the security limitations below before adapting it for a real application.

## Stack

- React and Vite
- Node.js and Express
- PostgreSQL (`pg`)
- `bcryptjs` for password hashing
- `jsonwebtoken` for JWTs
- `cookie-parser`, `cors`, and `dotenv`

## Repository layout

- Root: React/Vite frontend
- `backend/`: Express API and PostgreSQL connection
- `backend/server.js`: registration, login, refresh, logout, and protected-route examples

## Requirements

- Node.js and npm
- PostgreSQL with the `users` and `refresh_tokens` tables expected by the backend

## Setup

### 1. Configure PostgreSQL

Create a database and the required tables. Check the schema used by your project before running the server.

### 2. Configure the backend

```bash
cd backend
npm install
```

Create `backend/.env`:

```dotenv
PORT=5000
DB_USER=your_postgres_user
DB_HOST=localhost
DB_NAME=your_database_name
DB_PORT=5432
JWT_SECRET=replace_with_a_long_random_secret
REFRESH_SECRET=use_a_different_long_random_secret
CLIENT_ORIGIN=http://localhost:5173
NODE_ENV=development
```

The current `backend/db.js` uses these `DB_*` variables and currently configures an empty PostgreSQL password. Adjust it to read a `DB_PASSWORD` environment variable before using a password-protected database; never commit real credentials.

Start the backend from `backend/`:

```bash
npm run dev
```

### 3. Start the frontend

In a second terminal, from the repository root:

```bash
npm install
npm run dev
```

Vite normally serves the frontend at `http://localhost:5173`; the API defaults to `http://localhost:5000`. Set `VITE_API_URL` in a root `.env` file if the API runs elsewhere.

## Example API routes

- `POST /register` — create a standard user
- `POST /login` — authenticate and issue tokens
- `POST /refresh` — exchange a valid refresh token for a new token pair
- `POST /logout` — revoke the current refresh token
- `GET /protected` — demonstrate access-token verification and an admin-only role check

## Security notes

- Public registration must not allow users to assign themselves privileged roles.
- Use unique, strong JWT secrets and HTTPS in production.
- Review CSRF protections, rate limiting, input validation, token rotation/reuse detection, database migrations, and error handling before production use.
- The protected example is admin-only; configure authorization deliberately for your application.

This project demonstrates authentication concepts and needs further testing and hardening before production use.