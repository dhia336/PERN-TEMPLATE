# PERN Authentication Template

A learning project demonstrating a React/Vite frontend and an Express/PostgreSQL backend with password hashing, short-lived access tokens, refresh-token cookies, and a protected route.

> **Status:** Educational starter project, not a production-ready authentication system. Review the security notes before using it for a real application.

## Stack

- React and Vite
- Node.js and Express
- PostgreSQL (pg)
- bcryptjs for password hashing
- jsonwebtoken for JWTs
- cookie-parser, cors, and dotenv

## Repository layout

- Root: React/Vite frontend
- backend/: Express API and database connection
- backend/server.js: registration, login, refresh, logout, and protected-route examples

## Requirements

- Node.js and npm
- PostgreSQL
- A PostgreSQL database with the tables expected by backend/db.js

## Setup

### 1. Configure the backend

    cd backend
    npm install

Create backend/.env with values appropriate for your local PostgreSQL setup:

    PORT=5000
    DATABASE_URL=postgresql://USER:PASSWORD@localhost:5432/DATABASE_NAME
    JWT_SECRET=replace-with-a-long-random-secret
    REFRESH_SECRET=replace-with-a-different-long-random-secret
    NODE_ENV=development

Check backend/db.js and the database schema in the repository to confirm which database environment variables and tables the implementation expects. Never commit real secrets.

Start the API from the backend/ directory:

    npm run dev

### 2. Configure and start the frontend

From the repository root, in a second terminal:

    npm install
    npm run dev

Vite normally serves the frontend at http://localhost:5173. The example frontend calls the API at http://localhost:5000.

## Example routes

- POST /register — create a user
- POST /login — authenticate and issue tokens
- POST /refresh — exchange a valid refresh token for a new token pair
- POST /logout — revoke a refresh token
- GET /protected — demonstrate access-token verification and role checks

## Security limitations

- The frontend currently contains demo login credentials; replace this with a real login form before presenting the app as a reusable template.
- Registration currently accepts a role from the request body. A public registration endpoint must not allow users to assign themselves privileged roles.
- Review refresh-token rotation, cookie clearing, CSRF protections, rate limiting, validation, database migrations, and secret configuration before production use.
- The example protected endpoint is admin-only; adjust authorization deliberately rather than removing the role check.

This repository demonstrates authentication concepts and needs further hardening before production use.