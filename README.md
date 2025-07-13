# PERN Template

A minimal PERN (PostgreSQL, Express, React, Node.js) full-stack authentication template with JWT, refresh tokens, and role-based access.

## Features

- React frontend (Vite, HMR)
- Express backend with JWT authentication
- Refresh tokens (HTTP-only cookies)
- Role-based protected routes (admin/user)
- PostgreSQL database integration
- Secure password hashing (bcryptjs)
- ESLint configuration for code quality

## Project Structure

```bash
.
├── client              # React frontend
│   ├── public          # Static files
│   └── src             # React components and hooks
│
├── server              # Express backend
│   ├── config          # Configuration files
│   ├── controllers     # Route controllers
│   ├── middleware      # Custom middleware
│   ├── models          # Database models
│   ├── routes          # API routes
│   └── utils           # Utility functions
│
├── .env                # Environment variables
├── .gitignore          # Ignored files in Git
├── package.json        # Project metadata and dependencies
└── README.md           # Project documentation
```

## Getting Started

To get a local copy up and running, follow these simple steps.

### Prerequisites

- Node.js
- npm or Yarn
- PostgreSQL

### Installation

1. Clone the repo

   ```bash
   git clone https://github.com/dhia336/PERN-TEMPLATE.git
   ```

2. Install client dependencies

   ```bash
   npm install
   ```

3. Install server dependencies

   ```bash
   cd backend
   npm install
   ```

4. Configure environment variables

   Rename `.env.example` to `.env` in the server folder and update the values accordingly.

5. Run the development servers

   ```bash
   # In the server folder
   npm run dev

   # In the client folder
   npm run dev
   ```

   The client app will be running on [http://localhost:3000](http://localhost:3000) and the server on [http://localhost:5000](http://localhost:5000) by default.

### Usage

- Register a new user (admin or regular)
- Login to obtain access and refresh tokens
- Access protected routes based on your role
- Refresh your access token using the refresh token

## Acknowledgements

- [Vite](https://vitejs.dev/) - Next Generation Frontend Tooling
- [React](https://reactjs.org/) - A JavaScript library for building user interfaces
- [Express](https://expressjs.com/) - Fast, unopinionated, minimalist web framework for Node.js
- [Prisma](https://www.prisma.io/) - Next-generation ORM for Node.js and TypeScript
- [bcryptjs](https://github.com/dcodeIO/bcrypt.js) - Optimized bcrypt in JavaScript with zero dependencies
- [jsonwebtoken](https://github.com/auth0/node-jsonwebtoken) - JSON Web Token implementation for node.js
- [dotenv](https://github.com/motdotla/dotenv) - Loads environment variables from .env file
