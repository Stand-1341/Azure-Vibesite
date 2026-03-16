# Azure Vibesite

Azure Vibesite is a forum app with a retro terminal look. It has:

- A React + TypeScript frontend (`frontend/`)
- A Node/Express backend (`backend/`)
- Azure SQL for persistent data
- Azure Blob Storage for uploaded images

If you just want to run it locally, you can do that without deploying anything first.

## Project structure

```text
frontend/   React client app
backend/    Express API + database/image integration
```

## Requirements

- Node.js 20+
- npm
- An Azure SQL database
- An Azure Storage account (for image uploads)

## 1) Backend setup

Create `backend/.env`:

```ini
PORT=5000
FRONTEND_URL=http://localhost:3000

DB_SERVER=<server>.database.windows.net
DB_PORT=1433
DB_USER=<db-user>
DB_PASSWORD=<db-password>
DB_DATABASE=<db-name>
DB_ENCRYPT=true
DB_TRUST_SERVER_CERTIFICATE=false

AZURE_STORAGE_CONNECTION_STRING=<connection-string>
AZURE_IMAGE_CONTAINER=post-images

JWT_SECRET=<long-random-secret>
JWT_EXPIRES_IN=1h
NODE_ENV=development
```

Install and run:

```bash
cd backend
npm ci
npm start
```

Backend runs on `http://localhost:5000`.

## 2) Database setup

The backend now auto-applies `backend/combined_schema.sql` during startup, so required tables/columns are created if missing.

If you prefer to apply schema manually (or troubleshoot), you can still run:

```bash
sqlcmd -S <server>.database.windows.net -d <db> -U <user> -P "<password>" -i backend/combined_schema.sql
```

Optional: make your account admin:

```sql
UPDATE dbo.Users SET role = 'admin' WHERE username = '<your_username>';
```

## 3) Frontend setup

Create `frontend/.env.development`:

```ini
REACT_APP_API_URL=http://localhost:5000/api
```

Install and run:

```bash
cd frontend
npm ci
npm start
```

Frontend runs on `http://localhost:3000`.

## Build check

To verify the frontend compiles:

```bash
cd frontend
npm run build
```

## Notes

- The frontend API base URL now comes from `REACT_APP_API_URL`.
- If `REACT_APP_API_URL` is not set, it falls back to `http://localhost:5000/api`.
- On backend startup, the app applies `backend/combined_schema.sql` automatically.
- Keep `.env` files out of source control.
