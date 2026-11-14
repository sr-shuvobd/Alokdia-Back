# Alokdia High School — Backend

This folder contains the Node.js API service and MongoDB-backed admin/authentication endpoints.

## Run
1. Install Node.js (LTS) and make sure MongoDB is available.
2. Copy `.env.example` to `.env`.
3. Set `MONGODB_URI`, `SUPER_ADMIN_USERNAME`, `SUPER_ADMIN_PASSWORD`, and any email settings you use.
4. Run `npm install`
## Commands
- `npm run dev` - Run development server with auto-reload (using `tsx`)
- `npm run build` - Compile TypeScript to JavaScript in `dist/`
- `npm start` - Run the compiled server
- `npm run lint` - Check code style with ESLint

Default API port: `8765` (`DB_API_PORT` can override it).

Never commit your real `.env` file or share API keys/passwords.
