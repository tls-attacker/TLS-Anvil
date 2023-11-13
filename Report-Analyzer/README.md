# TLS-Anvil Report Analyzer

This web application visualizes the test report created by TLS-Anvil.
The easiest way to run this project locally is using Docker.

```shell
docker-compose up -d
```

The web application is available at [http://localhost:5000/](http://localhost:5000/). To get direct access to the MongoDB database where the test reports are stored, either use [http://localhost:8181/](http://localhost:8181/) or a MongoDB client of your choice connecting to `localhost:2701`.

For changing the URL where the application is deployed, the `docker-compose.yml` file has to be edited. The `app` container specifies a `REST_API_BASE_URL` variable, which must be changed.

## Uploading Reports

See `/src/backend/uploader/README.md`

## Development Setup

For the development, it is annoying to build the Docker container every time. The setup for this is to just use Docker for running the database. The backend and frontend web application runs locally.

1. Install dependencies

   ```
   npm install
   ```
2. Start the database

   ```
   docker-compose -f docker-compose.dev.yml up -d
   ```
3. Start the backend  
   Either run:

   ```
   npm run backend
   ```

   Or use VSCode:
   1. `STRG + SHIFT + B` select `tsc: Überwachen – tsconfig.json`
   1. Execute the `Start Backend` task in the debugger

4. Start the frontend

   ```
   npm run serve
   ```
5. Open [http://localhost:8080](http://localhost:8080)

