# Superset fork for Fugro

## How to install and run a development version

1. If you have superset-related containers from before, back up what is needed, and remove those containers with e.g. `docker container rm superset_worker_beat superset_app superset_worker superset_node superset_init superset_db superset_tests_worker superset_nginx superset_cache`
2. Ensure that Python 3.11 is installed and

   - if on linux, python3 points to that Python version
   - if on Windows, that Python version is the version in your Path env var

3. Inside the superset-frontend dir:

   - `npm install`
   - if on Windows:
     - Get zstd from [here](https://github.com/facebook/zstd/releases), install it, and put it in the Path env var
     - `npm install simple-zstd`
   - To build assets, run `npm run dev`, wait until it builds what it needs to, then terminate it

4. Run with `docker compose -f docker-compose.yml up` (this also builds and installs things and may take several, even 10-20 minutes)

   - In case of an error saying "Invalid decryption key", you may need to re-encrypt database credentials with e.g.`UPDATE dbs SET password = null, encrypted_extra = null WHERE database_name = 'examples';` in your "superset" DB
   - In case of an error saying "password authentication failed" with regards to the DB, you may need to set the "examples" DB user's password back to what it was before, with e.g. `ALTER USER examples WITH PASSWORD '<previous password>';` (for the original password used by superset for the "examples" user, see the env vars)

5. Access at `http://localhost:8088`
