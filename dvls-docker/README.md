# Devolutions Server Container

```powershell
docker build -f Dockerfile -t devolutions-server:test .

docker network create dvls-net

docker stop dvls-sql && docker rm dvls-sql

docker run -d --name dvls-sql --network dvls-net \
  -e "ACCEPT_EULA=Y" -e "SA_PASSWORD=SuperPass123!" \
  mcr.microsoft.com/mssql/server:2022-latest

docker run --rm -it --network dvls-net \
  -e DVLS_DB_HOST=dvls-sql \
  -e DVLS_DB_USER=sa \
  -e DVLS_DB_PASS=SuperPass123! \
  -e HOSTNAME=localhost \
  -e PORT=5001 \
  -e WEB_SCHEME=https \
  -e DVLS_INIT=true \
  -p 5001:5001 \
  devolutions-server:test
```
