# Vuln - STIX 2 Vulnerabilities database

This service stores and provides records of type `vulnerability` as specified by STIX 2 (see [https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_q5ytzmajn6re])

## Prerequisites:

.Net 9

## Settings:

Open `appsettings.cs` and replace the values:

- `JwtSettings:SecretKey`

or create a `.env` file in the project root folder:

```
JwtSettings__SecretKey="W0w!NoW_tH1S*1S#a_M45t3rFuLlY@Cr4fT3D/S3CrEt?KeY!" # use your own unique key longer than 32 chars
JwtSettings__ExpirationInMinutes=15
```

Content in `.env` file will overwrite the ones in `appsettings.json`.

## Run the service locally:

### Database

```sh
docker compose db up
```

This will start a `postgres` container and will setup a port-forwarding in port `5432` and the database will be accessible via `localhost:5432`.

Default username and password can be found in `docker-compose.yml` file.

#### Setting up Database Tables

In order to run the command below, `dotnet-ef` needs to be installed. See installation instructions at (Entity Framework Core tools)[https://learn.microsoft.com/en-us/ef/core/cli/dotnet]

To setup the DB tables, run:

```sh
dotnet ef database update
```

### API Service

Run the service with:

```sh
dotnet run
```

If running in development mode, swagger UI can be accessed at `http://localhost:5079/docs/`

First, generate an authorization token by making a request to `/auth/token`. Then, make requests to other endpoints including the generated JWToken in the `Authorization` header as a Bearer token