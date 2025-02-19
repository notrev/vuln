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

## Run the service:

From the project root folder, run
```sh
dotnet run
```

Access swagger interface at `http://localhost:5079/docs/`

First, generate an authorization token by making a request to `/auth/token`. Then, make request to other endpoints including the generated JWToken in the `Authorization` header as a Bearer token