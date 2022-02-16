# Pass headers to IFRAME

Example app passing headers (including JWT) to an IFRAME.

For this example both apps (the JWT producing app and the JWT consuming app) are the same running application for simplicity.

## Run the app

if you don't have Java installed, the simplest way is via SDKMAN.  Instructions to install SDKMAN: https://sdkman.io/install

Then ```sdk install java  17.0.2-open```

After that run the project

```bash
./mvnw spring-boot:run
```

Then visit http://localhost:8080

To alter the port use

```bash
./mvnw spring-boot:run -Dspring-boot.run.arguments=--server.port=9090
```

## Pass Header to IFRAME

Visit http://localhost:8080

## Pass JWT to IFRAME

Visit http://localhost:8080/jwt
