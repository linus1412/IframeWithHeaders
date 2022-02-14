# Pass Header to IFRAME

Example app of how to pass an HTTP header to an IFRAME.

This approach could be used, for example, to pass a JWT to an app running inside an IFRAME.

## Run the app

```bash
./mvnw spring-boot:run
```

Then visit http://localhost:8080

To alter the port use

```bash
./mvnw spring-boot:run -Dspring-boot.run.arguments=--server.port=9090
```
