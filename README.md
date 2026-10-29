### Ansvar och tekniker

Auth-service ansvarar för authorization både för user och admin inom applikationen.
Det krävs ett användarnamn och lösenord för att få en token som ger access till vårt projekt. Vi
använder oss av jwtPublicKey och jwtPrivateKey för att skapa ett keyPair som vi sedan krypterar med
jwtEncoder. Det ger oss en token som authentiserar inloggaren.

Vi använder oss av Dto:er för att dölja känsliga uppgifter, det användaren får tillbaka är ett username
och en role. Vi har även CRUD-metoder för en user.

### Databas, miljövariabler och port

Vi använder neon databas och de miljövariabler vi har är JWT_PUBLIC_KEY, JWT_PRIVATE_KEY,
SPRING_DATASOURCE_USERNAME, SPRING_DATASOURCE_PASSWORD, SPRING_DATASOURCE_URL och ALLOWED_ORIGINS som
tillåter localhost://5173. SPRING_DATASOURCE_** är miljövariabler för databasen. Auth använder port 8080.

### Länkade repositories är följande:

https://github.com/MartinGruter/product-service-projekt2.git
https://github.com/MartinGruter/order-service-projekt2.git
https://github.com/MartinGruter/email-service-projekt2.git
https://github.com/AnwarAsry/gateway-service.git
https://github.com/MartinGruter/micro-services.git

### Starta applikation

Applikationen startas på macOS ./mvnw spring-boot:run och med Windows mvnw.cmd spring-boot:run medan
fronted startas med npm install och npm run dev
När allt är igång så körs frontend på localhost://5173 där den anslutar till alla andra
mikrotjänster och startar igång applikationen.