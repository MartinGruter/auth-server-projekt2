FROM eclipse-temurin:17-jre
WORKDIR /app
COPY target/auth-server-projekt2-1.0.0.jar app.jar
EXPOSE 8080
ENTRYPOINT ["java", "-Xmx350m", "-Xss512k", "-XX:MaxMetaspaceSize=100m", "-jar", "app.jar"]