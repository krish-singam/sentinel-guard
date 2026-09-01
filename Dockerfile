# Stage 1: Build the SentinelGuard Application with Maven & Java 21
FROM maven:3.9.6-eclipse-temurin-21-alpine AS build
WORKDIR /app

# Cache Maven dependencies
COPY pom.xml .
RUN mvn dependency:go-offline -B

# Copy source code and build production jar
COPY src ./src
RUN mvn clean package -DskipTests

# Stage 2: Ultra-lightweight JRE Runtime
FROM eclipse-temurin:21-jre-alpine
WORKDIR /app

# Add unprivileged user for security compliance
RUN addgroup -S sentinel && adduser -S sentinel -G sentinel
USER sentinel

COPY --from=build /app/target/sentinel-guard-*.jar app.jar

ENV PORT=8090
ENV SPRING_PROFILES_ACTIVE=prod
EXPOSE 8090

ENTRYPOINT ["java", "-XX:+UseZGC", "-XX:+ZGenerational", "-Djava.security.egd=file:/dev/./urandom", "-jar", "app.jar"]
