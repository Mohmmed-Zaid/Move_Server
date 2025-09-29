# Use Maven to build the app
FROM maven:3.9.6-eclipse-temurin-21 AS build

WORKDIR /app

# Copy pom and download dependencies
COPY pom.xml .
RUN mvn dependency:go-offline -B

# Copy source code and build
COPY src ./src
RUN mvn clean package -DskipTests

# Run stage with JDK
FROM eclipse-temurin:21-jdk

WORKDIR /app

# Copy jar from build stage
COPY --from=build /app/target/*.jar app.jar

# Expose port (same as in application.properties, usually 8080)
EXPOSE 8080

# Start the app
ENTRYPOINT ["java", "-jar", "app.jar"]
