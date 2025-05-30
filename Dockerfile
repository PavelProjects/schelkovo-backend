# # Сборка
# FROM maven:3.8.3-openjdk-17 AS build
# WORKDIR /app
# COPY . .
# RUN mvn clean package -T 1C
#
# # Запуск
# FROM openjdk:17.0.1-jdk-slim
# COPY --from=build /app/target/*.jar app.jar
# ENTRYPOINT ["java","-jar","app.jar"]
# EXPOSE 8080

FROM openjdk:21-jdk-slim
WORKDIR /app
COPY target/*.jar app.jar
ENTRYPOINT ["java","-jar","app.jar"]
EXPOSE 8080
