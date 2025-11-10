FROM gradle:8.10.2-jdk21 AS builder
WORKDIR /app

COPY build.gradle settings.gradle ./
COPY gradle gradle
COPY src src

RUN gradle clean build -x test --no-daemon

FROM eclipse-temurin:21-jdk
WORKDIR /app

COPY --from=builder /app/build/libs/*.jar app.jar

EXPOSE 8090

ENV SPRING_PROFILES_ACTIVE=dev
ENV CONFIG_SERVER_URI=http://config-server:8888
ENV EUREKA_URI=http://eureka-server:8761/eureka/
ENV JWT_SECRET=VvQ4uF5t+HhX0fG6oA9/eJ7hR5t7yL1D3kG9QxT4zC2o=

ENTRYPOINT ["java", "-jar", "app.jar"]