FROM maven:3.9.9-eclipse-temurin-21-jammy as build-tlsanvil
COPY ./TLS-Test-Framework /src/TLS-Test-Framework/
COPY ./TLS-Testsuite /src/TLS-Testsuite/
COPY ./pom.xml /src/
WORKDIR /src/
RUN mvn install -DskipTests -Dspotless.apply.skip

FROM eclipse-temurin:21
RUN apt update && apt install -y tcpdump
COPY --from=build-tlsanvil /src/apps /apps/
ENV DOCKER=1
WORKDIR /output/
VOLUME /output
ENTRYPOINT ["java", "-jar", "/apps/TLS-Anvil.jar"]
