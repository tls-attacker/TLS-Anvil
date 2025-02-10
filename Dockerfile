FROM maven:3.9.9-openjdk-21 as build-tlsanvil
COPY ./TLS-Test-Framework /src/TLS-Test-Framework/
COPY ./TLS-Testsuite /src/TLS-Testsuite/
COPY ./pom.xml /src/
WORKDIR /src/
RUN mvn install -DskipTests -Dspotless.apply.skip

FROM openjdk:21
RUN apt-get update && apt-get install -y tcpdump
COPY --from=build-tlsanvil /src/apps /apps/
ENV DOCKER=1
WORKDIR /output/
VOLUME /output
ENTRYPOINT ["java", "-jar", "/apps/TLS-Anvil.jar"]
