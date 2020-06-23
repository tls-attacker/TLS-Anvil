FROM maven:3.6-openjdk-8 as build-modifiableVariable
COPY ModifiableVariable/ /src/ModifiableVariable/
WORKDIR /src/ModifiableVariable
RUN mvn install -DskipTests

FROM maven:3.6-openjdk-8 as build-tlsattacker
COPY --from=build-modifiableVariable /root/.m2 /root/.m2/
COPY TLS-Attacker-Development /src/TLS-Attacker-Development/
WORKDIR /src/TLS-Attacker-Development
RUN mvn install -DskipTests

FROM maven:3.6-openjdk-8 as build-tlsscanner
WORKDIR /src
RUN git clone -b 3.3.1 https://github.com/RUB-NDS/TLS-Attacker.git
WORKDIR /src/TLS-Attacker
RUN mvn install -DskipTests
COPY TLS-Scanner-Development /src/TLS-Scanner-Development/
WORKDIR /src/TLS-Scanner-Development
RUN mvn install -DskipTests

FROM maven:3.6-openjdk-8 as build-testframework
COPY --from=build-tlsscanner /root/.m2/ /root/.m2/
COPY --from=build-tlsattacker /root/.m2/ /root/.m2/
COPY TLS-Test-Framework /src/TLS-Test-Framework/
WORKDIR /src/TLS-Test-Framework
RUN mvn install -DskipTests

FROM maven:3.6-openjdk-8 as build-testsuite
COPY --from=build-testframework /root/.m2 /root/.m2/
COPY TLS-Testsuite /src/TLS-Testsuite/
WORKDIR /src/TLS-Testsuite
RUN mvn install -DskipTests

FROM java:8
COPY --from=build-testsuite /src/TLS-Testsuite/apps /apps/
WORKDIR /output/
VOLUME /output
ENTRYPOINT ["java", "-jar", "/apps/TLS-Testsuite.jar"]

