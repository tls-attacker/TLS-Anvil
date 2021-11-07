FROM maven:3.6-openjdk-8 as build-modifiableVariable
COPY ModifiableVariable/ /src/ModifiableVariable/
WORKDIR /src/ModifiableVariable
RUN mvn install -DskipTests

FROM maven:3.6-openjdk-8 as build-asn1-tool
COPY --from=build-modifiableVariable /root/.m2 /root/.m2/
COPY ASN.1-Tool /src/ASN.1-Tool/
WORKDIR /src/ASN.1-Tool
RUN mvn install -DskipTests

FROM maven:3.6-openjdk-8 as build-x509-attacker
COPY --from=build-asn1-tool /root/.m2 /root/.m2/
COPY X509-Attacker /src/X509-Attacker/
WORKDIR /src/X509-Attacker
RUN mvn install -DskipTests

FROM maven:3.6-openjdk-8 as build-tlsattacker
COPY --from=build-x509-attacker /root/.m2 /root/.m2/
COPY TLS-Attacker-Development /src/TLS-Attacker-Development/
WORKDIR /src/TLS-Attacker-Development
RUN mvn install -DskipTests

FROM maven:3.6-openjdk-8 as build-tlsscanner
COPY --from=build-tlsattacker /root/.m2 /root/.m2/
COPY TLS-Scanner-Development /src/TLS-Scanner-Development/
WORKDIR /src/TLS-Scanner-Development
RUN mvn install -DskipTests

FROM maven:3.6-openjdk-8 as build-testframework
COPY --from=build-tlsscanner /root/.m2/ /root/.m2/
COPY TLS-Test-Framework /src/TLS-Test-Framework/
WORKDIR /src/TLS-Test-Framework
RUN mvn install -DskipTests

FROM maven:3.6-openjdk-8 as build-testsuite
COPY --from=build-testframework /root/.m2 /root/.m2/
COPY TLS-Testsuite /src/TLS-Testsuite/
WORKDIR /src/TLS-Testsuite
RUN mvn install -DskipTests

FROM openjdk:8
RUN apt-get update && apt-get install -y tcpdump
COPY --from=build-testsuite /src/TLS-Testsuite/apps /apps/
COPY --from=build-testsuite /src/TLS-Testsuite/entrypoint.sh /apps/
ENV DOCKER=1
WORKDIR /output/
VOLUME /output
ENTRYPOINT ["/apps/entrypoint.sh"]

