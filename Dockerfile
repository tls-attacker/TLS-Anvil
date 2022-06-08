FROM maven:3.6-openjdk-11 as build-modifiableVariable
COPY ModifiableVariable/ /src/ModifiableVariable/
WORKDIR /src/ModifiableVariable
RUN mvn install -DskipTests

FROM maven:3.6-openjdk-11 as build-asn1-tool
COPY --from=build-modifiableVariable /root/.m2 /root/.m2/
COPY ASN.1-Tool /src/ASN.1-Tool/
WORKDIR /src/ASN.1-Tool
RUN mvn install -DskipTests

FROM maven:3.6-openjdk-11 as build-x509-attacker
COPY --from=build-asn1-tool /root/.m2 /root/.m2/
COPY X509-Attacker /src/X509-Attacker/
WORKDIR /src/X509-Attacker
RUN mvn install -DskipTests

FROM maven:3.6-openjdk-11 as build-tlsattacker
COPY --from=build-x509-attacker /root/.m2 /root/.m2/
COPY TLS-Attacker /src/TLS-Attacker/
WORKDIR /src/TLS-Attacker
RUN mvn install -DskipTests

FROM maven:3.6-openjdk-11 as build-tlsscanner
COPY --from=build-tlsattacker /root/.m2 /root/.m2/
COPY TLS-Scanner /src/TLS-Scanner/
WORKDIR /src/TLS-Scanner
RUN mvn install -DskipTests

FROM maven:3.6-openjdk-11 as build-tlsanvil
COPY --from=build-tlsscanner /root/.m2 /root/.m2/
COPY TLS-Anvil /src/TLS-Anvil/
WORKDIR /src/TLS-Anvil
RUN mvn install -DskipTests

FROM openjdk:11
RUN apt-get update && apt-get install -y tcpdump
COPY --from=build-tlsanvil /src/TLS-Anvil/TLS-Testsuite/apps /apps/
COPY --from=build-tlsanvil /src/TLS-Anvil/TLS-Testsuite/entrypoint.sh /apps/
ENV DOCKER=1
WORKDIR /output/
VOLUME /output
ENTRYPOINT ["/apps/entrypoint.sh"]

