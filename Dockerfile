FROM maven:3.6-openjdk-11 as build-modifiableVariable
COPY Dependencies/ModifiableVariable/ /src/ModifiableVariable/
WORKDIR /src/ModifiableVariable
RUN mvn install -DskipTests

FROM maven:3.6-openjdk-11 as build-asn1-tool
COPY --from=build-modifiableVariable /root/.m2 /root/.m2/
COPY Dependencies/ASN.1-Tool /src/ASN.1-Tool/
WORKDIR /src/ASN.1-Tool
RUN mvn install -DskipTests

FROM maven:3.6-openjdk-11 as build-x509-attacker
COPY --from=build-asn1-tool /root/.m2 /root/.m2/
COPY Dependencies/X.509-Attacker /src/X.509-Attacker/
WORKDIR /src/X.509-Attacker
RUN mvn install -DskipTests

FROM maven:3.6-openjdk-11 as build-tlsattacker
COPY --from=build-x509-attacker /root/.m2 /root/.m2/
COPY Dependencies/TLS-Attacker /src/TLS-Attacker/
WORKDIR /src/TLS-Attacker
RUN mvn install -DskipTests

FROM maven:3.6-openjdk-11 as build-tlsscanner
COPY --from=build-tlsattacker /root/.m2 /root/.m2/
COPY Dependencies/TLS-Scanner /src/TLS-Scanner/
WORKDIR /src/TLS-Scanner
RUN mvn install -DskipTests

FROM maven:3.6-openjdk-11 as build-tlsanvil
COPY --from=build-tlsscanner /root/.m2 /root/.m2/
COPY ./TLS-Test-Framework /src/TLS-Test-Framework/
COPY ./TLS-Testsuite /src/TLS-Testsuite/
COPY ./pom.xml /src/
WORKDIR /src/
RUN mvn install -DskipTests

FROM openjdk:11
RUN apt-get update && apt-get install -y tcpdump
COPY --from=build-tlsanvil /src/TLS-Testsuite/apps /apps/
ENV DOCKER=1
WORKDIR /output/
VOLUME /output
ENTRYPOINT ["java", "-jar", "/apps/TLS-Testsuite.jar"]

