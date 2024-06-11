/*
 *  TLS-Test-Framework - A framework for modeling TLS tests
 *
 *  Copyright 2020 Ruhr University Bochum and
 *  TÜV Informationstechnik GmbH
 *
 *  Licensed under Apache License 2.0
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

package de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.buildManagement.openSSL;

import com.github.dockerjava.api.model.*;
import de.rub.nds.tls.subject.ConnectionRole;
import de.rub.nds.tls.subject.TlsImplementationType;
import de.rub.nds.tls.subject.constants.TransportType;
import de.rub.nds.tls.subject.docker.DockerTlsManagerFactory.TlsClientInstanceBuilder;
import de.rub.nds.tls.subject.docker.DockerTlsManagerFactory.TlsServerInstanceBuilder;
import de.rub.nds.tls.subject.docker.build.DockerBuilder;
import de.rub.nds.tls.subject.exceptions.CertVolumeNotFoundException;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.buildManagement.docker.*;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionsConfig.ConfigurationOptionsConfig;
import java.util.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * DockerFactory to build OpenSSL server and client containers using a two-step build procedure to
 * utilize ccache. Utilizes the files in '[TLS-Docker-Library
 * path]/images/openssl/configurationOptionsFactoryWithCoverage/'
 */
public class OpenSSLDockerFactory extends DockerFactory {

    private static final Logger LOGGER = LogManager.getLogger();

    private final String factoryRepoName;

    // Required by the docker library
    private final Volume targetVolumeCoverage = new Volume("/covVolume/");
    private final Volume targetVolumeCert = new Volume("/cert/");

    private final String volumeNameCoverage = "coverage";
    private static final int CONTAINER_PORT_TLS_SERVER = 4433;
    private static final int CONTAINER_MANAGER_PORT = 8090;

    public OpenSSLDockerFactory(ConfigurationOptionsConfig configurationOptionsConfig) {
        super(configurationOptionsConfig, "openssl_img");

        String coverageSuffix = "-cov";

        factoryRepoName = "openssl-factory" + coverageSuffix;
        BUILD_REPRO_NAME = "openssl_img" + coverageSuffix;
        CONTAINER_NAME_PREFIX = "container" + coverageSuffix;
    }

    @Override
    public void init() {
        super.init();

        try {
            DockerBuilder.getCertDataVolumeInfo();
        } catch (CertVolumeNotFoundException ex) {
            throw new RuntimeException(
                    "Docker library's certificate volume not found. The docker library must be initialized through its setup script first.");
        }
    }

    public String getFactoryImageNameAndTag(String openSSLBranchName) {
        return String.format("%s:%s", factoryRepoName, openSSLBranchName);
    }

    public DockerServerTestContainer createDockerServer(
            TlsImplementationType tlsImplementationType,
            String version,
            String buildFlags,
            String dockerHost,
            Integer dockerManagerPort,
            Integer dockerTlsPort) {
        List<PortBinding> portBindings = new LinkedList<>();

        String dockerTag =
                DockerBuilder.getDefaultTag(
                        tlsImplementationType, version, ConnectionRole.SERVER, buildFlags);
        ExposedPort exposedTlsServerPort = ExposedPort.tcp(CONTAINER_PORT_TLS_SERVER);
        portBindings.add(
                new PortBinding(
                        Ports.Binding.bindIpAndPort(
                                configOptionsConfig.getDockerHostBinding(), dockerTlsPort),
                        exposedTlsServerPort));

        ExposedPort exposedManagerPort = ExposedPort.tcp(CONTAINER_MANAGER_PORT);
        portBindings.add(
                new PortBinding(
                        Ports.Binding.bindIpAndPort(
                                configOptionsConfig.getDockerHostBinding(), dockerManagerPort),
                        exposedManagerPort));
        TransportType serverTransportType;
        if (TestContext.getInstance().getConfig().isUseDTLS()) {
            serverTransportType = TransportType.UDP;
        } else {
            serverTransportType = TransportType.TCP;
        }
        TlsServerInstanceBuilder tlsServerInstanceBuilder =
                new TlsServerInstanceBuilder(tlsImplementationType, version, serverTransportType)
                        .hostname(dockerHost)
                        .port(dockerTlsPort)
                        .additionalBuildFlags(dockerHost);

        String containerName = String.format("%s_server_%s", CONTAINER_NAME_PREFIX, dockerTag);
        String dockerContainerId =
                createDockerContainer(tlsServerInstanceBuilder, portBindings, containerName);

        return new DockerServerTestContainer(
                dockerClient,
                dockerTag,
                dockerContainerId,
                dockerHost,
                dockerManagerPort,
                dockerTlsPort);
    }

    public DockerClientTestContainer createDockerClient(
            TlsImplementationType tlsImplementationType,
            String version,
            String buildFlags,
            String dockerManagerHost,
            Integer dockerManagerPort,
            String tlsServerHost,
            Integer tlsServerPort) {

        String dockerTag =
                DockerBuilder.getDefaultTag(
                        tlsImplementationType, version, ConnectionRole.CLIENT, buildFlags);
        List<PortBinding> portBindings = new LinkedList<>();

        ExposedPort exposedManagerPort = ExposedPort.tcp(CONTAINER_MANAGER_PORT);
        portBindings.add(
                new PortBinding(
                        Ports.Binding.bindIpAndPort(
                                configOptionsConfig.getDockerHostBinding(), dockerManagerPort),
                        exposedManagerPort));

        String containerName = String.format("%s_client_%s", CONTAINER_NAME_PREFIX, dockerTag);
        TransportType clientTransportType;
        if (TestContext.getInstance().getConfig().isUseDTLS()) {
            clientTransportType = TransportType.UDP;
        } else {
            clientTransportType = TransportType.TCP;
        }
        TlsClientInstanceBuilder clientInstanceBuilder =
                new TlsClientInstanceBuilder(tlsImplementationType, version, clientTransportType)
                        .hostname(tlsServerHost)
                        .port(tlsServerPort)
                        .additionalBuildFlags(buildFlags);

        String dockerContainerId =
                createDockerContainer(clientInstanceBuilder, portBindings, containerName);

        return new DockerClientTestContainer(
                dockerClient,
                dockerTag,
                dockerContainerId,
                dockerManagerHost,
                dockerManagerPort,
                configOptionsConfig.getDockerClientDestinationHostName(),
                tlsServerPort);
    }
}
