/*
 *  TLS-Test-Framework - A framework for modeling TLS tests
 *
 *  Copyright 2020 Ruhr University Bochum and
 *  TÜV Informationstechnik GmbH
 *
 *  Licensed under Apache License 2.0
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

package de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.buildManagement.docker;

import com.github.dockerjava.api.DockerClient;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsscanner.clientscanner.config.ClientScannerConfig;
import de.rub.nds.tlsscanner.clientscanner.execution.TlsClientScanner;
import de.rub.nds.tlstest.framework.ClientFeatureExtractionResult;
import de.rub.nds.tlstest.framework.FeatureExtractionResult;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.execution.TestPreparator;

/** Represents a DockerContainer that runs tls clients for testing purposes. */
public class DockerClientTestContainer extends DockerTestContainer {

    private final String inboundConnectionHost;
    private final Integer inboundConnectionPort;

    /**
     * Constructor for the docker client test container.
     *
     * @param dockerClient - the docker client
     * @param dockerTag - the dockerTag of the image the container is built on
     * @param containerId - the containers id (used to identify the container with the dockerClient)
     * @param dockerHost - the host address the docker container is bound on
     * @param managerPort - the port (on the docker host) the containers manager listens for http
     *     requests (e.g. /trigger)
     * @param inboundConnectionHost - the host the client should connect to
     * @param inboundConnectionPort - the port the client should connect to
     */
    public DockerClientTestContainer(
            DockerClient dockerClient,
            String dockerTag,
            String containerId,
            String dockerHost,
            Integer managerPort,
            String inboundConnectionHost,
            Integer inboundConnectionPort) {
        super(dockerClient, dockerTag, containerId, dockerHost, managerPort);

        this.inboundConnectionHost = inboundConnectionHost;
        this.inboundConnectionPort = inboundConnectionPort;
    }

    public Integer getInboundConnectionPort() {
        return inboundConnectionPort;
    }

    @Override
    protected synchronized FeatureExtractionResult createFeatureExtractionResult(
            ParallelExecutor parallelExecutor) {
        ClientScannerConfig scannerConfig =
                TestPreparator.getClientScannerConfig(
                        inboundConnectionPort,
                        TestContext.getInstance()
                                .getConfig()
                                .getAnvilTestConfig()
                                .getConnectionTimeout(),
                        TestContext.getInstance()
                                .getConfig()
                                .getTestClientDelegate()
                                .getTriggerScript(),
                        TestContext.getInstance().getConfig().isUseDTLS());
        TlsClientScanner clientScanner = new TlsClientScanner(scannerConfig, parallelExecutor);
        ClientHelloMessage clientHello =
                TestPreparator.catchClientHello(parallelExecutor, inboundConnectionPort);
        ClientFeatureExtractionResult clientFeatureExtractionResult =
                ClientFeatureExtractionResult.fromClientScanReport(clientScanner.scan(), dockerTag);
        clientFeatureExtractionResult.setReceivedClientHello(clientHello);
        if (TestContext.getInstance().getReceivedClientHelloMessage() == null) {
            TestContext.getInstance().setReceivedClientHelloMessage(clientHello);
        }
        return clientFeatureExtractionResult;
    }
}
