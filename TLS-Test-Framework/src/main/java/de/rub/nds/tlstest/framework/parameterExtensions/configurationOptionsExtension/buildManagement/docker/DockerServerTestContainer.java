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
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsscanner.serverscanner.execution.TlsServerScanner;
import de.rub.nds.tlstest.framework.FeatureExtractionResult;
import de.rub.nds.tlstest.framework.ServerFeatureExtractionResult;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.config.delegates.TestServerDelegate;
import de.rub.nds.tlstest.framework.execution.TestPreparator;

/** Represents a DockerContainer that runs a tls server for testing purposes. */
public class DockerServerTestContainer extends DockerTestContainer {
    private final Integer tlsServerPort;

    /**
     * Constructor for the docker server test container.
     *
     * @param dockerClient - the docker client
     * @param dockerTag - the dockerTag of the image the container is built on
     * @param containerId - the containers id (used to identify the container with the dockerClient)
     * @param dockerHost - the host address the docker container is bound on
     * @param managerPort - the port (on the docker host) the containers manager listens for http
     *     requests (e.g. /shutdown)
     * @param tlsServerPort - the port (on the docker host) the tls server runs on
     */
    public DockerServerTestContainer(
            DockerClient dockerClient,
            String dockerTag,
            String containerId,
            String dockerHost,
            Integer managerPort,
            Integer tlsServerPort) {
        super(dockerClient, dockerTag, containerId, dockerHost, managerPort);
        this.tlsServerPort = tlsServerPort;
    }

    public Integer getTlsServerPort() {
        return tlsServerPort;
    }

    public synchronized FeatureExtractionResult createFeatureExtractionResult(
            ParallelExecutor parallelExecutor) {
        TestServerDelegate testServerDelegate = new TestServerDelegate();
        testServerDelegate.setHost(dockerHost + ":" + tlsServerPort);
        TlsServerScanner scanner =
                TestPreparator.getServerScanner(
                        new GeneralDelegate(),
                        testServerDelegate,
                        parallelExecutor,
                        TestContext.getInstance()
                                .getConfig()
                                .getAnvilTestConfig()
                                .getConnectionTimeout(),
                        false,
                        false);
        return ServerFeatureExtractionResult.fromServerScanReport(scanner.scan());
    }
}
