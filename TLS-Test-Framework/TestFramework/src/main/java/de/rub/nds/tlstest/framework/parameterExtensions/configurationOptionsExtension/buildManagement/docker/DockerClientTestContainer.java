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
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.TestSiteReport;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.buildManagement.TestSiteReportFactory;

/**
 * Represents a DockerContainer that runs tls clients for testing purposes.
 */
public class DockerClientTestContainer extends DockerTestContainer {

    private String inboundConnectionHost;
    private Integer inboundConnectionPort;

    /**
     * Constructor for the docker client test container.
     *
     * @param dockerClient - the docker client
     * @param dockerTag - the dockerTag of the image the container is built on
     * @param containerId - the containers id (used to identify the container with the dockerClient)
     * @param dockerHost - the host address the docker container is bound on
     * @param managerPort - the port (on the docker host) the containers manager listens for http requests (e.g. /trigger)
     * @param inboundConnectionHost - the host the client should connect to
     * @param inboundConnectionPort - the port the client should connect to
     */
    public DockerClientTestContainer(DockerClient dockerClient, String dockerTag, String containerId,
                                     String dockerHost, Integer managerPort, String inboundConnectionHost, Integer inboundConnectionPort)
    {
        super(dockerClient, dockerTag, containerId, dockerHost, managerPort);

        this.inboundConnectionHost = inboundConnectionHost;
        this.inboundConnectionPort = inboundConnectionPort;
    }

    public Integer getInboundConnectionPort() {
        return inboundConnectionPort;
    }

    @Override
    protected synchronized TestSiteReport createSiteReport(){
        InboundConnection inboundConnection = new InboundConnection(inboundConnectionPort, inboundConnectionHost);
        TestSiteReport report = TestSiteReportFactory.createClientSiteReport(TestContext.getInstance().getConfig(), inboundConnection, false);
        return report;
    }

}
