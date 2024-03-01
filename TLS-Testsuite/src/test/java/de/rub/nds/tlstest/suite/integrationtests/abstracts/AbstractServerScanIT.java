package de.rub.nds.tlstest.suite.integrationtests.abstracts;

import com.github.dockerjava.api.command.InspectContainerCmd;
import com.github.dockerjava.api.command.InspectContainerResponse;
import com.github.dockerjava.api.model.Image;
import de.rub.nds.anvilcore.constants.TestEndpointType;
import de.rub.nds.tls.subject.ConnectionRole;
import de.rub.nds.tls.subject.TlsImplementationType;
import de.rub.nds.tls.subject.constants.TransportType;
import de.rub.nds.tls.subject.docker.DockerClientManager;
import de.rub.nds.tls.subject.docker.DockerTlsInstance;
import de.rub.nds.tls.subject.docker.DockerTlsManagerFactory;
import de.rub.nds.tlstest.framework.config.delegates.TestServerDelegate;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.Assume;

public abstract class AbstractServerScanIT extends AbstractScanIT {
    private static final Logger LOGGER = LogManager.getLogger();
    protected TestServerDelegate testServerDelegate = new TestServerDelegate();
    protected String serverName = "";

    protected Integer serverPort;

    public AbstractServerScanIT(TlsImplementationType implementationType, String version) {
        super(implementationType, ConnectionRole.SERVER, version);
    }

    @Override
    protected void setUpTest() {
        setUpServerDelegate(testServerDelegate);
        tlsConfig.setTestServerDelegate(testServerDelegate);
        tlsConfig.setTestEndpointMode(TestEndpointType.SERVER);
        anvilTestConfig.setEndpointMode(TestEndpointType.SERVER);
        super.setUpTest();
    }

    protected void setUpServerDelegate(TestServerDelegate testServerDelegate) {
        testServerDelegate.setHost(serverName + ":" + serverPort);
    }

    @Override
    protected DockerTlsInstance startDockerContainer(
            Image image,
            TlsImplementationType implementation,
            String version,
            TransportType transportType) {
        DockerTlsManagerFactory.TlsServerInstanceBuilder serverInstanceBuilder;
        if (image != null) {
            serverInstanceBuilder =
                    new DockerTlsManagerFactory.TlsServerInstanceBuilder(image, transportType);

        } else {
            serverInstanceBuilder =
                    new DockerTlsManagerFactory.TlsServerInstanceBuilder(
                                    implementation, version, transportType)
                            .pull();
        }
        try {
            serverInstanceBuilder.additionalParameters("");
            dockerInstance = serverInstanceBuilder.build();
            dockerInstance.start();
            try (InspectContainerCmd cmd =
                    DockerClientManager.getDockerClient()
                            .inspectContainerCmd(this.dockerInstance.getId())) {
                InspectContainerResponse response = cmd.exec();
                this.serverPort =
                        response.getNetworkSettings().getPorts().getBindings().keySet().stream()
                                .findFirst()
                                .get()
                                .getPort();
                this.serverName = response.getNetworkSettings().getIpAddress();
            }
            return dockerInstance;
        } catch (InterruptedException e) {
            LOGGER.error(String.format("Error while build or launching Docker container: %s", e));
            Assume.assumeNoException(e);
            return null;
        }
    }
}
