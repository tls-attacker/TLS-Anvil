package de.rub.nds.tlstest.suite.integrationtests.abstracts;

import static org.junit.jupiter.api.Assertions.*;

import com.github.dockerjava.api.command.InspectContainerCmd;
import com.github.dockerjava.api.command.InspectContainerResponse;
import com.github.dockerjava.api.model.*;
import de.rub.nds.anvilcore.constants.TestEndpointType;
import de.rub.nds.tls.subject.ConnectionRole;
import de.rub.nds.tls.subject.TlsImplementationType;
import de.rub.nds.tls.subject.constants.TransportType;
import de.rub.nds.tls.subject.docker.DockerClientManager;
import de.rub.nds.tls.subject.docker.DockerTlsClientInstance;
import de.rub.nds.tls.subject.docker.DockerTlsInstance;
import de.rub.nds.tls.subject.docker.DockerTlsManagerFactory;
import de.rub.nds.tlstest.framework.config.delegates.TestClientDelegate;
import java.io.IOException;
import java.net.ServerSocket;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opentest4j.TestAbortedException;

public abstract class AbstractClientScanIT extends AbstractScanIT {

    private static final Logger LOGGER = LogManager.getLogger();
    protected String clientHostname;
    protected Integer clientTriggerPort;
    protected Integer serverPort;
    protected TestClientDelegate testClientDelegate = new TestClientDelegate();

    public AbstractClientScanIT(TlsImplementationType tlsImplementationType, String version) {
        super(tlsImplementationType, ConnectionRole.CLIENT, version);
        clientTriggerPort = 8090;
        serverPort = findPort();
    }

    private Integer findPort() {
        try (ServerSocket serverSocket = new ServerSocket(0)) {
            assertNotNull(serverSocket);
            assertTrue(serverSocket.getLocalPort() > 0);
            return serverSocket.getLocalPort();
        } catch (IOException e) {
            fail("No port available");
            return null;
        }
    }

    @Override
    protected DockerTlsInstance startDockerContainer(
            Image image,
            TlsImplementationType implementation,
            String version,
            TransportType transportType) {
        DockerTlsManagerFactory.TlsClientInstanceBuilder clientInstanceBuilder;
        if (image != null) {
            clientInstanceBuilder =
                    new DockerTlsManagerFactory.TlsClientInstanceBuilder(image, transportType);

        } else {
            clientInstanceBuilder =
                    new DockerTlsManagerFactory.TlsClientInstanceBuilder(
                                    implementation, version, transportType)
                            .pull();
        }
        try {
            dockerInstance =
                    clientInstanceBuilder
                            .hostConfigHook(
                                    (hostConfig ->
                                            hostConfig.withExtraHosts(
                                                    "host.docker.internal:host-gateway")))
                            .ip("host.docker.internal")
                            .port(serverPort)
                            .connectOnStartup(true)
                            .build();
            dockerInstance.start();
            try (InspectContainerCmd cmd =
                    DockerClientManager.getDockerClient()
                            .inspectContainerCmd(this.dockerInstance.getId())) {
                InspectContainerResponse response = cmd.exec();
                this.clientHostname = response.getNetworkSettings().getIpAddress();
            }
            return dockerInstance;
        } catch (InterruptedException e) {
            LOGGER.error(String.format("Error while build or launching Docker container: %s", e));
            throw new TestAbortedException();
        }
    }

    @Override
    protected void setUpTest() {
        setUpClientDelegate(testClientDelegate);
        tlsConfig.setTestClientDelegate(testClientDelegate);
        tlsConfig.setTestEndpointMode(TestEndpointType.CLIENT);
        anvilTestConfig.setEndpointMode(TestEndpointType.CLIENT);
        super.setUpTest();
    }

    protected void setUpClientDelegate(TestClientDelegate testClientDelegate) {
        testClientDelegate.setPort(serverPort);
        testClientDelegate.setTriggerScript(
                state -> {
                    ((DockerTlsClientInstance) dockerInstance).connect();
                    return 0;
                });
    }
}
