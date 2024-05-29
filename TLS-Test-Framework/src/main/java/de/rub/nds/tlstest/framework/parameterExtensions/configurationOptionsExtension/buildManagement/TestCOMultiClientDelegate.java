/*
 *  TLS-Test-Framework - A framework for modeling TLS tests
 *
 *  Copyright 2020 Ruhr University Bochum and
 *  TÜV Informationstechnik GmbH
 *
 *  Licensed under Apache License 2.0
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

package de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.buildManagement;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlstest.framework.config.delegates.TestClientDelegate;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.buildManagement.docker.DockerClientTestContainer;
import java.io.IOException;
import java.net.ServerSocket;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

public class TestCOMultiClientDelegate extends TestClientDelegate {
    private final Map<Integer, ClientConnectionInfo> inboundPortToClientConnectionInfo;

    private Integer defaultInboundPort;

    private static class ClientConnectionInfo {
        DockerClientTestContainer clientContainer;
        private final ServerSocket serverSocket;

        public ClientConnectionInfo(DockerClientTestContainer clientContainer) {
            this.clientContainer = clientContainer;

            try {
                this.serverSocket = new ServerSocket(clientContainer.getInboundConnectionPort());
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        public DockerClientTestContainer getClientContainer() {
            return clientContainer;
        }

        public ServerSocket getServerSocket() {
            return serverSocket;
        }
    }

    public TestCOMultiClientDelegate() {
        super();
        inboundPortToClientConnectionInfo = new HashMap<>();
        defaultInboundPort = null;
        Function<State, Integer> triggerScript =
                (State state) -> {
                    InboundConnection inboundConnection =
                            state.getConfig().getDefaultServerConnection();
                    ClientConnectionInfo info =
                            this.getClientConnectionForInboundConnection(inboundConnection);
                    info.getClientContainer().sendHttpRequestToManager("trigger");
                    return 0;
                };
        this.setTriggerScript(triggerScript);
    }

    @Override
    public void applyDelegate(Config config) {
        config.setDefaultRunningMode(RunningModeType.SERVER);
    }

    public void registerNewConnection(DockerClientTestContainer clientContainer) {
        Integer inboundConnectionPort = clientContainer.getInboundConnectionPort();
        if (inboundPortToClientConnectionInfo.containsKey(inboundConnectionPort)) {
            throw new RuntimeException(
                    String.format(
                            "InboundConnection Port %d was assigned multiple times!",
                            inboundConnectionPort));
        }
        inboundPortToClientConnectionInfo.put(
                inboundConnectionPort, new ClientConnectionInfo(clientContainer));
    }

    @Override
    public ServerSocket getServerSocket() {
        throw new UnsupportedOperationException(
                "TestCOMultiClientDelegate does not support getServerSocket without any arguments");
    }

    public ServerSocket getServerSocket(Config config) {
        InboundConnection inboundConnection = config.getDefaultServerConnection();
        ClientConnectionInfo info = getClientConnectionForInboundConnection(inboundConnection);
        return info.getServerSocket();
    }

    public ServerSocket getServerSocket(int port) {
        return inboundPortToClientConnectionInfo.get(port).getServerSocket();
    }

    public void configureDefaultInboundPort(Integer defaultInboundPort) {
        this.defaultInboundPort = defaultInboundPort;
    }

    public Integer getDefaultInboundPort() {
        return defaultInboundPort;
    }

    @Override
    public void setServerSocket(ServerSocket serverSocket) {
        throw new UnsupportedOperationException(
                "TestCOMultiClientDelegate does not support setServerSocket");
    }

    private ClientConnectionInfo getClientConnectionForInboundConnection(
            InboundConnection inboundConnection) {
        if (inboundConnection == null) {
            if (defaultInboundPort == null) {
                throw new RuntimeException(
                        "No InboundConnection is given and no default connection was configured.");
            }
            return inboundPortToClientConnectionInfo.get(defaultInboundPort);
        } else {
            Integer inboundPort = inboundConnection.getPort();
            if (!inboundPortToClientConnectionInfo.containsKey(inboundPort)) {
                throw new IllegalArgumentException(
                        String.format(
                                "InboundConnection with port '%d' was not registered yet.",
                                inboundPort));
            }
            return inboundPortToClientConnectionInfo.get(inboundPort);
        }
    }
}
