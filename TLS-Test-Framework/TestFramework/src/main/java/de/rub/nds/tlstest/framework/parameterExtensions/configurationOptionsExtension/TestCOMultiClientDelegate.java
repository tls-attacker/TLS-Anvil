package de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlstest.framework.config.delegates.TestClientDelegate;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.ServerSocket;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

public class TestCOMultiClientDelegate extends TestClientDelegate {

    private static final Logger LOGGER = LogManager.getLogger();

    private ServerSocket serverSocket;

    //private Map<Integer,ServerSocket> inboundPortToServerSocket;
    private Map<Integer,ClientConnectionInfo> inboundPortToClientConnectionInfo;

    private String triggerRequest = "trigger"; // "http://<host>:<port>/<triggerRequest>"

    private Integer defaultInboundPort;

    private class ClientConnectionInfo {
        private String clientHttpHost;
        private Integer clientHttpPort;
        private Integer inboundConnectionPort;

        private ServerSocket serverSocket;

        public ClientConnectionInfo(String clientHttpHost, Integer clientHttpPort, Integer inboundConnectionPort) {
            this.clientHttpHost = clientHttpHost;
            this.clientHttpPort = clientHttpPort;
            this.inboundConnectionPort = inboundConnectionPort;

            try {
                this.serverSocket = new ServerSocket(inboundConnectionPort);
            }
            catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        public String getClientHttpHost() { return clientHttpHost; }

        public void setClientHttpHost(String clientHttpHost) { this.clientHttpHost = clientHttpHost; }

        public Integer getClientHttpPort() { return clientHttpPort; }

        public void setClientHttpPort(Integer clientHttpPort) { this.clientHttpPort = clientHttpPort; }

        public ServerSocket getServerSocket() {
            return serverSocket;
        }

        public URL getTriggerUrl(String triggerRequest){
            String httpUrl = String.format("http://%s:%d/%s", clientHttpHost, clientHttpPort, triggerRequest);
            URL url;
            try{
                url = new URL(httpUrl);
            }
            catch(MalformedURLException e){
                throw new RuntimeException(String.format("URL '%s' is malformed", httpUrl));
            }
            return url;
        }

    }

    public TestCOMultiClientDelegate(){
        super();
        inboundPortToClientConnectionInfo = new HashMap<>();
        defaultInboundPort = null;

        Function<State, Integer> triggerScript = (State state) -> {
            InboundConnection inboundConnection = state.getConfig().getDefaultServerConnection();
            ClientConnectionInfo info = this.getClientConnectionForInboundConnection(inboundConnection);

            sendHttpRequest(info.getTriggerUrl(this.triggerRequest));

            return 0;
        };
        this.setTriggerScript(triggerScript);
    }

    @Override
    public void applyDelegate(Config config) {
    }

    public void registerNewConnection(String clientHttpHost, Integer clientHttpPort, Integer inboundConnectionPort){
        if(inboundPortToClientConnectionInfo.containsKey(inboundConnectionPort)){
            throw new RuntimeException(String.format("InboundConnection Port %d was assigned multiple times!", inboundConnectionPort));
        }
        inboundPortToClientConnectionInfo.put(inboundConnectionPort, new ClientConnectionInfo(clientHttpHost, clientHttpPort, inboundConnectionPort));
    }

    @Override
    public ServerSocket getServerSocket() {
        throw new UnsupportedOperationException("TestCOMultiClientDelegate does not support getServerSocket without any arguments");
    }

    public ServerSocket getServerSocket(Config config){
        InboundConnection inboundConnection = config.getDefaultServerConnection();
        ClientConnectionInfo info = getClientConnectionForInboundConnection(inboundConnection);
        return info.getServerSocket();
    }

    public void configureDefaultInboundPort(Integer defaultInboundPort) {
        this.defaultInboundPort = defaultInboundPort;
    }

    public Integer getDefaultInboundPort() {
        return defaultInboundPort;
    }

    @Override
    public void setServerSocket(ServerSocket serverSocket) {
        throw new UnsupportedOperationException("TestCOMultiClientDelegate does not support setServerSocket");
    }

    public String getTriggerRequest() {
        return triggerRequest;
    }

    public void setTriggerRequest(String triggerRequest) {
        this.triggerRequest = triggerRequest;
    }

    private ClientConnectionInfo getClientConnectionForInboundConnection(InboundConnection inboundConnection){
        if(inboundConnection == null){
            if(defaultInboundPort == null){
                throw new RuntimeException("No InboundConnection is given and no default connection was configured.");
            }
            return inboundPortToClientConnectionInfo.get(defaultInboundPort);
        }
        else{
            Integer inboundPort = inboundConnection.getPort();
            if(!inboundPortToClientConnectionInfo.containsKey(inboundPort)){
                throw new IllegalArgumentException(String.format("InboundConnection with port '%d' was not registered yet.", inboundPort));
            }
            return inboundPortToClientConnectionInfo.get(inboundPort);
        }
    }

    private static void sendHttpRequest(URL url){
        final int MAX_ATTEMPTS = 3;
        final int ATTEMPT_DELAY = 2000;//ms

        boolean connected;
        int attempts = 0;

        do
        {
            try{
                HttpURLConnection http = (HttpURLConnection)url.openConnection();
                http.disconnect();
                int responseCode = http.getResponseCode();
                if(responseCode != 200){
                    LOGGER.warn(String.format("Client docker container at '%s' cannot be triggered. Response Code: %i. Try new attempt.", url.toString(), responseCode));
                    connected = false;
                }
                else{
                    connected = true;
                }
            }
            catch(Exception e){
                //LOGGER.warn(String.format("Client docker container at '%s' cannot be triggered.", url.toString()));
                connected = false;
            }
            if(!connected){
                attempts += 1;
                if(attempts > MAX_ATTEMPTS){
                    throw new RuntimeException("Cannot send http request to client docker container.");
                }
                try{
                    Thread.sleep(ATTEMPT_DELAY);
                }
                catch(Exception e){
                    e.printStackTrace();
                }
            }
        }
        while(!connected);

    }
    
}
