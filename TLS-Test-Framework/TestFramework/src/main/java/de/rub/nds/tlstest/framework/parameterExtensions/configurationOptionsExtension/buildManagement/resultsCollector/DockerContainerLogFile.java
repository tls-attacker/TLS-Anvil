/*
 *  TLS-Test-Framework - A framework for modeling TLS tests
 *
 *  Copyright 2020 Ruhr University Bochum and
 *  TÜV Informationstechnik GmbH
 *
 *  Licensed under Apache License 2.0
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

package de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.buildManagement.resultsCollector;

import com.github.dockerjava.api.async.ResultCallback;
import com.github.dockerjava.api.model.Frame;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.buildManagement.docker.*;

import java.io.Closeable;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Used to log the output of a docker container.
 */
public class DockerContainerLogFile extends LogFile{

    private final DockerContainer dockerContainer;
    private boolean loggingIsActive;

    public DockerContainerLogFile(Path folderDirectoryPath, String fileName, DockerContainer dockerContainer){
        super(folderDirectoryPath, fileName, "%m");
        this.dockerContainer = dockerContainer;
        loggingIsActive = false;
        initContainerLogging();
    }

    /**
     * Somehow the logging must be enabled after every container start. (Currently a docker bug (or so it seems))
     */
    public void notifyContainerStart(){
        //startLogging();
    }

    private void initContainerLogging(){
        DateTimeFormatter dtf = DateTimeFormatter.ofPattern("yyyy/MM/dd HH:mm:ss");
        LocalDateTime now = LocalDateTime.now();
        String timeStamp = dtf.format(now);

        List<String> infoFields = new ArrayList<>(Arrays.asList(
                "Output Log of Docker Container",
                String.format("Docker Tag: %s", dockerContainer.getDockerTag()),
                String.format("Container Id: %s", dockerContainer.getContainerId()),
                String.format("Log Started at: %s", timeStamp)
        ));

        if(dockerContainer instanceof DockerTestContainer){
            DockerTestContainer testContainerInfo = (DockerTestContainer) dockerContainer;
            infoFields.add(String.format("Docker Host: %s", testContainerInfo.getDockerHost()));
            if(testContainerInfo instanceof DockerClientTestContainer){
                DockerClientTestContainer clientTestContainerInfo = (DockerClientTestContainer) testContainerInfo;
                infoFields.add("Type: Client Container");
                infoFields.add(String.format("InboundConnectionPort: %d", clientTestContainerInfo.getInboundConnectionPort()));
            }
            else if(testContainerInfo instanceof DockerServerTestContainer){
                DockerServerTestContainer serverTestContainerInfo = (DockerServerTestContainer) testContainerInfo;
                infoFields.add("Type: Server Container");
                infoFields.add(String.format("TLS Server Port: %d", serverTestContainerInfo.getTlsServerPort()));
            }
            infoFields.add(String.format("Manager Port: %d", testContainerInfo.getManagerPort()));
        }


        String header = String.format(
                "\n==================================\n" +
                "%s\n" +
                "==================================\n",
                String.join("\n", infoFields) );

        log(header);
        startLogging();

    }

    private void startLogging(){
        if(!loggingIsActive){
            ResultCallback<Frame> rc = getNewResultsCallback();
            dockerContainer.getDockerClient().logContainerCmd(dockerContainer.getContainerId()).withStdOut(true).
                    withStdErr(true).withFollowStream(true).withTimestamps(true).exec(rc);
            loggingIsActive = true;
        }

    }

    private ResultCallback<Frame> getNewResultsCallback(){
        return new ResultCallback<Frame>() {
            @Override
            public void onStart(Closeable closeable) {
                log("== Container started ==\n");
            }

            @Override
            public void onNext(Frame object) {
                log(new String(object.getPayload()));
            }

            @Override
            public void onError(Throwable throwable) {

            }

            @Override
            public void onComplete() {
                log("== Container stopped ==\n");
                //loggingIsActive = false;
            }

            @Override
            public void close() {

            }
        };
    }

}
