/*
 *  TLS-Test-Framework - A framework for modeling TLS tests
 *
 *  Copyright 2020 Ruhr University Bochum and
 *  TÜV Informationstechnik GmbH
 *
 *  Licensed under Apache License 2.0
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

package de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.OpenSSL.ResultsCollector;

import com.github.dockerjava.api.DockerClient;
import com.github.dockerjava.api.model.Frame;
import com.github.dockerjava.core.command.LogContainerResultCallback;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.OpenSSL.DockerContainerInfo;

import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * Used to log the output of a docker container.
 */
public class DockerContainerLogFile extends LogFile{
    private DockerClient dockerClient;

    public DockerContainerLogFile(Path folderDirectoryPath, String fileName, DockerClient dockerClient){
        super(folderDirectoryPath, fileName, "[%d]:%n%m%n");
        this.dockerClient = dockerClient;
    }

    public void logDockerContainer(DockerContainerInfo containerInfo){
        DateTimeFormatter dtf = DateTimeFormatter.ofPattern("yyyy/MM/dd HH:mm:ss");
        LocalDateTime now = LocalDateTime.now();
        String timeStamp = dtf.format(now);

        String header = String.format(
                "\n==================================\n" +
                "Output Log of Docker Container\n" +
                "Docker Tag: %s\n" +
                "Container Id: %s\n" +
                "Log Started at: %s\n" +
                "==================================\n",
                containerInfo.getDockerTag(),
                containerInfo.getContainerId(),
                timeStamp);
        log(header);

        try {
            dockerClient.logContainerCmd(containerInfo.getContainerId()).withStdOut(true).
                    withStdErr(true).withFollowStream(true).exec(new LogContainerResultCallback() {
                @Override
                public void onNext(Frame item) {
                    log(new String(item.getPayload()));
                }
            });
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
