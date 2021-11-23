/*
 *  TLS-Test-Framework - A framework for modeling TLS tests
 *
 *  Copyright 2020 Ruhr University Bochum and
 *  TÜV Informationstechnik GmbH
 *
 *  Licensed under Apache License 2.0
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

package de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.OpenSSL;

import com.github.dockerjava.api.DockerClient;
import com.github.dockerjava.core.DockerClientBuilder;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.junit.Test;

import static org.junit.Assert.*;


public class DockerTest {

    /**
     * Checks if docker can be accessed. If this test fails make sure that docker is correctly installed.
     * If you do not used the configurationOptionsExtension you may ignore this issue.
     */
    @Test
    public void dockerCheck(){
        Logger.getRootLogger().setLevel(Level.OFF);
        DockerClient dockerClient = DockerClientBuilder.getInstance().build();
        assertNotNull(dockerClient);
    }

}
