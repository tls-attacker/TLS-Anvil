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
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.ConfigurationOptionValue;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.ConfigurationOptionsConfigTest;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.OpenSSL.ResultsCollector.OpenSSLConfigOptionsResultsCollector;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionDerivationParameter.ConfigurationOptionDerivationParameter;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionDerivationParameter.DisablePskDerivation;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionsConfig.ConfigurationOptionsConfig;
import org.junit.Test;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashSet;
import java.util.Set;


public class ResultsCollectorTest {

    /*public static OpenSSLConfigOptionsResultsCollector getTestCollector(){
        final ConfigurationOptionsConfig config = ConfigurationOptionsConfigTest.createTestConfig();
        final Path collectorLogPath = Paths.get("/home/fabian/Testsuite/TLS-Anvil/TLS-Test-Framework/TestFramework/misc");

        DockerClient dockerClient = DockerClientBuilder.getInstance().build();
        OpenSSLConfigOptionsResultsCollector collector = new OpenSSLConfigOptionsResultsCollector(collectorLogPath, config, dockerClient);
        return collector;
    }

    @Test
    public void resultsCollectorFSCheck(){
        OpenSSLConfigOptionsResultsCollector collector = getTestCollector();

    }

    @Test
    public void resultsCollectorOverviewCheck(){
        OpenSSLConfigOptionsResultsCollector collector = getTestCollector();
        Set<ConfigurationOptionDerivationParameter> optionSet = new HashSet<>();
        optionSet.add(new DisablePskDerivation(new ConfigurationOptionValue(true)));

        collector.logNewOpenSSLBuildCreated(optionSet, "myDockerTag", 1234);

        optionSet = new HashSet<>();
        optionSet.add(new DisablePskDerivation(new ConfigurationOptionValue(false)));

        collector.logNewOpenSSLBuildCreated(optionSet, "myOtherTag", 4321);


    }*/


}
