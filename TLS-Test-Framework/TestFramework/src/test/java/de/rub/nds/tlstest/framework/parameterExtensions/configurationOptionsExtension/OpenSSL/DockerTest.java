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
import com.github.dockerjava.api.model.Container;
import com.github.dockerjava.core.DockerClientBuilder;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.TestSiteReport;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.ConfigurationOptionValue;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.ConfigurationOptionsConfigTest;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.OpenSSL.ResultsCollector.DockerContainerLogFile;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.OpenSSL.ResultsCollector.LogFile;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionDerivationParameter.ConfigurationOptionDerivationParameter;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionDerivationParameter.DisablePskDerivation;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionsConfig.ConfigurationOptionsConfig;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;

import static org.junit.Assert.*;


public class DockerTest {

    /*private ConfigurationOptionsConfig createTestConfig(){
        String testFileContent =
                "<config>\n" +
                        "    <tlsLibraryName>OpenSSL</tlsLibraryName>\n" +
                        "    <tlsVersionName>OpenSSL_1_1_1</tlsVersionName>\n" +
                        "    <buildManager>OpenSSLBuildManager</buildManager>\n" +
                        "    <dockerConfig>\n" +
                        "        <dockerLibraryPath>/home/fabian/TLS-Docker-Library</dockerLibraryPath>\n" +
                        "        <dockerHostName>127.0.0.42</dockerHostName>\n" +
                        "        <portRange>8090-10000</portRange>\n" +
                        "        <dockerClientDestinationHost>192.168.162.242</dockerClientDestinationHost>\n" +
                        "    </dockerConfig>\n" +
                        "\n" +
                        "\n" +
                        "    <optionsToTest>\n" +
                        "        <optionEntry>\n" +
                        "            <derivationType>ConfigOptionDerivationType.DisablePSK</derivationType>\n" +
                        "            <valueTranslation type=\"Flag\">\n" +
                        "                <true>no-psk</true>\n" +
                        "                <false></false>\n" +
                        "            </valueTranslation>\n" +
                        "        </optionEntry>\n" +
                        "    </optionsToTest>\n" +
                        "</config>";




        InputStream is = new ByteArrayInputStream(testFileContent.getBytes());

        ConfigurationOptionsConfig config = new ConfigurationOptionsConfig(is);

        return config;
    }*/

    /**
     * Checks if docker can be accessed. If this test fails make sure that docker is correctly installed.
     * If you do not used the configurationOptionsExtension you may ignore this issue.
     */
    @Test
    public void dockerCheck(){

        DockerClient dockerClient = DockerClientBuilder.getInstance().build();
        assertNotNull(dockerClient);
    }

    // TODO: The following test are only temporary for development. Delete me later.
    /*@Test
    public void dockerBuildLogicTemp(){
        Logger.getRootLogger().setLevel(Level.OFF);
        //DockerClient dockerClient = DockerClientBuilder.getInstance().build();
        ConfigurationOptionsConfig config = createTestConfig();
        OpenSSLBuildManager manager = new OpenSSLBuildManager(config);
        manager.init();

        String tag = "taggTagg";

        //OpenSSLDockerHelper.buildOpenSSLImageWithFactory(manager.getDockerClient(),
        //        Arrays.asList("no-tls1_3"),
        //        tag,
        //        config.getDockerLibraryPath().resolve(Paths.get("images", "openssl", "configurationOptionsFactory", "Dockerfile_Min_OpenSSL")),
        //        "OpenSSL_1_1_1",
        //        "ccache-cache");
        DockerContainerInfo info = OpenSSLDockerHelper.createDockerServer(manager.getDockerClient(), tag, "127.0.0.42", 4433);
        OpenSSLDockerHelper.startContainer(manager.getDockerClient(), info);

        OpenSSLDockerHelper.printContainerLogDebug(manager.getDockerClient(), info.getContainerId());


    }*/

    /*@Test
    public void dockerClientTest(){
        Logger.getRootLogger().setLevel(Level.OFF);
        //DockerClient dockerClient = DockerClientBuilder.getInstance().build();
        ConfigurationOptionsConfig config = ConfigurationOptionsConfigTest.createTestConfig();
        OpenSSLBuildManager manager = new OpenSSLBuildManager(config);
        manager.init();

        String tag = "testTag";

        //OpenSSLDockerHelper.buildOpenSSLImageWithFactory(manager.getDockerClient(),
        //        Arrays.asList("no-tls1_3"),
        //        tag,
        //        config.getDockerLibraryPath().resolve(Paths.get("images", "openssl", "configurationOptionsFactory", "Dockerfile_Min_OpenSSL")),
        //        "OpenSSL_1_1_1",
        //        "ccache-cache");

        DockerContainerInfo info = OpenSSLDockerHelper.createDockerClient(manager.getDockerClient(), tag,
                "127.0.0.41", 4466, "192.168.160.1", 4433);

        DockerContainerInfo info2 = OpenSSLDockerHelper.createDockerClient(manager.getDockerClient(), tag,
                "127.0.0.41", 4467, "192.168.160.1", 4433);

        OpenSSLDockerHelper.startContainer(manager.getDockerClient(), info);
        OpenSSLDockerHelper.startContainer(manager.getDockerClient(), info2);

        OpenSSLDockerHelper.printContainerLogDebug(manager.getDockerClient(), info.getContainerId());
    }*/

    // temp
    /*@Test
    public void siteReportScanTest(){
        String tag = "taggTagg";
        OpenSSLBuildManager manager = new OpenSSLBuildManager(ConfigurationOptionsConfigTest.createTestConfig());
        manager.init();
        //DockerContainerInfo info = OpenSSLDockerHelper.createDockerContainerServer(OpenSSLBuildManager.getInstance().getDockerClient(), tag, "127.0.0.42", 4433);
        //OpenSSLDockerHelper.startContainer(OpenSSLBuildManager.getInstance().getDockerClient(), info);

        TestSiteReport report = manager.createServerSiteReport(tag);
        System.out.println(report);

    }*/

    // temp
    /*@Test
    public void fullTest(){
        OpenSSLBuildManager manager = new OpenSSLBuildManager(ConfigurationOptionsConfigTest.createTestConfig());
        manager.init();
        Config config = Config.createEmptyConfig();
        TestContext context = TestContext.getInstance();
        Set<ConfigurationOptionDerivationParameter> optionSet = new HashSet<>();
        DisablePskDerivation noPskDerivation = new DisablePskDerivation(new ConfigurationOptionValue(true));
        optionSet.add(noPskDerivation);

        TestSiteReport report = manager.configureOptionSetAndGetSiteReport(config, context, optionSet);
        System.out.println(report);
        System.out.println(config.getDefaultClientConnection().getPort());
    }*/

}
