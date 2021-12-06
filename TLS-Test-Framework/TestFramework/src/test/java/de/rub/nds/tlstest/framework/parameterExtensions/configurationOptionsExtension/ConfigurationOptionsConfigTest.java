/*
 *  TLS-Test-Framework - A framework for modeling TLS tests
 *
 *  Copyright 2020 Ruhr University Bochum and
 *  TÜV Informationstechnik GmbH
 *
 *  Licensed under Apache License 2.0
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

package de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension;

import de.rub.nds.tlstest.framework.model.DerivationManager;
import de.rub.nds.tlstest.framework.model.DerivationType;
import de.rub.nds.tlstest.framework.model.derivationParameter.BasicDerivationType;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionsConfig.ConfigOptionValueTranslation;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionsConfig.ConfigurationOptionsConfig;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionsConfig.FlagTranslation;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionsConfig.PortRange;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import static org.junit.Assert.*;

public class ConfigurationOptionsConfigTest {

    @Test
    public void testOpenSSLOptionsConfig(){
        String testFileContent =
                "<config>\n" +
                "    <tlsLibraryName>OpenSSL</tlsLibraryName>\n" +
                "    <tlsVersionName>OpenSSL_1_1_1</tlsVersionName>\n" +
                "    <buildManager>OpenSSLBuildManager</buildManager>\n" +
                "    <dockerConfig>\n" +
                "        <dockerLibraryPath>/home/fabian/TLS-Docker-Library/</dockerLibraryPath>\n" +
                "        <dockerHostName>127.0.0.42</dockerHostName>\n" +
                "        <portRange>4433-5433</portRange>\n" +
                "    </dockerConfig>\n" +
                "    \n" +
                "\n" +
                "    <optionsToTest>\n" +
                "        <optionEntry>\n" +
                "            <derivationType>ConfigOptionDerivationType.DisablePSK</derivationType>\n" +
                "            <valueTranslation type=\"Flag\">\n" +
                "                <true>no_psk</true>\n" +
                "                <false></false>\n" +
                "            </valueTranslation>\n" +
                "        </optionEntry>\n" +
                "    </optionsToTest>\n" +
                "</config>";



        InputStream is = new ByteArrayInputStream(testFileContent.getBytes());

        ConfigurationOptionsConfig config = new ConfigurationOptionsConfig(is);

        assertEquals("OpenSSL", config.getTlsLibraryName());
        assertEquals("OpenSSL_1_1_1", config.getTlsVersionName());
        assertNotNull(config.getBuildManager());


        // Check docker stuff
        assertTrue(config.isDockerConfigPresent());
        assertTrue(config.getDockerLibraryPath().endsWith("Path/to/dockerLib/"));
        assertEquals("127.0.0.42", config.getDockerHostName());
        assertEquals(PortRange.fromString("4433-5433"), config.getDockerPortRange());

        // Check translation
        ConfigOptionValueTranslation translation = config.getOptionsToTranslationMap().get(ConfigOptionDerivationType.DisablePSK);
        assertNotNull(translation);
        assertTrue(translation instanceof FlagTranslation);
        FlagTranslation flagTranslation = (FlagTranslation) translation;
        assertEquals("no_psk",flagTranslation.getDataIfSet());
        assertEquals("",flagTranslation.getDataIfNotSet());
    }


}
