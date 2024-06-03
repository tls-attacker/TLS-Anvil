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

import static org.junit.Assert.*;

import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionDerivationParameter.SeedingMethodDerivation;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionsConfig.*;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import org.junit.Test;

public class ConfigurationOptionsConfigTest {
    public static ConfigurationOptionsConfig createTestConfig() {
        String testFileContent =
                "<config>\n"
                        + "    <tlsLibraryName>OpenSSL</tlsLibraryName>\n"
                        + "    <tlsVersionName>OpenSSL_1_1_1</tlsVersionName>\n"
                        + "    <buildManager>OpenSSLBuildManager</buildManager>\n"
                        + "    <dockerConfig>\n"
                        + "        <dockerLibraryPath>/Path/to/dockerLib/</dockerLibraryPath>\n"
                        + "        <dockerHostBinding>127.0.0.41</dockerHostBinding>\n"
                        + "        <dockerHostName>127.0.0.42</dockerHostName>\n"
                        + "        <portRange>4433-5433</portRange>\n"
                        + "        <dockerClientDestinationHost>172.26.103.178</dockerClientDestinationHost>\n"
                        + "    </dockerConfig>\n"
                        + "    <disableSiteReportConsoleLog>false</disableSiteReportConsoleLog>\n"
                        + "   <maxSimultaneousBuilds>3</maxSimultaneousBuilds>\n"
                        + "    <maxRunningContainers>42</maxRunningContainers>\n"
                        + "\n"
                        + "    <optionsToTest>\n"
                        + "        <optionEntry>\n"
                        + "            <derivationType>ConfigOptionDerivationType.DisablePsk</derivationType>\n"
                        + "            <enabled>true</enabled>\n"
                        + "            <valueTranslation type=\"Flag\">\n"
                        + "                <true>no-psk</true>\n"
                        + "                <false></false>\n"
                        + "            </valueTranslation>\n"
                        + "        </optionEntry>\n"
                        + "\n"
                        + "        <optionEntry>\n"
                        + "            <derivationType>ConfigOptionDerivationType.SeedingMethod</derivationType>\n"
                        + "            <valueTranslation type=\"SingleValueOption\">\n"
                        + "                <identifier>--with-rand-seed</identifier>\n"
                        + "                <value key=\"OsEntropySource\">os</value>\n"
                        + "                <value key=\"GetRandom\">getrandom</value>\n"
                        + "                <value key=\"DevRandom\">devrandom</value>\n"
                        + "                <value key=\"EntropyGeneratingDaemon\">egd</value>\n"
                        + "                <value key=\"CpuCommand\">rdcpu</value>\n"
                        + "                <value key=\"None\">none</value>\n"
                        + "\n"
                        + "            </valueTranslation>\n"
                        + "        </optionEntry>\n"
                        + "\n"
                        + "    </optionsToTest>\n"
                        + "</config>";

        InputStream is = new ByteArrayInputStream(testFileContent.getBytes());

        ConfigurationOptionsConfig config = new ConfigurationOptionsConfig(is);

        return config;
    }

    @Test
    public void testOpenSSLOptionsConfig() {
        ConfigurationOptionsConfig config = createTestConfig();

        assertEquals("OpenSSL", config.getTlsLibraryName());
        assertEquals("OpenSSL_1_1_1", config.getTlsVersionName());
        assertNotNull(config.getBuildManager());

        // Check docker stuff
        assertTrue(config.isDockerConfigPresent());
        assertTrue(config.getDockerLibraryPath().endsWith("Path/to/dockerLib/"));
        assertEquals("127.0.0.41", config.getDockerHostBinding());
        assertEquals("127.0.0.42", config.getDockerHostName());
        assertEquals(PortRange.fromString("4433-5433"), config.getDockerPortRange());
        assertEquals(42, config.getMaxRunningContainers());
        assertEquals(3, config.getMaxSimultaneousBuilds());

        // Check flag translation
        {
            ConfigOptionValueTranslation translation =
                    config.getOptionsToTranslationMap().get(ConfigOptionParameterType.DISABLE_PSK);
            assertNotNull(translation);
            assertTrue(translation instanceof FlagTranslation);
            FlagTranslation flagTranslation = (FlagTranslation) translation;
            assertEquals("no-psk", flagTranslation.getDataIfSet());
            assertEquals("", flagTranslation.getDataIfNotSet());
        }

        // Check single value option translation
        {
            ConfigOptionValueTranslation translation =
                    config.getOptionsToTranslationMap()
                            .get(ConfigOptionParameterType.SEEDING_METHOD);
            assertNotNull(translation);
            assertTrue(translation instanceof SingleValueOptionTranslation);
            SingleValueOptionTranslation singleTranslation =
                    (SingleValueOptionTranslation) translation;
            assertEquals("--with-rand-seed", singleTranslation.getIdentifier());
            assertEquals(
                    "os",
                    singleTranslation.getValueTranslation(
                            SeedingMethodDerivation.SeedingMethodType.OS_ENTROPY_SOURCE.name()));
        }
    }
}
