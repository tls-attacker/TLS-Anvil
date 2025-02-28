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

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.anvilcore.context.AnvilContext;
import de.rub.nds.anvilcore.context.AnvilTestConfig;
import de.rub.nds.tlstest.framework.anvil.TlsParameterIdentifierProvider;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionDerivationParameter.SeedingMethodDerivation;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionsConfig.*;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import org.junit.jupiter.api.Test;

public class ConfigurationOptionsConfigTest {
    public static ConfigurationOptionsConfig createTestConfig() {
        String testFileContent =
                """
                    <config>
                       <tlsLibraryName>OPENSSL</tlsLibraryName>
                       <tlsVersionName>1.1.1.i</tlsVersionName>
                       <buildManager>OpenSSLBuildManager</buildManager>
                       <dockerConfig>
                           <dockerHostBinding>127.0.0.41</dockerHostBinding>
                           <dockerHostName>127.0.0.42</dockerHostName>
                           <portRange>4433-5433</portRange>
                           <dockerClientDestinationHost>172.26.103.178</dockerClientDestinationHost>
                       </dockerConfig>
                       <disableSiteReportConsoleLog>false</disableSiteReportConsoleLog>
                       <maxSimultaneousBuilds>3</maxSimultaneousBuilds>
                       <maxRunningContainers>42</maxRunningContainers>
                       <configOptionsIpmStrength>2</configOptionsIpmStrength>
                       <optionsToTest>
                           <optionEntry>
                               <derivationType>ConfigOptionParameter:DISABLE_PSK</derivationType>
                               <enabled>true</enabled>
                               <valueTranslation type="Flag">
                                   <true>no-psk</true>"
                                   <false></false>
                               </valueTranslation>
                           </optionEntry>
                           <optionEntry>
                               <derivationType>ConfigOptionParameter:SEEDING_METHOD</derivationType>"
                               <valueTranslation type="SingleValueOption">
                                   <identifier>--with-rand-seed</identifier>
                                   <value key="OS_ENTROPY_SOURCE">os</value>
                                   <value key="GET_RANDOM">getrandom</value>
                                   <value key="DEV_RANDOM">devrandom</value>
                                   <value key="ENTROPY_GENERATING_DAEMON">egd</value>
                                   <value key="CPU_COMMAND">rdcpu</value>
                                   <value key="NONE">none</value>
                               </valueTranslation>
                           </optionEntry>
                       </optionsToTest>
                    </config>
                """;

        InputStream is = new ByteArrayInputStream(testFileContent.getBytes());

        return new ConfigurationOptionsConfig(is);
    }

    @Test
    public void testOpenSSLOptionsConfig() {
        AnvilTestConfig testConfig = new AnvilTestConfig();
        testConfig.setParallelTestCases(1);
        testConfig.setParallelTests(1);
        AnvilContext.createInstance(testConfig, "", new TlsParameterIdentifierProvider());
        ConfigurationOptionsConfig config = createTestConfig();

        assertEquals("OPENSSL", config.getTlsLibraryName());
        assertEquals("1.1.1.i", config.getTlsVersionName());
        assertNotNull(config.getBuildManager());

        // Check docker stuff
        assertTrue(config.isDockerConfigPresent());
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
            assertInstanceOf(FlagTranslation.class, translation);
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
            assertInstanceOf(SingleValueOptionTranslation.class, translation);
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
