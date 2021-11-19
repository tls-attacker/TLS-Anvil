/**
 *  TLS-Test-Framework - A framework for modeling TLS tests
 *
 *  Copyright 2020 Ruhr University Bochum and
 *  TÜV Informationstechnik GmbH
 *
 *  Licensed under Apache License 2.0
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

package de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.OpenSSL;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.TestSiteReport;
import de.rub.nds.tlstest.framework.model.DerivationType;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.*;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionDerivationParameter.ConfigurationOptionDerivationParameter;

import javax.xml.bind.DatatypeConverter;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

/**
 * The OpenSSLBuildManager is a ConfigurationOptionsBuildManager to build modern OpenSSL versions.
 */
public class OpenSSLBuildManager implements ConfigurationOptionsBuildManager {
    private static OpenSSLBuildManager instance = null;
    private Path buildScriptPath;
    private Map<String, TestSiteReport> dockerTagToSiteReport;

    public static synchronized OpenSSLBuildManager getInstance() {
        if (OpenSSLBuildManager.instance == null) {
            OpenSSLBuildManager.instance = new OpenSSLBuildManager();
        }
        return OpenSSLBuildManager.instance;
    }

    private OpenSSLBuildManager(){
        dockerTagToSiteReport = new HashMap<>();
    }

    @Override
    public TestSiteReport configureOptionSetAndGetSiteReport(Config config, TestContext context, Set<ConfigurationOptionDerivationParameter> optionSet) {
        ConfigurationOptionsConfig configOptionsConfig = ConfigurationOptionsDerivationManager.getInstance().getConfigurationOptionsConfig();
        if(configOptionsConfig == null){
            throw new IllegalStateException("No config option configuration configured yet.");
        }
        Integer port = provideOpenSSLImplementation(configOptionsConfig, optionSet);

        // TODO: Configure port and check for TestSiteReport
        return null;
    }


    /*private Integer provideOpenSSLServerImplementation(ConfigurationOptionsConfig configOptionsConfig, Set<ConfigurationOptionDerivationParameter> optionSet){
        // TODO
        return -1;
    }*/

    private Integer provideOpenSSLImplementation(ConfigurationOptionsConfig configOptionsConfig, Set<ConfigurationOptionDerivationParameter> optionSet){
        String cliString = createConfigOptionCliString(optionSet, configOptionsConfig);
        String dockerTag = computeDockerTag(cliString, configOptionsConfig.getTlsLibraryName(), configOptionsConfig.getTlsLibraryVersion());

        if(!dockerTagExists(dockerTag)){
            buildDockerImageWithBuildScript(cliString, dockerTag);
        }

        // TODO: start container and assign port

        return -1;
    }


    /**
     * Creates a docker tag. This tag is different, if the library name, the library version, or the cli option
     * string is different. The docker tags looks like:
     * _[LIB NAME]_[LIB VERSION]_[CLI OPTION HASH]
     *
     * the CLI_OPTION HASH is an hex string of the hash value over the cli option input string (required, because the
     * docker tag has a maximal length). Also, both LIB NAME and LIB VERSION are cut after the 20th character and illegal
     * docker tag characters are eliminated.
     *
     * @param cliString - The command line string that is passed the buildscript
     * @param libraryName - The name of the tls library (e.g. 'OpenSSL')
     * @param libraryVersion - The library's version (e.g. '1.1.1e')
     * @returns the resulting docker tag
     */
    private static String computeDockerTag(String cliString, String libraryName, String libraryVersion){
        String libraryNamePart = libraryName.substring(0, Math.min(20, libraryName.length()));
        String libraryVersionPart = libraryVersion.substring(0,Math.min(20, libraryVersion.length()));
        String cliStringHashString;
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.update(cliString.getBytes());
            cliStringHashString = DatatypeConverter.printHexBinary(messageDigest.digest()).toLowerCase();
        }
        catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw new UnsupportedOperationException("Cannot create a docker tag.");
        }

        String res = String.format("_%s_%s_%s", libraryNamePart, libraryVersionPart, cliStringHashString);
        res = res.replaceAll("[^a-zA-Z0-9_\\.\\-]", "");
        return res;
    }

    private String createConfigOptionCliString(Set<ConfigurationOptionDerivationParameter> optionSet, ConfigurationOptionsConfig configOptionsConfig){
        Map<ConfigOptionDerivationType,ConfigOptionValueTranslation> optionsToTranslationMap = configOptionsConfig.getOptionsToTranslationMap();
        List<String> optionsCliList = new ArrayList<>();
        for(ConfigurationOptionDerivationParameter optionParameter : optionSet){
            String cliOption = translateOptionValue(optionParameter, optionsToTranslationMap).trim();
            if(!cliOption.isEmpty()){
                optionsCliList.add(cliOption);
            }
        }
        // Sort the options alphabetically. This is used to obtain deterministic results independent of the Set's iteration order.
        optionsCliList.sort(Comparator.comparing(String::toString));

        return String.join(" ", optionsCliList);
    }

    private String translateOptionValue(ConfigurationOptionDerivationParameter optionParameter, Map<ConfigOptionDerivationType,ConfigOptionValueTranslation> optionsToTranslationMap){
        ConfigurationOptionValue value = optionParameter.getSelectedValue();
        if(value == null){
            throw new IllegalArgumentException("Passed option parameter has no selected value yet.");
        }
        DerivationType derivationType = optionParameter.getType();
        if(!(derivationType instanceof ConfigOptionDerivationType)){
            throw new IllegalArgumentException("Passed derivation parameter is not of type ConfigOptionDerivationType.");
        }
        ConfigOptionDerivationType optionType = (ConfigOptionDerivationType) derivationType;

        if(!optionsToTranslationMap.containsKey(optionType)){
            throw new IllegalStateException("The ConfigurationOptionsConfig's translation map does not contain the passed type");
        }

        ConfigOptionValueTranslation translation = optionsToTranslationMap.get(optionType);

        if(translation instanceof FlagTranslation){
            FlagTranslation flagTranslation = (FlagTranslation) translation;
            if(!value.isFlag()){
                throw new IllegalStateException("The ConfigurationOptionsConfig's translation is a flag, but the ConfigurationOptionValue isn't. Value can't be translated.");
            }

            if(value.isOptionSet()){
                return flagTranslation.getDataIfSet();
            }
            else{
                return flagTranslation.getDataIfNotSet();
            }
        }
        else{
            throw new UnsupportedOperationException(String.format("The OpenSSLBuildManager does not support translations '%s'.", translation.getClass()));
        }

    }

    // Docker access functions

    private boolean dockerTagExists(String dockerTag){
        // TODO
        return false;
    }

    private void buildDockerImageWithBuildScript(String cliOptionString, String dockerTag){
        // TODO
        return;
    }

    private void createDockerContainer(String dockerTag, Integer port){
        // TODO
        return;
    }
}
