/*
 *  TLS-Test-Framework - A framework for modeling TLS tests
 *
 *  Copyright 2020 Ruhr University Bochum and
 *  TÜV Informationstechnik GmbH
 *
 *  Licensed under Apache License 2.0
 *  http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionsConfig;

import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.constants.TestEndpointType;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.ConfigOptionDerivationType;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.buildManagement.ConfigurationOptionsBuildManager;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.buildManagement.openSSL.OpenSSLBuildManager;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.IOException;

/**
 * Contains all configuration data that is contained in the configuration option XML config file. These data are used
 * to specify which TLS library is built and how. Additionally, the set of used ConfigOptionDerivationParameter%s
 * is specified and how to translate them to library specific configurations (e.g. OpenSSL cli parameters).
 *
 * Check out the exampleConfig.xml file in examples/ for usage instructions.
 */
public class ConfigurationOptionsConfig {

    private String tlsLibraryName;
    private String tlsVersionName;
    private ConfigurationOptionsBuildManager buildManager;
    private final Map<ConfigOptionDerivationType, ConfigOptionValueTranslation> optionsToTranslation;

    private int configOptionsIpmStrength; // default: strength of main IPM

    private boolean withCoverage;
    private int maxRunningContainers; // default 16
    /** Defines how many containers should be shutdown simultaneously. When measuring coverage the coverage data
     * is collected at the shutdown. Therefore it is much more CPU expensive than a simple shutdown.*/
    private int maxRunningContainerShutdowns; // default 8 with coverage or maxRunningContainers/2 without coverage

    // Docker Config (not required, but necessary for build managers that work with docker)
    private boolean dockerConfigPresent;

    private Path dockerLibraryPath;
    /** The address the docker host is bound to (e.g. 127.0.0.1, or 0.0.0.0) */
    private String dockerHostBinding;
    /** Thee address to access the host (may differ from dockerHostBinding when using docker with WSL) */
    private String dockerHostName;
    private PortRange dockerPortRange;
    private String dockerClientDestinationHostName;


    public ConfigurationOptionsConfig(Path configFilePath) throws FileNotFoundException {
        optionsToTranslation = new HashMap<>();
        parseConfigFile(new FileInputStream(configFilePath.toFile()));
    }

    public ConfigurationOptionsConfig(InputStream inputStream) {
        optionsToTranslation = new HashMap<>();
        parseConfigFile(inputStream);
    }

    public String getTlsLibraryName() {
        return tlsLibraryName;
    }

    public String getTlsVersionName() {
        return tlsVersionName;
    }

    public ConfigurationOptionsBuildManager getBuildManager() { // temporary a String
        return buildManager;
    }

    public boolean isWithCoverage() {
        return withCoverage;
    }

    public int getConfigOptionsIpmStrength() { return configOptionsIpmStrength; }

    public boolean isDockerConfigPresent() {
        return dockerConfigPresent;
    }

    public Path getDockerLibraryPath() {
        return dockerLibraryPath;
    }

    public String getDockerHostBinding() {
        return dockerHostBinding;
    }

    public String getDockerHostName() {
        return dockerHostName;
    }

    public PortRange getDockerPortRange() {
        return dockerPortRange;
    }

    public String getDockerClientDestinationHostName() {
        return dockerClientDestinationHostName;
    }

    public Map<ConfigOptionDerivationType, ConfigOptionValueTranslation> getOptionsToTranslationMap() {
        return new HashMap<>(optionsToTranslation);
    }

    public Set<ConfigOptionDerivationType> getEnabledConfigOptionDerivations() {
        return new HashSet<>(optionsToTranslation.keySet());
    }

    public int getMaxRunningContainers() {
        return maxRunningContainers;
    }

    public int getMaxRunningContainerShutdowns() {
        return maxRunningContainerShutdowns;
    }

    private void parseConfigFile(InputStream inputStream){
        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);

            DocumentBuilder db = dbf.newDocumentBuilder();
            Document doc = db.parse(inputStream);
            doc.getDocumentElement().normalize();

            Element rootElement = doc.getDocumentElement();

            parseAndConfigureTLSLibraryName(rootElement);
            parseAndConfigureTLSVersionName(rootElement);
            parseAndConfigureConfigOptionsIpmStrength(rootElement);


            parseAndConfigureDockerConfig(rootElement);
            parseAndConfigureWithCoverage(rootElement);

            parseAndConfigureMaxRunningContainers(rootElement);
            parseAndConfigureMaxRunningContainerShutdowns(rootElement);
            parseAndConfigureOptionsToTest(rootElement);
            parseAndConfigureBuildManager(rootElement);

        }
        catch(IOException | SAXException | ParserConfigurationException e){
            e.printStackTrace();
            throw new RuntimeException("Parsing failure.");
        }
    }

    private void parseAndConfigureTLSLibraryName(Element rootElement){
        tlsLibraryName = Objects.requireNonNull(XmlParseUtils.findElement(rootElement, "tlsLibraryName", true)).getTextContent();
    }

    private void parseAndConfigureTLSVersionName(Element rootElement){
        tlsVersionName = Objects.requireNonNull(XmlParseUtils.findElement(rootElement, "tlsVersionName", true)).getTextContent();
    }

    private void parseAndConfigureBuildManager(Element rootElement){
        buildManager = getBuildManagerFromString(Objects.requireNonNull(XmlParseUtils.findElement(rootElement, "buildManager", true)).getTextContent());
    }

    private void parseAndConfigureWithCoverage(Element rootElement){
        Element withCoverageElement =  XmlParseUtils.findElement(rootElement, "withCoverage", false);
        if(withCoverageElement != null){
            withCoverage = Boolean.parseBoolean(withCoverageElement.getTextContent());
        }
        else{
            withCoverage = false;
        }
    }

    private void parseAndConfigureConfigOptionsIpmStrength(Element rootElement){
        Element configOptionsIpmStrengthElement =  XmlParseUtils.findElement(rootElement, "configOptionsIpmStrength", false);
        if(configOptionsIpmStrengthElement != null){
            configOptionsIpmStrength = Integer.parseInt(configOptionsIpmStrengthElement.getTextContent());
        }
        else{
            configOptionsIpmStrength = TestContext.getInstance().getConfig().getStrength(); // default
        }
    }

    private void parseAndConfigureMaxRunningContainers(Element rootElement){
        Element maxRunningContainersElement =  XmlParseUtils.findElement(rootElement, "maxRunningContainers", false);
        if(maxRunningContainersElement != null){
            maxRunningContainers = Integer.parseInt(maxRunningContainersElement.getTextContent());
        }
        else{
            maxRunningContainers = 16; // default
        }
    }

    // Must be called after parseAndConfigureWithCoverage and parseAndConfigureMaxRunningContainers
    private void parseAndConfigureMaxRunningContainerShutdowns(Element rootElement){
        Element maxRunningContainersElement =  XmlParseUtils.findElement(rootElement, "maxRunningContainerShutdowns", false);
        if(maxRunningContainersElement != null){
            maxRunningContainerShutdowns = Integer.parseInt(maxRunningContainersElement.getTextContent());
        }
        else{
            if(withCoverage){
                maxRunningContainerShutdowns = 8; // default
            }
            else{
                // Ceil ensures that maxRunningContainerShutdowns > 0
                maxRunningContainerShutdowns = (int) Math.ceil( ( (float) maxRunningContainers) / 2.0f );
            }
        }
    }

    private void parseAndConfigureDockerConfig(Element rootElement){
        NodeList dockerConfigList = rootElement.getElementsByTagName("dockerConfig");
        if(dockerConfigList.getLength() > 0){
            Element dockerConfigElement = (Element) dockerConfigList.item(0);
            dockerLibraryPath = Paths.get(Objects.requireNonNull(XmlParseUtils.findElement(dockerConfigElement, "dockerLibraryPath", true)).getTextContent());
            dockerHostName = Objects.requireNonNull(XmlParseUtils.findElement(dockerConfigElement, "dockerHostName", true)).getTextContent();
            dockerHostBinding = Objects.requireNonNull(XmlParseUtils.findElement(dockerConfigElement, "dockerHostBinding", true)).getTextContent();
            dockerPortRange = PortRange.fromString(Objects.requireNonNull(XmlParseUtils.findElement(dockerConfigElement, "portRange", true)).getTextContent());
            // Docker client dest is required for client tests
            Element dockerClientDestElement =  XmlParseUtils.findElement(dockerConfigElement, "dockerClientDestinationHost", (TestContext.getInstance().getConfig().getTestEndpointMode() == TestEndpointType.CLIENT));
            if(dockerClientDestElement != null){
                dockerClientDestinationHostName = dockerClientDestElement.getTextContent();
            }
            dockerConfigPresent = true;
        }
        else{
            dockerConfigPresent = false;
        }
    }



    private void parseAndConfigureOptionsToTest(Element rootElement){
        // Parse options-translation list
        Element optionsToTest = XmlParseUtils.findElement(rootElement, "optionsToTest", true);
        assert optionsToTest != null;
        NodeList list = optionsToTest.getElementsByTagName("optionEntry");

        for (int optionEntryIdx = 0; optionEntryIdx < list.getLength(); optionEntryIdx++) {

            Node optionEntryNode = list.item(optionEntryIdx);

            if (optionEntryNode.getNodeType() == Node.ELEMENT_NODE) {
                Element optionEntry = (Element) optionEntryNode;

                // Disable the option if enabled is set to false. Options are enabled by default (i.e. if the element is not given)
                Element enabledElement =  XmlParseUtils.findElement(optionEntry, "enabled", false);
                if(enabledElement != null){
                    boolean optionEnabled = Boolean.parseBoolean(enabledElement.getTextContent());
                    if(!optionEnabled){
                        continue;
                    }
                }

                // Parse derivation type
                ConfigOptionDerivationType derivationType = derivationTypeFromString(Objects.requireNonNull(XmlParseUtils.findElement(optionEntry, "derivationType", true)).getTextContent());

                // Parse value translation
                ConfigOptionValueTranslation translation = getTranslationFromElement(Objects.requireNonNull(XmlParseUtils.findElement(optionEntry, "valueTranslation", true)));
                optionsToTranslation.put(derivationType, translation);
            }
        }
    }

    private ConfigurationOptionsBuildManager getBuildManagerFromString(String str)
    {
        if ("OpenSSLBuildManager".equals(str)) {
            if (!dockerConfigPresent) {
                throw new RuntimeException("dockerConfig field is required for using the OpenSSLBuildManager");
            }
            return new OpenSSLBuildManager(this);
        }
        throw new UnsupportedOperationException(String.format("There is no ConfigurationOptionsBuildManager of name '%s' known to this parser.", str));
    }

    private ConfigOptionDerivationType derivationTypeFromString(String str) throws IllegalArgumentException
    {
        String[] splittedStr = str.split("\\.");

        if(splittedStr.length != 2){
            throw new IllegalArgumentException("Illegal derivation type string format. Syntax is \"[Enum].[Value]\"");
        }

        ConfigOptionDerivationType res;
        if ("ConfigOptionDerivationType".equals(splittedStr[0])) {
            res = ConfigOptionDerivationType.valueOf(splittedStr[1]);
        } else {
            throw new IllegalArgumentException("Unsupported derivation type '" + splittedStr[0] + "'");
        }

        return res;
    }

    private ConfigOptionValueTranslation getTranslationFromElement(Element translationElement) throws IllegalArgumentException
    {
        String type = translationElement.getAttribute("type");
        switch(type){
            case "Flag":
                return new FlagTranslation(translationElement);
            case "SingleValueOption":
                return new SingleValueOptionTranslation(translationElement);
            default:
                throw new IllegalArgumentException("Unsupported translation type '"+type+"'");
        }
    }

}

