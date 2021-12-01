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

import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.ConfigOptionDerivationType;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.ConfigurationOptionsBuildManager;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.OpenSSL.OpenSSLBuildManager;
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
 */
public class ConfigurationOptionsConfig {

    private String tlsLibraryName;
    private String tlsVersionName;
    private ConfigurationOptionsBuildManager buildManager;
    private Map<ConfigOptionDerivationType, ConfigOptionValueTranslation> optionsToTranslation;

    // Docker Config (not required, but necessary for build managers that work with docker)
    private boolean dockerConfigPresent;

    private Path dockerLibraryPath;

    private String dockerHostName;
    private PortRange dockerPortRange;

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

    public boolean isDockerConfigPresent() {
        return dockerConfigPresent;
    }

    public Path getDockerLibraryPath() {
        return dockerLibraryPath;
    }

    public String getDockerHostName() {
        return dockerHostName;
    }

    public PortRange getDockerPortRange() {
        return dockerPortRange;
    }

    public Map<ConfigOptionDerivationType, ConfigOptionValueTranslation> getOptionsToTranslationMap() {
        return new HashMap<>(optionsToTranslation);
    }

    public Set<ConfigOptionDerivationType> getEnabledConfigOptionDerivations() {
        return new HashSet<>(optionsToTranslation.keySet());
    }

    private void parseConfigFile(InputStream inputStream){
        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);

            DocumentBuilder db = dbf.newDocumentBuilder();
            Document doc = db.parse(inputStream);
            doc.getDocumentElement().normalize();

            Element rootElement = doc.getDocumentElement();

            // Parse basic configurations
            tlsLibraryName = findRequiredElement(rootElement, "tlsLibraryName").getTextContent();
            tlsVersionName = findRequiredElement(rootElement, "tlsVersionName").getTextContent();


            //dockerLibraryPath = Paths.get(rootElement.getElementsByTagName("dockerLibraryPath").item(0).getTextContent());

            Element optionsToTest = (Element) rootElement.getElementsByTagName("optionsToTest").item(0);

            // Parse docker config if present
            NodeList dockerConfigList = rootElement.getElementsByTagName("dockerConfig");
            if(dockerConfigList.getLength() > 0){
                Element dockerConfigElement = (Element) dockerConfigList.item(0);
                dockerLibraryPath = Paths.get(findRequiredElement(dockerConfigElement, "dockerLibraryPath").getTextContent());
                dockerHostName = findRequiredElement(dockerConfigElement, "dockerHostName").getTextContent();
                dockerPortRange = PortRange.fromString(findRequiredElement(dockerConfigElement, "portRange").getTextContent());
                dockerConfigPresent = true;
            }
            else{
                dockerConfigPresent = false;
            }

            buildManager = getBuildManagerFromString(findRequiredElement(rootElement, "buildManager").getTextContent());

            // Parse options-translation list
            NodeList list = optionsToTest.getElementsByTagName("optionEntry");

            for (int optionEntryIdx = 0; optionEntryIdx < list.getLength(); optionEntryIdx++) {

                Node optionEntryNode = list.item(optionEntryIdx);

                if (optionEntryNode.getNodeType() == Node.ELEMENT_NODE) {

                    Element optionEntry = (Element) optionEntryNode;

                    // Parse derivation type
                    ConfigOptionDerivationType derivationType = derivationTypeFromString(findRequiredElement(optionEntry, "derivationType").getTextContent());

                    // Parse value translation
                    ConfigOptionValueTranslation translation = getTranslationFromElement(findRequiredElement(optionEntry, "valueTranslation"));

                    optionsToTranslation.put(derivationType, translation);
                }
            }
        }
        catch(IOException | SAXException | ParserConfigurationException e){
            e.printStackTrace();
            throw new RuntimeException("Parsing failure.");
        }
        catch(NullPointerException e){
            e.printStackTrace();
            throw new RuntimeException("Parsing failure. There are missing entries.");
        }
    }

    private Element findRequiredElement(Element root, String tagName){
        NodeList elementList = root.getElementsByTagName(tagName);
        if(elementList.getLength() < 1){
            throw new RuntimeException(String.format("Missing child '%s' of '%s'.", tagName, root.getTagName()));
        }
        else if(elementList.getLength() > 1){
            throw new RuntimeException(String.format("Multiple children '%s' in '%s' found.", tagName));
        }
        if (elementList.item(0).getNodeType() != Node.ELEMENT_NODE) {
            throw new RuntimeException(String.format("Config entry of tag '%s' is no element node.", tagName));
        }
        Element element = (Element) elementList.item(0);

        return element;
    }

    private ConfigurationOptionsBuildManager getBuildManagerFromString(String str)
    {
        switch(str){
            case "OpenSSLBuildManager":
                if(!dockerConfigPresent){
                    throw new RuntimeException("dockerConfig field is required for using the OpenSSLBuildManager");
                }
                return new OpenSSLBuildManager(this);
            default:
                throw new UnsupportedOperationException(String.format("There is no ConfigurationOptionsBuildManager of name '%s' known to this parser.", str));
        }
    }

    private ConfigOptionDerivationType derivationTypeFromString(String str) throws IllegalArgumentException
    {
        String[] splittedStr = str.split("\\.");

        if(splittedStr.length != 2){
            throw new IllegalArgumentException("Illegal derivation type string format. Syntax is \"[Enum].[Value]\"");
        }

        ConfigOptionDerivationType res;
        switch(splittedStr[0]) {
            case "ConfigOptionDerivationType":
                res = ConfigOptionDerivationType.valueOf(splittedStr[1]);
                break;
            default:
                throw new IllegalArgumentException("Unsupported derivation type \'"+splittedStr[0]+"\'");
        }

        return res;
    }

    private ConfigOptionValueTranslation getTranslationFromElement(Element translationElement) throws IllegalArgumentException
    {
        String type = translationElement.getAttribute("type");
        switch(type){
            case "Flag":
                return new FlagTranslation(translationElement);
            default:
                throw new IllegalArgumentException("Unsupported translation type \'"+type+"\'");
        }
    }

}

