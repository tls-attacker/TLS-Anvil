/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * Copyright 2020 Ruhr University Bochum and
 * TÜV Informationstechnik GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension;

import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.OpenSSL.OpenSSLBuildManager;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

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
    private String tlsLibraryVersion;
    private ConfigurationOptionsBuildManager buildManager;
    private Path buildScriptPath;
    private Map<ConfigOptionDerivationType, ConfigOptionValueTranslation> optionsToTranslation;

    public ConfigurationOptionsConfig(Path configFilePath) throws ParserConfigurationException, IOException, SAXException {
        optionsToTranslation = new HashMap<>();
        parseConfigFile(configFilePath);
    }

    public String getTlsLibraryName() {
        return tlsLibraryName;
    }

    public String getTlsLibraryVersion() {
        return tlsLibraryVersion;
    }

    public ConfigurationOptionsBuildManager getBuildManager() { // temporary a String
        return buildManager;
    }

    public Path getBuildScriptPath() {
        return buildScriptPath;
    }

    public Map<ConfigOptionDerivationType, ConfigOptionValueTranslation> getOptionsToTranslationMap() {
        return new HashMap<>(optionsToTranslation);
    }

    public Set<ConfigOptionDerivationType> getEnabledConfigOptionDerivations() {
        return new HashSet<>(optionsToTranslation.keySet());
    }

    private void parseConfigFile(Path configFilePath) throws ParserConfigurationException, IOException, SAXException {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);

        DocumentBuilder db = dbf.newDocumentBuilder();
        Document doc = db.parse(configFilePath.toFile());
        doc.getDocumentElement().normalize();

        Element rootElement = doc.getDocumentElement();

        // Parse basic configurations
        tlsLibraryName = rootElement.getElementsByTagName("tlsLibraryName").item(0).getTextContent();
        tlsLibraryVersion = rootElement.getElementsByTagName("tlsLibraryVersion").item(0).getTextContent();
        buildManager = getBuildManagerFromString(rootElement.getElementsByTagName("buildManager").item(0).getTextContent());
        buildScriptPath = Paths.get(rootElement.getElementsByTagName("buildScriptPath").item(0).getTextContent());

        Element optionsToTest = (Element) rootElement.getElementsByTagName("optionsToTest").item(0);

        // Parse options-translation list
        NodeList list = optionsToTest.getElementsByTagName("optionEntry");

        for (int optionEntryIdx = 0; optionEntryIdx < list.getLength(); optionEntryIdx++) {

            Node optionEntryNode = list.item(optionEntryIdx);

            if (optionEntryNode.getNodeType() == Node.ELEMENT_NODE) {

                Element optionEntry = (Element) optionEntryNode;

                // Parse derivation type
                ConfigOptionDerivationType derivationType = derivationTypeFromString(optionEntry.getElementsByTagName("derivationType").item(0).getTextContent());

                // Parse value translation
                ConfigOptionValueTranslation translation = getTranslationFromElement((Element) optionEntry.getElementsByTagName("valueTranslation").item(0));

                optionsToTranslation.put(derivationType, translation);
            }
        }
    }

    private ConfigurationOptionsBuildManager getBuildManagerFromString(String str)
    {
        switch(str){
            case "OpenSSLBuildManager":
                return OpenSSLBuildManager.getInstance();
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

