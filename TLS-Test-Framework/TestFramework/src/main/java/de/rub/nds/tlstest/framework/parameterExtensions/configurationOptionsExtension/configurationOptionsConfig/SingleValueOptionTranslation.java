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

import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.util.HashMap;
import java.util.Map;

/**
 * Translation for an option with a single value, e.g. 'fruit=apple'. In this example 'fruit' is the identifier and 'apple'
 * a possible value. All values that can appear must be covered.
 */
public class SingleValueOptionTranslation extends ConfigOptionValueTranslation{
    private String identifier;
    private Map<String, String> valueTranslationMap;

    public SingleValueOptionTranslation(Element xmlElement)
    {
        valueTranslationMap = new HashMap<>();
        this.setFromXmlElement(xmlElement);
    }

    public String getIdentifier() {
        return identifier;
    }

    public String getValueTranslation(String key){
        if(!valueTranslationMap.containsKey(key)){
            throw new IllegalArgumentException(String.format("Cannot get translation for key '%s'. It was not configured in the config file."));
        }
        return valueTranslationMap.get(key);
    }

    @Override
    protected void setFromXmlElement(Element xmlElement) {
        try{

            this.identifier = XmlParseUtils.findElement(xmlElement, "identifier", true).getTextContent();
            NodeList valueElementList = xmlElement.getElementsByTagName("value");

            for (int optionEntryIdx = 0; optionEntryIdx < valueElementList.getLength(); optionEntryIdx++) {
                Node valueNode = valueElementList.item(optionEntryIdx);
                if (valueNode.getNodeType() == Node.ELEMENT_NODE) {
                    Element valueElement = (Element) valueNode;
                    addValueTranslationByElement(valueElement);
                }
            }
        }
        catch(Exception e){
            e.printStackTrace();
            throw new IllegalArgumentException("Error while parsing OptionWithSingleValueTranslation.");
        }
    }

    private void addValueTranslationByElement(Element valueElement){
        String key = valueElement.getAttribute("key");
        if(key == ""){
            throw new IllegalArgumentException(String.format("In OptionWithSingleValue translation with identifier '%s': <value> element does not contain required attribute 'key'.",
                    identifier));
        }
        if(valueTranslationMap.containsKey(key)){
            throw new IllegalArgumentException(String.format("In OptionWithSingleValue translation with identifier '%s': Key '%s' is defined multiple times.",
                    identifier,
                    key));
        }
        String value = valueElement.getTextContent();
        valueTranslationMap.put(key, value);
    }

}
