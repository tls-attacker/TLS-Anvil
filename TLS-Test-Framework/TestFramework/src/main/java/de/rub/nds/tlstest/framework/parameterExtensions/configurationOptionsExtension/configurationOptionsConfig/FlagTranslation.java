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

/**
 * A ConfigOptionValueTranslation that is used for flags. It contains data a String for a set and unset flag.
 */
public class FlagTranslation extends ConfigOptionValueTranslation
{
    private String dataIfSet;
    private String dataIfNotSet;

    public FlagTranslation(Element xmlElement)
    {
        super(xmlElement);
    }

    @Override
    protected void setFromXmlElement(Element xmlElement) {
        dataIfSet = xmlElement.getElementsByTagName("true").item(0).getTextContent();
        dataIfNotSet = xmlElement.getElementsByTagName("false").item(0).getTextContent();
    }

    public String getDataIfSet(){
        return dataIfSet;
    }

    public String getDataIfNotSet(){
        return dataIfNotSet;
    }
}

