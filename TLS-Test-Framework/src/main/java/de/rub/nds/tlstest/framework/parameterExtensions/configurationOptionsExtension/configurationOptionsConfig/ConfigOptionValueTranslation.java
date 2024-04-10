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
 * Abstract class to represent how a value of a ConfigOptionDerivationParameter is translated to a
 * library specific configuration String (E.g. if the DerivationParameter for 'DisablePSK' is set
 * OpenSSL needs to configure using the option 'no_psk'). This translation is very library specific
 * and the respective ConfigurationOptionsBuildManagers have to know how to handle the translations
 * and which translation objects are expected.
 */
public abstract class ConfigOptionValueTranslation {
    public ConfigOptionValueTranslation() {}

    public ConfigOptionValueTranslation(Element xmlElement) {
        setFromXmlElement(xmlElement);
    }

    protected abstract void setFromXmlElement(Element xmlElement);
}
