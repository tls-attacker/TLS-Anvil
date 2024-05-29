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

/** A collection of static utils functions that is used to support XML parsing using org.w3c.dom. */
public class XmlParseUtils {

    public static Element findElement(Element root, String tagName, boolean required) {
        NodeList elementList = root.getElementsByTagName(tagName);
        if (elementList.getLength() < 1) {
            if (required) {
                throw new RuntimeException(
                        String.format(
                                "Missing required child '%s' of '%s'.",
                                tagName, root.getTagName()));
            } else {
                return null;
            }
        } else if (elementList.getLength() > 1) {
            throw new RuntimeException(String.format("Multiple children in '%s' found.", tagName));
        }
        if (elementList.item(0).getNodeType() != Node.ELEMENT_NODE) {
            throw new RuntimeException(
                    String.format("Config entry of tag '%s' is no element node.", tagName));
        }

        return (Element) elementList.item(0);
    }
}
