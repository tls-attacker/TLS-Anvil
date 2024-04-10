/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.anvil;

import de.rub.nds.anvilcore.model.DefaultModelTypes;
import java.util.Set;

public class TlsModelTypes {
    public static final String GENERIC = "GENERIC";
    public static final String CERTIFICATE = "CERTIFICATE";
    public static final String LENGTHFIELD = "LENGTHFIELD";

    public static Set<String> tlsModelTypes =
            Set.of(DefaultModelTypes.EMPTY, GENERIC, CERTIFICATE, LENGTHFIELD);
}
