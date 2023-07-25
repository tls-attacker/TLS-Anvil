/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.annotations.keyExchange;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;

public class KexAnnotationMethodTest extends KexAnnotationTest {

    @AnvilTest
    @KeyExchange(supported = {KeyExchangeType.ECDH})
    public void execute_SupportedSupported() {}

    @AnvilTest
    @KeyExchange(supported = {KeyExchangeType.ALL12})
    public void execute_allSupported() {}

    @AnvilTest
    @KeyExchange(supported = {KeyExchangeType.DH, KeyExchangeType.ECDH})
    public void execute_multipleSupported() {}

    @AnvilTest
    public void execute_noKexAnnotationSpecified() {}

    @AnvilTest
    @KeyExchange(
            supported = {},
            mergeSupportedWithClassSupported = true)
    public void not_execute_KexNotSupportedByTarget2() {}

    @AnvilTest
    @KeyExchange(supported = KeyExchangeType.DH)
    public void not_execute_KexNotSupportedByTarget_setSupportedOnly() {}
}
