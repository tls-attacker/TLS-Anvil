/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * Copyright 2020 Ruhr University Bochum and
 * TÜV Informationstechnik GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework;

import de.rub.nds.tlsattacker.core.config.Config;
import org.junit.Test;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.TimeZone;


public class TestRunnerTest {

    @Test
    public void test() {
        Config config = Config.createConfig();
        config.setDefaultClientSupportedCipherSuites(new ArrayList<>());

        Config copy = config.createCopy();
        assert copy.getDefaultClientSupportedCipherSuites().size() == config.getDefaultClientSupportedCipherSuites().size();
    }

    @Test
    public void tesft() {
        Date d = new Date(System.currentTimeMillis());
        SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssXXX");
        format.setTimeZone(TimeZone.getTimeZone("UTC"));
        System.out.println(format.format(d));
    }

}
