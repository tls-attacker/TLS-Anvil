/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * Copyright 2020 Ruhr University Bochum and
 * TÜV Informationstechnik GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.constants;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.tlsattacker.core.protocol.message.ServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.TestSiteReport;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.extension.ExtensionContext;

import javax.annotation.Nonnull;
import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public class KeyX implements KeyExchange {
    private static final Logger LOGGER = LogManager.getLogger();

    private KeyExchangeType[] supportedKxs = new KeyExchangeType[0];
    private boolean mergeSupportedWithClassSupported = true;
    private boolean requiresServerKeyExchMsg = false;

    KeyX() {
        super();
    }

    public KeyX(KeyExchange exchange) {
        super();
        this.supportedKxs = exchange.supported();
        this.mergeSupportedWithClassSupported = exchange.mergeSupportedWithClassSupported();
        this.requiresServerKeyExchMsg = exchange.requiresServerKeyExchMsg();
    }

    @Override
    public KeyExchangeType[] supported() {
        return this.supportedKxs;
    }

    @Override
    public boolean mergeSupportedWithClassSupported() {
        return mergeSupportedWithClassSupported;
    }

    @Override
    public boolean requiresServerKeyExchMsg() {
        return this.requiresServerKeyExchMsg;
    }

    @Override
    public Class<? extends Annotation> annotationType() {
        return null;
    }

    public void setSupportedKxs(KeyExchangeType[] supportedKxs) {
        this.supportedKxs = supportedKxs;
    }


    /**
     * filters supportedKxs, so that it only contains the KeyExchangeTypes that are actually supported by the server/client.
     */
    public void filterSupportedKexs() {
        TestContext context = TestContext.getInstance();
        TestSiteReport report = context.getSiteReport();
        Set<CipherSuite> ciphers = report.getCipherSuites();
        if (ciphers == null) {
            ciphers = new HashSet<>();
        }

        Set<KeyExchangeType> filtered = new HashSet<>();

        for (CipherSuite i : ciphers) {
            KeyExchangeAlgorithm kexalg = AlgorithmResolver.getKeyExchangeAlgorithm(i);
            ServerKeyExchangeMessage skx = new WorkflowConfigurationFactory(Config.createConfig()).createServerKeyExchangeMessage(kexalg);
            for (KeyExchangeType t : this.supported()) {
                if (kexalg == null || (requiresServerKeyExchMsg && skx == null)) {
                    continue;
                }
                if (kexalg.isKeyExchangeEcdh() && t == KeyExchangeType.ECDH) {
                    filtered.add(t);
                }
                else if (kexalg.isKeyExchangeRsa() && t == KeyExchangeType.RSA) {
                    filtered.add(t);
                }
                else if (kexalg.isKeyExchangeDh() && t == KeyExchangeType.DH) {
                    filtered.add(t);
                }
            }
        }

        if (Arrays.asList(this.supported()).contains(KeyExchangeType.ALL13) &&
                report.getSupportedTls13CipherSuites() != null &&
                report.getSupportedTls13CipherSuites().size() > 0) {
            filtered.add(KeyExchangeType.ALL13);
        }

        KeyExchangeType[] filteredA = new KeyExchangeType[filtered.size()];
        filtered.toArray(filteredA);
        setSupportedKxs(filteredA);
    }


    @Nonnull
    public static KeyExchange resolveKexAnnotation(ExtensionContext context) {
        Method testMethod = context.getRequiredTestMethod();
        Class<?> testClass = context.getRequiredTestClass();
        KeyX resolvedKeyExchange = new KeyX();

        // annotation on method level
        if (testMethod.isAnnotationPresent(KeyExchange.class)) {
            if (!testClass.isAnnotationPresent(KeyExchange.class)) {
                // annotation only on method level present
                KeyExchange existing = testMethod.getAnnotation(KeyExchange.class);
                resolvedKeyExchange = new KeyX(existing);
            } else if (testClass.isAnnotationPresent(KeyExchange.class)) {
                // annotation on method AND class level present
                KeyExchange method = testMethod.getAnnotation(KeyExchange.class);
                resolvedKeyExchange = new KeyX(method);

                KeyExchange cls = testClass.getAnnotation(KeyExchange.class);
                Set<KeyExchangeType> supportedKexsSet = new HashSet<>(Arrays.asList(method.supported()));

                if (method.mergeSupportedWithClassSupported()) {
                    supportedKexsSet.addAll(Arrays.asList(cls.supported()));
                }

                KeyExchangeType[] supportedKexs = new KeyExchangeType[supportedKexsSet.size()];
                supportedKexsSet.toArray(supportedKexs);

                resolvedKeyExchange.setSupportedKxs(supportedKexs);
            }
        } else if (testClass.isAnnotationPresent(KeyExchange.class)) {
            KeyExchange existing = testClass.getAnnotation(KeyExchange.class);
            resolvedKeyExchange = new KeyX(existing);
        } else {
            resolvedKeyExchange = new KeyX();
            resolvedKeyExchange.setSupportedKxs(new KeyExchangeType[]{KeyExchangeType.ALL12, KeyExchangeType.ALL13});
        }

        boolean supportsAll = Arrays.asList(resolvedKeyExchange.supported()).contains(KeyExchangeType.ALL12);
        if (supportsAll) {
            resolvedKeyExchange.setSupportedKxs(new KeyExchangeType[]{KeyExchangeType.DH, KeyExchangeType.ECDH, KeyExchangeType.RSA});
        }

        if (resolvedKeyExchange.supported().length > 0) {
            resolvedKeyExchange.filterSupportedKexs();
        } else {
            resolvedKeyExchange.setSupportedKxs(new KeyExchangeType[0]);
        }

        return resolvedKeyExchange;
    }

    public boolean compatibleWithCiphersuite(CipherSuite i) {
        if (i.isTLS13()) {
            return  Arrays.asList(this.supported()).contains(KeyExchangeType.ALL13);
        }

        KeyExchangeAlgorithm alg = AlgorithmResolver.getKeyExchangeAlgorithm(i);
        // TLS 1.3 is handled above
        assert alg != null;

        ServerKeyExchangeMessage skxm = new WorkflowConfigurationFactory(Config.createConfig()).createServerKeyExchangeMessage(alg);

        boolean compatible = false;
        for (KeyExchangeType kext : this.supported()) {
            switch (kext) {
                case RSA:
                    compatible |= alg.isKeyExchangeRsa() && !this.requiresServerKeyExchMsg;
                    break;
                case DH:
                    // equivalent to alg.isKeyExchangeDh() && ((this.requiresServerKeyExchMsg && skxm != null) || !this.requiresServerKeyExchMsg)
                    compatible |= alg.isKeyExchangeDh() && (!this.requiresServerKeyExchMsg || skxm != null);
                    break;
                case ECDH:
                    compatible |= alg.isKeyExchangeEcdh() && (!this.requiresServerKeyExchMsg || skxm != null);
                    break;
                case ALL12:
                    compatible |= AlgorithmResolver.getKeyExchangeAlgorithm(i) != null && (!this.requiresServerKeyExchMsg || skxm != null);
                    break;
                case NOT_SPECIFIED:
                    break;
            }
        }

        return compatible;
    }
}
