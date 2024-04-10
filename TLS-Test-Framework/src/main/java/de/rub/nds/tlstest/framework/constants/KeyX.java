/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.constants;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.tlsattacker.core.protocol.message.ServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlstest.framework.FeatureExtractionResult;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import javax.annotation.Nonnull;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.extension.ExtensionContext;

public class KeyX implements KeyExchange {
    private static final Logger LOGGER = LogManager.getLogger();
    private static Map<CipherSuite, ServerKeyExchangeMessage> cipherSuiteSkeCache;

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
     * filters supportedKxs, so that it only contains the KeyExchangeTypes that are actually
     * supported by the server/client.
     */
    public void filterSupportedKexs() {
        TestContext context = TestContext.getInstance();
        FeatureExtractionResult report = context.getFeatureExtractionResult();
        if (cipherSuiteSkeCache == null) {
            buildCache();
        }

        Set<CipherSuite> ciphers = report.getCipherSuites();
        if (ciphers == null) {
            ciphers = new HashSet<>();
        }

        Set<KeyExchangeType> filtered = new HashSet<>();

        for (CipherSuite cipherSuite : ciphers) {
            KeyExchangeAlgorithm kexalg = AlgorithmResolver.getKeyExchangeAlgorithm(cipherSuite);
            ServerKeyExchangeMessage serverKeyExchangeMessage =
                    cipherSuiteSkeCache.get(cipherSuite);
            for (KeyExchangeType type : this.supported()) {
                if (kexalg == null
                        || (requiresServerKeyExchMsg && serverKeyExchangeMessage == null)) {
                    continue;
                }
                if (kexalg.isKeyExchangeEcdh() && type == KeyExchangeType.ECDH) {
                    filtered.add(type);
                } else if (kexalg.isKeyExchangeRsa() && type == KeyExchangeType.RSA) {
                    filtered.add(type);
                } else if (kexalg.isKeyExchangeDh() && type == KeyExchangeType.DH) {
                    filtered.add(type);
                }
            }
        }

        if (Arrays.asList(this.supported()).contains(KeyExchangeType.ALL13)
                && report.getSupportedTls13CipherSuites() != null
                && report.getSupportedTls13CipherSuites().size() > 0) {
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
                Set<KeyExchangeType> supportedKexsSet =
                        new HashSet<>(Arrays.asList(method.supported()));

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
            resolvedKeyExchange.setSupportedKxs(
                    new KeyExchangeType[] {KeyExchangeType.ALL12, KeyExchangeType.ALL13});
        }

        boolean supportsAll =
                Arrays.asList(resolvedKeyExchange.supported()).contains(KeyExchangeType.ALL12);
        if (supportsAll) {
            resolvedKeyExchange.setSupportedKxs(
                    new KeyExchangeType[] {
                        KeyExchangeType.DH, KeyExchangeType.ECDH, KeyExchangeType.RSA
                    });
        }

        if (resolvedKeyExchange.supported().length > 0) {
            resolvedKeyExchange.filterSupportedKexs();
        } else {
            resolvedKeyExchange.setSupportedKxs(new KeyExchangeType[0]);
        }

        return resolvedKeyExchange;
    }

    public boolean compatibleWithCiphersuite(CipherSuite cipherSuite) {
        if (cipherSuite.isTLS13()) {
            return Arrays.asList(this.supported()).contains(KeyExchangeType.ALL13);
        }
        if (cipherSuiteSkeCache == null) {
            buildCache();
        }

        KeyExchangeAlgorithm alg = AlgorithmResolver.getKeyExchangeAlgorithm(cipherSuite);
        // TLS 1.3 is handled above
        assert alg != null;

        ServerKeyExchangeMessage serverKeyExchangeMessage = cipherSuiteSkeCache.get(cipherSuite);

        boolean compatible = false;
        for (KeyExchangeType type : this.supported()) {
            switch (type) {
                case RSA:
                    compatible |= alg.isKeyExchangeRsa() && !this.requiresServerKeyExchMsg;
                    break;
                case DH:
                    // equivalent to alg.isKeyExchangeDh() && ((this.requiresServerKeyExchMsg &&
                    // skxm != null) || !this.requiresServerKeyExchMsg)
                    compatible |=
                            alg.isKeyExchangeDh()
                                    && (!this.requiresServerKeyExchMsg
                                            || serverKeyExchangeMessage != null);
                    break;
                case ECDH:
                    compatible |=
                            alg.isKeyExchangeEcdh()
                                    && (!this.requiresServerKeyExchMsg
                                            || serverKeyExchangeMessage != null);
                    break;
                case ALL12:
                    compatible |=
                            AlgorithmResolver.getKeyExchangeAlgorithm(cipherSuite) != null
                                    && (!this.requiresServerKeyExchMsg
                                            || serverKeyExchangeMessage != null);
                    break;
                case NOT_SPECIFIED:
                    break;
            }
        }

        return compatible;
    }

    public boolean supports(KeyExchangeType keyExType) {
        if (supported() == null) {
            return false;
        } else {
            return Arrays.stream(supported())
                    .anyMatch(supportedType -> keyExType.equals(supportedType));
        }
    }

    private void buildCache() {
        cipherSuiteSkeCache = new HashMap<>();
        Config helperConfig = Config.createConfig();
        for (CipherSuite cipherSuite : CipherSuite.values()) {
            KeyExchangeAlgorithm kexalg = AlgorithmResolver.getKeyExchangeAlgorithm(cipherSuite);
            if (cipherSuite.isEphemeral() || cipherSuite.isSrp()) {
                cipherSuiteSkeCache.put(
                        cipherSuite,
                        new WorkflowConfigurationFactory(helperConfig)
                                .createServerKeyExchangeMessage(kexalg));
            } else {
                cipherSuiteSkeCache.put(cipherSuite, null);
            }
        }
    }
}
