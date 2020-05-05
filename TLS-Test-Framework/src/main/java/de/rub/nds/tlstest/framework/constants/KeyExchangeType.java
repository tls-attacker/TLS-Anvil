package de.rub.nds.tlstest.framework.constants;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.tlsattacker.core.protocol.message.ServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlstest.framework.TestContext;
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

public enum KeyExchangeType {
    RSA,
    DH,
    ECDH,
    ALL12,
    TLS13,
    NOT_SPECIFIED;

    private static final Logger LOGGER = LogManager.getLogger();


    public boolean compatibleWithCiphersuite(CipherSuite i) {
        KeyExchangeAlgorithm alg = AlgorithmResolver.getKeyExchangeAlgorithm(i);
        switch (this) {
            case RSA:
                return alg != null && alg.isKeyExchangeRsa();
            case DH:
                return alg != null && alg.isKeyExchangeDh();
            case ECDH:
                return alg != null && alg.isKeyExchangeEcdh();
            case ALL12:
                return AlgorithmResolver.getKeyExchangeAlgorithm(i) != null;
            case TLS13:
                return AlgorithmResolver.getKeyExchangeAlgorithm(i) == null;
            case NOT_SPECIFIED:
                return false;
        }
        return false;
    }

    @Nonnull
    public static KeyExchangeType forCipherSuite(CipherSuite i) {
        KeyExchangeAlgorithm alg = AlgorithmResolver.getKeyExchangeAlgorithm(i);
        if (alg == null) {
            return KeyExchangeType.TLS13;
        }

        if (alg.isKeyExchangeEcdh()) return KeyExchangeType.ECDH;
        if (alg.isKeyExchangeRsa()) return KeyExchangeType.RSA;
        if (alg.isKeyExchangeDh()) return KeyExchangeType.DH;

        return KeyExchangeType.NOT_SPECIFIED;
    }


}
