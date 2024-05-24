/*
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * Copyright 2020 Ruhr University Bochum and
 * TÜV Informationstechnik GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension;

import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.anvilcore.model.parameter.ParameterScope;
import de.rub.nds.anvilcore.model.parameter.ParameterType;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionDerivationParameter.ConfigurationOptionCompoundDerivation;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionDerivationParameter.DisableAfalgEngineDerivation;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionDerivationParameter.DisableAssemblerCodeDerivation;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionDerivationParameter.DisableBinaryEllipticCurvesDerivation;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionDerivationParameter.DisableCertificateTransparencyDerivation;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionDerivationParameter.DisableErrorStringsDerivation;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionDerivationParameter.DisableExtensionForIpAddressesAndAsIdentifiersDerivation;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionDerivationParameter.DisableMultiblockDerivation;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionDerivationParameter.DisableNextProtocolNegotiationExtensionDerivation;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionDerivationParameter.DisableOcspSupportDerivation;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionDerivationParameter.DisablePadlockEngineDerivation;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionDerivationParameter.DisablePosixIoDerivation;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionDerivationParameter.DisablePskDerivation;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionDerivationParameter.DisableRdrandDerivation;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionDerivationParameter.DisableSrpCiphersuitesDerivation;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionDerivationParameter.DisableSse2Derivation;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionDerivationParameter.EnableCompressionDerivation;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionDerivationParameter.EnableDevelopmentFlagsDerivation;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionDerivationParameter.EnableEntropyGatheringDaemonDerivation;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionDerivationParameter.EnableMd2Derivation;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionDerivationParameter.EnableMemoryDebuggingSupportDerivation;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionDerivationParameter.EnableNistEcOptimizationsDerivation;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionDerivationParameter.EnableRc5Derivation;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionDerivationParameter.EnableWeakSslCiphersDerivation;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionDerivationParameter.SeedingMethodDerivation;
import java.lang.reflect.InvocationTargetException;

/**
 * All these types represent configuration options. Configuration options are library options that
 * are configured at compile time and are therefore NOT configured and negotiated during the TLS
 * handshake. Note that not all of these options are supported by every TLS-library.
 *
 * <p>To implement new options (e.g. the option ExampleOption) the following steps need to be
 * applied: 1) Add ExampleOption to the ConfigOptionDerivationType enum below 2) Add a new class
 * 'ExampleOptionDerivation' in the package
 * de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension. Implement the
 * required functions like the other classes. 3) Add the new class to the factory method
 * 'ConfigurationOptionsDerivationManager.getDerivationParameterInstance(...)' 4) To use the new
 * option in your test, make sure to add it to your config options config file (together with the
 * respective translation) 5) If required: Add constraints regarding your new option to the required
 * tests in your testsuite.
 */
public enum ConfigOptionParameterType implements ParameterType {
    CONFIG_OPTION_COMPOUND_PARAMETER(ConfigurationOptionCompoundDerivation.class),

    // 1st Priority
    SEEDING_METHOD(SeedingMethodDerivation.class),
    ENABLE_NIST_EC_OPTIMIZATIONS(EnableNistEcOptimizationsDerivation.class),
    DISABLE_SSE2(DisableSse2Derivation.class),

    DISABLE_BINARY_ELLIPTIC_CURVES(DisableBinaryEllipticCurvesDerivation.class),
    DISABLE_MULTIBLOCK(DisableMultiblockDerivation.class),
    DISABLE_PSK(DisablePskDerivation.class),

    ENABLE_COMPRESSION(EnableCompressionDerivation.class),

    // 2nd Priority
    DISABLE_AFALG_ENGINE(DisableAfalgEngineDerivation.class),
    ENABLE_ENTROPY_GATHERING_DAEMON(EnableEntropyGatheringDaemonDerivation.class),
    DISABLE_RDRAND(DisableRdrandDerivation.class),

    DISABLE_CERTIFICATE_TRANSPARENCY(DisableCertificateTransparencyDerivation.class),
    DISABLE_NEXT_PROTOCOL_NEGOTIATION(DisableNextProtocolNegotiationExtensionDerivation.class),
    DISABLE_OCSP_SUPPORT(DisableOcspSupportDerivation.class),

    ENABLE_WEAK_SSL_CIPHERS(EnableWeakSslCiphersDerivation.class),
    ENABLE_MD2(EnableMd2Derivation.class),
    ENABLE_RC5(EnableRc5Derivation.class),

    DISABLE_ASSEMBLER_CODE(DisableAssemblerCodeDerivation.class),

    // 3rd Priority
    DISABLE_PADLOCK_ENGINE(DisablePadlockEngineDerivation.class),
    DISABLE_POSIX_IO(DisablePosixIoDerivation.class),

    DISABLE_EXTENSION_FOR_IP_ADRESSES_AND_AS_IDENTIFIERS(
            DisableExtensionForIpAddressesAndAsIdentifiersDerivation.class),
    DISABLE_SRP_CIPHER_SUITES(DisableSrpCiphersuitesDerivation.class),

    ENABLE_DEVELOPMENT_FLAGS(EnableDevelopmentFlagsDerivation.class), // OpenSSL: --strict-warnings
    ENABLE_MEMORY_DEBUGGING_SUPPORT(EnableMemoryDebuggingSupportDerivation.class),
    DISABLE_ERROR_STRINGS(DisableErrorStringsDerivation.class);

    ConfigOptionParameterType(Class<? extends DerivationParameter> derivationClass) {
        this.derivationClass = derivationClass;
    }

    private Class<? extends DerivationParameter> derivationClass;

    @Override
    public DerivationParameter getInstance(ParameterScope scope) {
        try {
            return derivationClass.getDeclaredConstructor().newInstance();
        } catch (InstantiationException
                | IllegalAccessException
                | InvocationTargetException
                | NoSuchMethodException e) {
            throw new RuntimeException(e);
        }
    }
}
