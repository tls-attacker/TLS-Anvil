package de.rub.nds.tlstest.framework.testClasses;


import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlstest.framework.annotations.TlsVersion;

@TlsVersion(supported = ProtocolVersion.TLS13)
public class Tls13Test extends TlsBaseTest {
    @Override
    public Config getConfig() {
        Config config = context.getConfig().createConfig();
        config.setHighestProtocolVersion(ProtocolVersion.TLS13);
        config.setAddEllipticCurveExtension(true);
        config.setAddECPointFormatExtension(true);
        config.setAddKeyShareExtension(true);
        config.setAddSignatureAndHashAlgorithmsExtension(true);
        config.setAddSupportedVersionsExtension(true);
        config.setAddRenegotiationInfoExtension(false);
        config.setDefaultServerSupportedSignatureAndHashAlgorithms(
                SignatureAndHashAlgorithm.RSA_PSS_RSAE_SHA384,
                SignatureAndHashAlgorithm.RSA_PSS_RSAE_SHA256,
                SignatureAndHashAlgorithm.RSA_PSS_RSAE_SHA512,
                SignatureAndHashAlgorithm.RSA_SHA1,
                SignatureAndHashAlgorithm.RSA_SHA256,
                SignatureAndHashAlgorithm.RSA_SHA384,
                SignatureAndHashAlgorithm.RSA_SHA512,
                SignatureAndHashAlgorithm.ED25519
        );
        return config;
    }
}
