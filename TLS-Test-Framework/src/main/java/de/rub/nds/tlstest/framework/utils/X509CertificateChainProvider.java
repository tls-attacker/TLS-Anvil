package de.rub.nds.tlstest.framework.utils;

import de.rub.nds.protocol.constants.FfdhGroupParameters;
import de.rub.nds.protocol.crypto.key.DhPublicKey;
import de.rub.nds.protocol.crypto.key.KeyGenerator;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlstest.framework.model.derivationParameter.helper.CertificateConfigChainValue;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.constants.X509NamedCurve;
import de.rub.nds.x509attacker.constants.X509PublicKeyType;
import de.rub.nds.x509attacker.constants.X509SignatureAlgorithm;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class X509CertificateChainProvider {
    private static X509CertificateChainProvider instance = null;
    private static final Logger LOGGER = LogManager.getLogger();
    private ArrayList<X509CertificateConfig> certConfigs;
    public static final String RESOURCE_CERT_CONFIG_FOLDER = "/serverCertConfigs";

    public static X509CertificateChainProvider getInstance() {
        if (instance == null) {
            instance = new X509CertificateChainProvider();
        }
        return instance;
    }

    public static final int LEAF_CERT_INDEX = 0;
    public static final BigInteger RSA_PUBLIC_KEY = new BigInteger("65537", 10);
    public static final Map<BigInteger, BigInteger> RSA_MODULUS_PRIVATE_KEY_MAP = new HashMap<>();

    static {
        // 1024
        RSA_MODULUS_PRIVATE_KEY_MAP.put(
                new BigInteger(
                        "00d7169ef864f41347e8af4886d7696a378a116baaf523e7c24d042ef3a0fef406f34a1547d2c2cd43dd6c431125de8066b56e7eebb5d7ee340c5cd0aa38fd7cbb22a52153b260c6a0219a3bc22d95209bb26a428306f9819dd0b824289b36a079f02e774fff17051086340bc52c49ad139f6cf55e7232d605222eec39a5178b6f",
                        16),
                new BigInteger(
                        "00ae6e84fbd2fb724b85f3e93099afbed94dda74e3cf2c903eae30ef56db41086c3e8fdd144363820e409b1504ea1e392992880adc63bbbb4d709d31086b717fddd2cdd86369731bf85c998881a403f277c884952111863aaf00c7179db55ae183387a8c18c5ec024f13e24704cd6dc1eaaa24477ffd2724d3f440d62479be2169",
                        16));
        // 2048
        RSA_MODULUS_PRIVATE_KEY_MAP.put(
                new BigInteger(
                        "00ccb73b51ad7a40cc4ad79afab7211bbc7bee8cbbf0c598f7e28cd1394eecb06aa2d9f99cbc8d3757494694c0dc70d4418229223e06633164f5eca5616ab9d6858cb46883f9d6ddfc4f5a37fa8a3d23fad5b2554d7342eb9a644b03c36946c51c727fce66ee885114ff24c24a476307f05542b428c9b5651e6f060cb95297743650349f7178915a71bea4fe4bd18758b9b51a204f6083d9f6b8fae07591c5aeb0f01553a77c2d285ce2196f46e6604f73e9af79692da48dde5c5f31052c0b3c21b94d042e279a648bddb5f8d749b6f76a8c3af909111b1739b7ebf263e416e801dafa53ca19040e4a943a2978075ba59993a4a48419720b7d2a10fae909a67eb3",
                        16),
                new BigInteger(
                        "4020fe321df7f8288721776926c8f6595b316560d291f3d36362dd7fe85b79004eb79ddc1dacd7333ebf1f8633081d55d02276999b82a34c8f456ca151bf99960877d36dd46c1cea172999f3a02e7b00eec488b8546d18452b39dc99f076bcf4a661a714d3905c66096f4875e05b0377a41ddb3613ca013d416651c2143f61a5ba95ea82337fce5df16b710a9d0557b481243603432d88c6188c3f87a38030bd51c291d53615aa50653d377ce1bb73fb1c8199e78efa7a8f8259e5d1959ee357c0d7ec56ac29da544f56759171905583022c6780dd0c684525dc3745105f3d8ccf80947a3a954eec7d4778754f74f109610aad2b5a49f3e7cddcfdc4f5b55061",
                        16));
        // 4096
        RSA_MODULUS_PRIVATE_KEY_MAP.put(
                new BigInteger(
                        "00c0876e609e9573e314a9052baebfc2c213b24007359987759c5b64272b1df16cc30274813d4ef1c63d1663edd169d551eeeb9529c707e20d48553c70b8e9f00f5555b77d0a595a5984ad7601879d06aab234ccecdb3e75c8c453c5da2ba905650e14f8447c3903652b9f00df0e345751fa872602207ab4b113b05a7c580109c81a27237eac44b144adb8bd86502cbccb8f459298360dbbe41dff35f5f70b70b00d28c7de1c58a6944b1533ce7b2fa6cea953b46e7d390d2d58e1ecb2738387f26b4921018d70f8b2be1ee6e4522a4271c9fb0466060455bdd586bec40d312f311e248785f13269c12e9ef19a0f10e4f9ffbba995c18d746d2cd64c3c958a3dafd240d948394c3f19bc62cffd8a643582aa3b4c646f0aeb364b9c4666df5d42caa267ee125b118babe33842ba696ffb141a1f2402072b56e5eb43f576d63b32db5d7347bf1aa5ddad42e49d0b190dc609fad7dbf0c8d0cc4f7523ce56b6ae9c4ca3142de742ba8911873e887cce1523c3edb36fa0b36e51f2b796b3199387b96f1d5aab9a4b39fe8d430d7e336b4d01fe4b25cc25b768986dbe86e24f7379b961fc368d6b23d9b97f24a01f19c5fcb75ba69055e45c5ede8381fef7b44f27a33f44863fb55080a92fcabc01888599171e1917b457224d4e3242b91d99985cf307ede657d9dffa7104f0bc033e7e733f80466372e1ddde8d0df0b0422500221511",
                        16),
                new BigInteger(
                        "336bf8af15ac1527b17cf3449787e01cb5e605f3e6fcfa910f11d9ce1c56030569905e4da6724f61032fd7c0cd0dd74beae44112c775f38a58a76b5d30064b77ccf2f7ef0db48fcd1902bb61ed36a37133e7a6541cbab1facd75128312e631eaabb82e171c969db187d510068364b76dcddc0aeac681ff80cc216e0987f7bf0512f72123d41f04b9b32c84723b37b7b526af0e58591791f77b8b8e7e035daadb5aa869b98918a4653728928db39926944be56f6b9346899e72fee4994500fc6e62f9453784ef877d360a4ae0f09118ee0b645fe85ff308738b7451bf4b46b7b406b8faf96b526bac8d2726a05f25c40281ab3dc021d20626a2b319e9948737b2277dde314eece01c1479d6a9ee95651295abb3856c75d783bae8cfff7e619eea2744033d155064f7e0c940b6bc2d24ccafbc7c5cce1a819b98d2b76310ab693b88910e6d042a787ca2320a2326a89e7b8d7ec4df89433b3ff5613cb04cc5ed0f9bf20d30ac81ab7c3cf592b64e03dc6e0733e00fd889d064d5ffcb8e3c5fec72bf48c1613346e9060c976b3b7e6cde0005ccc9ab60ae88d2ca427a571ce9aef36aa455781128d0badc08102ba8d2f875b3a31d06c634b9c3368c25e0e837b25fe3762ab9f4bcb7b4379f152eba07e39969ef73997982e5ba0863e623b76f79bb704a36c5c922f53e250d6400a602d34b5be1f81cd161e34a5614d2f561152381",
                        16));
    }

    public static List<X509CertificateConfig> getRsaLeafConfigs() {
        List<X509CertificateConfig> certConfigs = new ArrayList<>();
        // PSS, RSAE, and PSS_RSAE
        List<X509PublicKeyType> leafKeyTypes =
                List.of(
                        X509PublicKeyType.RSASSA_PSS,
                        X509PublicKeyType.RSAES_OAEP,
                        X509PublicKeyType.RSA);
        for (X509PublicKeyType keyType : leafKeyTypes) {
            for (BigInteger modulus : RSA_MODULUS_PRIVATE_KEY_MAP.keySet()) {
                X509CertificateConfig rsaLeaf = new X509CertificateConfig();
                rsaLeaf.setPublicKeyType(keyType);
                rsaLeaf.setRsaModulus(modulus);
                rsaLeaf.setRsaPublicKey(RSA_PUBLIC_KEY);
                rsaLeaf.setRsaPrivateKey(RSA_MODULUS_PRIVATE_KEY_MAP.get(modulus));
                certConfigs.add(rsaLeaf);
            }
        }
        return certConfigs;
    }

    public static List<X509CertificateConfig> getEcLeafConfigs() {
        List<X509CertificateConfig> certConfigs = new ArrayList<>();
        List<NamedGroup> namedGroups =
                NamedGroup.getImplemented().stream()
                        .filter(NamedGroup::isEcGroup)
                        .filter(group -> group.convertToX509() != null)
                        .toList();
        for (NamedGroup group : namedGroups) {
            X509CertificateConfig ecLeaf = new X509CertificateConfig();
            ecLeaf.setPublicKeyType(X509PublicKeyType.ECDH_ECDSA);
            ecLeaf.setDefaultSubjectNamedCurve(group.convertToX509());
            ecLeaf.setEcPublicKey(
                    KeyGenerator.generateEcdsaPublicKey(
                                    ecLeaf.getEcPrivateKey(), group.convertToX509().getParameters())
                            .getPublicPoint());
            certConfigs.add(ecLeaf);
        }
        return certConfigs;
    }

    public static List<CertificateConfigChainValue> getCertificateChainConfigs() {
        List<List<X509CertificateConfig>> certChainConfigs = new ArrayList<>();
        certChainConfigs.addAll(getRsaSignedChainConfigs());
        // X509-Attacker does not support ECDSA signed certs yet
        // certChainConfigs.addAll(getEcdsaSignedChainConfigs());

        return CertificateConfigChainValue.fromCertificateConfigs(certChainConfigs);
    }

    public static List<List<X509CertificateConfig>> getRsaSignedChainConfigs() {
        List<List<X509CertificateConfig>> certChainConfigs = new ArrayList<>();
        List<X509CertificateConfig> leafConfigs = getAllLeafConfigs();
        for (X509CertificateConfig leafConfig : leafConfigs) {
            X509CertificateConfig rsaSigningCert = new X509CertificateConfig();
            rsaSigningCert.setPublicKeyType(X509PublicKeyType.RSA);
            leafConfig.setSignatureAlgorithm(X509SignatureAlgorithm.SHA256_WITH_RSA_ENCRYPTION);
            List<X509CertificateConfig> chainConfig = new ArrayList<>();
            chainConfig.add(leafConfig);
            chainConfig.add(rsaSigningCert);
            certChainConfigs.add(chainConfig);
        }
        return certChainConfigs;
    }

    private static List<X509CertificateConfig> getAllLeafConfigs() {
        List<X509CertificateConfig> leafConfigs = getRsaLeafConfigs();
        leafConfigs.addAll(getEcLeafConfigs());
        leafConfigs.addAll(getDhLeafConfigs());
        leafConfigs.addAll(getDsaLeafConfigs());
        return leafConfigs;
    }

    public static List<List<X509CertificateConfig>> getEcdsaSignedChainConfigs() {
        List<List<X509CertificateConfig>> certChainConfigs = new ArrayList<>();
        List<X509CertificateConfig> leafConfigs = getAllLeafConfigs();
        for (X509CertificateConfig leafConfig : leafConfigs) {
            X509CertificateConfig ecdsaSigningCert = new X509CertificateConfig();
            ecdsaSigningCert.setDefaultSubjectNamedCurve(X509NamedCurve.SECP256R1);
            ecdsaSigningCert.setPublicKeyType(X509PublicKeyType.ECDH_ECDSA);
            ecdsaSigningCert.setSignatureAlgorithm(X509SignatureAlgorithm.ECDSA_WITH_SHA256);
            leafConfig.setSignatureAlgorithm(X509SignatureAlgorithm.ECDSA_WITH_SHA256);
            List<X509CertificateConfig> chainConfig = new ArrayList<>();
            chainConfig.add(leafConfig);
            chainConfig.add(ecdsaSigningCert);
            certChainConfigs.add(chainConfig);
        }
        return certChainConfigs;
    }

    public static List<X509CertificateConfig> getDhLeafConfigs() {
        List<NamedGroup> dhGroups =
                NamedGroup.getImplemented().stream().filter(NamedGroup::isDhGroup).toList();
        for (NamedGroup group : dhGroups) {
            X509CertificateConfig dhLeaf = new X509CertificateConfig();
            FfdhGroupParameters parameters = (FfdhGroupParameters) group.getGroupParameters();
            DhPublicKey dhPublicKey =
                    KeyGenerator.generateDhPublicKey(dhLeaf.getDhPrivateKey(), parameters);
            dhLeaf.setPublicKeyType(X509PublicKeyType.DH);
            dhLeaf.setDhGenerator(RSA_PUBLIC_KEY);
            dhLeaf.setDhPublicKey(dhPublicKey.getPublicKey());
            dhLeaf.setDhModulus(dhPublicKey.getModulus());
            dhLeaf.setDhGenerator(dhPublicKey.getGenerator());
        }
        return new LinkedList<>();
    }

    public static List<X509CertificateConfig> getDsaLeafConfigs() {
        List<X509CertificateConfig> certConfigs = new ArrayList<>();
        X509CertificateConfig dsaLeaf = new X509CertificateConfig();
        dsaLeaf.setPublicKeyType(X509PublicKeyType.DSA);
        certConfigs.add(dsaLeaf);
        return certConfigs;
    }

    public List<X509CertificateConfig> getCertConfigs() {
        return certConfigs;
    }
}
