package de.rub.nds.tlstest.framework.anvil;

// TODO Parameter Scope should probably be an interface.

import de.rub.nds.anvilcore.model.parameter.ParameterScope;

public class TlsParameterScope extends ParameterScope {

    public static final TlsParameterScope MAC_BITMASK =
            new TlsParameterScope(TlsParameterScopeEnum.MAC_BITMASK);
    public static final TlsParameterScope CIPHERTEXT_BITMASK =
            new TlsParameterScope(TlsParameterScopeEnum.CIPHERTEXT_BITMASK);
    public static final TlsParameterScope AUTH_TAG_BITMASK =
            new TlsParameterScope(TlsParameterScopeEnum.AUTH_TAG_BITMASK);
    public static final TlsParameterScope PADDING_BITMASK =
            new TlsParameterScope(TlsParameterScopeEnum.PADDING_BITMASK);
    public static final TlsParameterScope PRF_BITMASK =
            new TlsParameterScope(TlsParameterScopeEnum.PRF_BITMASK);
    public static final TlsParameterScope SIGNATURE_BITMASK =
            new TlsParameterScope(TlsParameterScopeEnum.SIGNATURE_BITMASK);

    TlsParameterScopeEnum scope;

    private TlsParameterScope(TlsParameterScopeEnum scope) {
        this.scope = scope;
    }

    @Override
    public String getUniqueScopeIdentifier() {
        return scope.name();
    }

    public static TlsParameterScope resolveScope(String scope) {
        TlsParameterScopeEnum enumValue = TlsParameterScopeEnum.valueOf(scope);
        if (enumValue == null) {
            return null;
        }
        switch (enumValue) {
            case AUTH_TAG_BITMASK:
                return AUTH_TAG_BITMASK;
            case CIPHERTEXT_BITMASK:
                return CIPHERTEXT_BITMASK;
            case MAC_BITMASK:
                return MAC_BITMASK;
            case PADDING_BITMASK:
                return PADDING_BITMASK;
            case PRF_BITMASK:
                return PRF_BITMASK;
            case SIGNATURE_BITMASK:
                return SIGNATURE_BITMASK;
            default:
                throw new RuntimeException("Scope " + scope + " could not be resolved.");
        }
    }
}
