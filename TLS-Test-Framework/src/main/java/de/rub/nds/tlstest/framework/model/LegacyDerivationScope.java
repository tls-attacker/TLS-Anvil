/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.model;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.annotations.DynamicValueConstraints;
import de.rub.nds.tlstest.framework.annotations.ExplicitModelingConstraints;
import de.rub.nds.tlstest.framework.annotations.ExplicitValues;
import de.rub.nds.tlstest.framework.annotations.ManualConfig;
import de.rub.nds.tlstest.framework.annotations.ScopeExtensions;
import de.rub.nds.tlstest.framework.annotations.ScopeLimitations;
import de.rub.nds.tlstest.framework.annotations.TestStrength;
import de.rub.nds.tlstest.framework.annotations.ValueConstraints;
import de.rub.nds.tlstest.framework.coffee4j.model.ModelFromScope;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.constants.KeyX;
import de.rub.nds.tlstest.framework.model.constraint.ValueConstraint;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.extension.ExtensionContext;

/**
 * Defines which TLS parameters are used for the test derivation and how they are applied to the
 * session.
 */
public class LegacyDerivationScope {
    private ModelType baseModel = ModelType.GENERIC;
    private final List<TlsParameterType> scopeLimits;
    private final List<TlsParameterType> scopeExtensions;
    private final KeyX keyExchangeRequirements;
    private final List<ValueConstraint> valueConstraints;
    private final Map<TlsParameterType, String> explicitValues;
    private final Map<TlsParameterType, String> explicitModelingConstraints;
    private final ExtensionContext extensionContext;
    private final Set<TlsParameterType> manualConfigTypes;
    private final int testStrength;

    public LegacyDerivationScope(ExtensionContext context) {
        this.keyExchangeRequirements = (KeyX) KeyX.resolveKexAnnotation(context);
        this.scopeLimits = resolveScopeLimits(context);
        this.scopeExtensions = resolveScopeExtensions(context);
        this.valueConstraints = resolveValueConstraints(context);
        this.explicitValues = resolveExplicitValues(context);
        this.explicitModelingConstraints = resolveExplicitModelingConstraints(context);
        this.manualConfigTypes = resolveManualConfigTypes(context);
        this.extensionContext = context;
        this.testStrength = resolveTestStrength(context);
    }

    public LegacyDerivationScope(ExtensionContext context, ModelFromScope modelFromScope) {
        this(context);
        this.baseModel = modelFromScope.baseModel();
    }

    public ModelType getBaseModel() {
        return baseModel;
    }

    public List<TlsParameterType> getScopeLimits() {
        return scopeLimits;
    }

    public List<TlsParameterType> getScopeExtensions() {
        return scopeExtensions;
    }

    public void addScopeLimit(TlsParameterType type) {
        scopeLimits.add(type);
    }

    public void addExtension(TlsParameterType type) {
        scopeExtensions.add(type);
    }

    public KeyX getKeyExchangeRequirements() {
        return keyExchangeRequirements;
    }

    private List<TlsParameterType> resolveScopeLimits(ExtensionContext context) {
        List<TlsParameterType> limitations = new LinkedList<>();
        Method testMethod = context.getRequiredTestMethod();
        if (testMethod.isAnnotationPresent(ScopeLimitations.class)) {
            ScopeLimitations scopeLimitations = testMethod.getAnnotation(ScopeLimitations.class);
            Arrays.stream(scopeLimitations.value())
                    .forEach(derivation -> limitations.add(derivation));
        }
        return limitations;
    }

    private List<TlsParameterType> resolveScopeExtensions(ExtensionContext context) {
        List<TlsParameterType> extensions = new LinkedList<>();
        Method testMethod = context.getRequiredTestMethod();
        if (testMethod.isAnnotationPresent(ScopeExtensions.class)) {
            ScopeExtensions scopeExtensions = testMethod.getAnnotation(ScopeExtensions.class);
            Arrays.stream(scopeExtensions.value())
                    .forEach(derivation -> extensions.add(derivation));
        }
        return extensions;
    }

    private List<ValueConstraint> resolveValueConstraints(ExtensionContext context) {
        List<ValueConstraint> constraints = new LinkedList<>();
        Method testMethod = context.getRequiredTestMethod();
        if (testMethod.isAnnotationPresent(ValueConstraints.class)) {
            ValueConstraints valConstraints = testMethod.getAnnotation(ValueConstraints.class);
            TlsParameterType[] affectedTypes = valConstraints.affectedTypes();
            String[] methods = valConstraints.methods();
            if (methods.length != affectedTypes.length) {
                throw new RuntimeException(
                        "Unable to resolve ValueConstraints - argument count mismatch");
            }
            for (int i = 0; i < affectedTypes.length; i++) {
                constraints.add(
                        new ValueConstraint(
                                affectedTypes[i],
                                methods[i],
                                context.getRequiredTestClass(),
                                false));
            }
        }
        if (testMethod.isAnnotationPresent(DynamicValueConstraints.class)) {
            DynamicValueConstraints valConstraints =
                    testMethod.getAnnotation(DynamicValueConstraints.class);
            TlsParameterType[] affectedTypes = valConstraints.affectedTypes();
            String[] methods = valConstraints.methods();
            if (methods.length != affectedTypes.length) {
                throw new RuntimeException(
                        "Unable to resolve ValueConstraints - argument count mismatch");
            }
            for (int i = 0; i < affectedTypes.length; i++) {
                constraints.add(
                        new ValueConstraint(
                                affectedTypes[i],
                                methods[i],
                                context.getRequiredTestClass(),
                                true));
            }
        }

        return constraints;
    }

    private Map<TlsParameterType, String> resolveExplicitValues(ExtensionContext context) {
        Map<TlsParameterType, String> valueMap = new HashMap<>();
        Method testMethod = context.getRequiredTestMethod();
        if (testMethod.isAnnotationPresent(ExplicitValues.class)) {
            ExplicitValues explicitValues = testMethod.getAnnotation(ExplicitValues.class);
            TlsParameterType[] affectedTypes = explicitValues.affectedTypes();
            String[] methods = explicitValues.methods();
            if (methods.length != affectedTypes.length) {
                throw new RuntimeException(
                        "Unable to resolve ExplicitValues - argument count mismatch");
            }
            for (int i = 0; i < affectedTypes.length; i++) {
                if (valueMap.containsKey(affectedTypes[i])) {
                    throw new RuntimeException(
                            "Unable to resolve ExplicitValues - multiple explicit values derfined for "
                                    + affectedTypes[i]);
                }
                valueMap.put(affectedTypes[i], methods[i]);
            }
        }
        return valueMap;
    }

    private Map<TlsParameterType, String> resolveExplicitModelingConstraints(
            ExtensionContext context) {
        Map<TlsParameterType, String> valueMap = new HashMap<>();
        Method testMethod = context.getRequiredTestMethod();
        if (testMethod.isAnnotationPresent(ExplicitModelingConstraints.class)) {
            ExplicitModelingConstraints explicitConstraints =
                    testMethod.getAnnotation(ExplicitModelingConstraints.class);
            TlsParameterType[] affectedTypes = explicitConstraints.affectedTypes();
            String[] methods = explicitConstraints.methods();
            if (methods.length != affectedTypes.length) {
                throw new RuntimeException(
                        "Unable to resolve ExplicitModelParameterConstraints - argument count mismatch");
            }
            for (int i = 0; i < affectedTypes.length; i++) {
                if (valueMap.containsKey(affectedTypes[i])) {
                    throw new RuntimeException(
                            "Unable to resolve ExplicitModelParameterConstraints - multiple explicit values derfined for "
                                    + affectedTypes[i]);
                }
                valueMap.put(affectedTypes[i], methods[i]);
            }
        }
        return valueMap;
    }

    private Set<TlsParameterType> resolveManualConfigTypes(ExtensionContext context) {
        Set<TlsParameterType> manualConfigTypes = new HashSet<>();
        Method testMethod = context.getRequiredTestMethod();
        if (testMethod.isAnnotationPresent(ManualConfig.class)) {
            ManualConfig manualConfig = testMethod.getAnnotation(ManualConfig.class);
            TlsParameterType[] types = manualConfig.value();
            manualConfigTypes.addAll(Arrays.asList(types));
        }
        return manualConfigTypes;
    }

    private int resolveTestStrength(ExtensionContext context) {
        Method testMethod = context.getRequiredTestMethod();
        if (testMethod.isAnnotationPresent(TestStrength.class)) {
            TestStrength testStrength = testMethod.getAnnotation(TestStrength.class);
            return testStrength.value();
        }
        return TestContext.getInstance().getConfig().getStrength();
    }

    public boolean hasExplicitValues(TlsParameterType type) {
        return explicitValues.containsKey(type);
    }

    public boolean hasExplicitModelingConstraints(TlsParameterType type) {
        return explicitModelingConstraints.containsKey(type);
    }

    public List<ValueConstraint> getValueConstraints() {
        return valueConstraints;
    }

    public ProtocolVersion getTargetVersion() {
        if (isTls13Test()) {
            return ProtocolVersion.TLS13;
        } else {
            return ProtocolVersion.TLS12;
        }
    }

    public String getExplicitValueMethod(TlsParameterType type) {
        return explicitValues.get(type);
    }

    public String getExplicitModelingConstraintMethod(TlsParameterType type) {
        return explicitModelingConstraints.get(type);
    }

    public ExtensionContext getExtensionContext() {
        return extensionContext;
    }

    public boolean isTls13Test() {
        /* Some tests defined in TLS 1.3 test packages
         * test the backwards compatibility of an implementation
         * using a TLS 1.2 handshake - this is evident from the defined
         * KeyExchange annotation
         */
        return keyExchangeRequirements.supports(KeyExchangeType.ALL13);
    }

    public boolean isAutoApplyToConfig(TlsParameterType type) {
        return !manualConfigTypes.contains(type);
    }

    public Map<TlsParameterType, String> getExplicitTypeValues() {
        return explicitValues;
    }

    public int getTestStrength() {
        return testStrength;
    }
}
