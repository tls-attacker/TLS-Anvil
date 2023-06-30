/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.model;

import com.fasterxml.jackson.annotation.JsonValue;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.model.derivationParameter.DerivationParameter;
import de.rwth.swc.coffee4j.model.Combination;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.StringJoiner;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** Holds parameters that represent one set of test derivation. */
public class DerivationContainer {

    private static final Logger LOGGER = LogManager.getLogger();
    private final List<DerivationParameter> derivations;
    private LegacyDerivationScope underlyingScope;

    public DerivationContainer(List<Object> objects) {
        derivations = new LinkedList<>();
        for (Object derivation : objects) {
            if (derivation instanceof DerivationParameter) {
                derivations.add((DerivationParameter) derivation);
            } else {
                LOGGER.warn(
                        "Found a Test Parameter that is not a DerivationParameter - will be ignored");
            }
        }
    }

    public DerivationContainer(List<Object> objects, LegacyDerivationScope underlyingScope) {
        this(objects);
        this.underlyingScope = underlyingScope;
        derivations.addAll(
                ParameterModelFactory.getStaticParameters(
                        TestContext.getInstance(), underlyingScope));
    }

    public static DerivationContainer fromCombination(Combination combination) {
        List<Object> res = new ArrayList<>();
        combination
                .getParameterValueMap()
                .keySet()
                .forEach(
                        key -> {
                            Object value = combination.getParameterValueMap().get(key).get();
                            res.add(value);
                        });
        return new DerivationContainer(res);
    }

    public <T extends DerivationParameter<?>> T getDerivation(Class<T> clazz) {
        for (DerivationParameter listed : derivations) {
            if (clazz.equals(listed.getClass())) {
                return (T) listed;
            }
        }
        return null;
    }

    public DerivationParameter getDerivation(TlsParameterType type) {
        for (DerivationParameter listed : derivations) {
            if (listed.getType() == type) {
                return listed;
            }
        }
        LOGGER.warn("Parameter of type " + type + " was not added by model!");
        return null;
    }

    public DerivationParameter getChildParameter(TlsParameterType type) {
        for (DerivationParameter listed : derivations) {
            if (listed.getParent() == type) {
                return listed;
            }
        }
        LOGGER.warn("Child of parameter " + type + " was not added by model!");
        return null;
    }

    public void applyToConfig(Config baseConfig, TestContext context) {
        for (DerivationParameter listed : derivations) {
            if (underlyingScope.isAutoApplyToConfig(listed.getType())) {
                listed.applyToConfig(baseConfig, context);
            }
        }
        for (DerivationParameter listed : derivations) {
            if (underlyingScope.isAutoApplyToConfig(listed.getType())) {
                listed.postProcessConfig(baseConfig, context);
            }
        }
        LOGGER.debug("Applied " + toString());
    }

    public String toString() {
        StringJoiner joiner = new StringJoiner(", ");
        for (DerivationParameter derivationParameter : derivations) {
            joiner.add(derivationParameter.toString());
        }
        return joiner.toString();
    }

    public byte[] buildBitmask() {
        for (DerivationParameter listed : derivations) {
            if (listed.getType().isBitmaskDerivation()) {
                return buildBitmask(listed.getType());
            }
        }
        return null;
    }

    public byte[] buildBitmask(TlsParameterType type) {
        DerivationParameter byteParameter = getDerivation(type);
        DerivationParameter bitParameter = getChildParameter(type);

        byte[] constructed = new byte[(Integer) byteParameter.getSelectedValue() + 1];
        constructed[(Integer) byteParameter.getSelectedValue()] =
                (byte) (1 << (Integer) bitParameter.getSelectedValue());
        return constructed;
    }

    @JsonValue
    private Map<String, DerivationParameter> jsonObject() {
        Map<String, DerivationParameter> res = new HashMap<>();
        for (DerivationParameter i : derivations) {
            res.put(i.getType().name(), i);
        }
        return res;
    }

    public LegacyDerivationScope getUnderlyingScope() {
        return underlyingScope;
    }
}
