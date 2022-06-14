/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * Copyright 2020 Ruhr University Bochum and
 * TÜV Informationstechnik GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.model;

import com.fasterxml.jackson.annotation.JsonValue;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.TestSiteReport;
import de.rub.nds.tlstest.framework.model.derivationParameter.DerivationParameter;
import de.rwth.swc.coffee4j.model.Combination;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.StringJoiner;
import java.util.concurrent.Callable;

/**
 *
 * Holds parameters that represent one set of test derivation.
 */
public class DerivationContainer {

    private static final Logger LOGGER = LogManager.getLogger();
    private final List<DerivationParameter> derivations;
    private DerivationScope underlyingScope;

    // The site report that must be used for the respective derivations. By default the global site report is taken.
    //private TestSiteReport associatedSiteReport;
    /** Used to get the site report that must be used for the respective derivations. By default the global site report is taken.
     A callable is used, so site reports are only created if necessary.*/
    private Callable<TestSiteReport> getAssociatedSiteReportCallable;

    public DerivationContainer(List<Object> objects) {
        derivations = new LinkedList<>();
        getAssociatedSiteReportCallable = (Callable) () -> TestContext.getInstance().getSiteReport();
        for (Object derivation : objects) {
            if (derivation instanceof DerivationParameter) {
                derivations.add((DerivationParameter) derivation);
            } else {
                LOGGER.warn("Found a Test Parameter that is not a DerivationParameter - will be ignored");
            }
        }
    }

    public DerivationContainer(List<Object> objects, DerivationScope underlyingScope) {
        this(objects);
        this.underlyingScope = underlyingScope;
        derivations.addAll(ParameterModelFactory.getStaticParameters(TestContext.getInstance(), underlyingScope));
    }

    public static DerivationContainer fromCombination(Combination combination) {
        List<Object> res = new ArrayList<>();
        combination.getParameterValueMap().keySet().forEach(key -> {
            Object value = combination.getParameterValueMap().get(key).get();
            res.add(value);
        });
        return new DerivationContainer(res);
    }
    
    public <T extends DerivationParameter<?>> T getDerivation(Class<T> clazz) {
        for(DerivationParameter listed : derivations) {
            if(clazz.equals(listed.getClass())) {
                return (T)listed;
            }
        }
        return null;
    }

    public DerivationParameter getDerivation(DerivationType type) {
        for (DerivationParameter listed : derivations) {
            if (listed.getType() == type) {
                return listed;
            }
        }
        LOGGER.warn("Parameter of type " + type + " was not added by model!");
        return null;
    }

    public List<DerivationParameter> getDerivationList() {
        return derivations;
    }

    public DerivationParameter getChildParameter(DerivationType type) {
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
            if(underlyingScope.isAutoApplyToConfig(listed.getType())) {
                listed.applyToConfig(baseConfig, context);
            } 
        }
        for (DerivationParameter listed : derivations) {
            if(underlyingScope.isAutoApplyToConfig(listed.getType())) {
                listed.postProcessConfig(baseConfig, context);
            }
        }
        LOGGER.debug("Applied " + toString());
    }

    /**
     * This method is called after the applyToConfig method is called to configure options that depend on multiple
     * DerivationParameter%s.
     *
     * @param baseConfig The config to create/manipulate
     * @param context The text context
     */
    public void configureDependencies(Config baseConfig, TestContext context){
        for (DerivationParameter listed : derivations) {
            if(underlyingScope.isAutoApplyToConfig(listed.getType())) {
                listed.configureParameterDependencies(baseConfig, context, this);
            }
        }
    }

    /**
     * This method is called after the respective using this container is executed. Every derivation parameter can
     * react, so that they can make final configurations. This is only necessary in rare cases (e.g. for configuration
     * options support).
     */
    public void finalizeContainer(){
        for (DerivationParameter listed : derivations) {
            if(underlyingScope.isAutoApplyToConfig(listed.getType())) {
                listed.onContainerFinalized(this);
            }
        }
    }

    public void configureGetAssociatedSiteReportCallable(Callable<TestSiteReport> getSiteReportCallable){
        this.getAssociatedSiteReportCallable = getSiteReportCallable;
    }

    public TestSiteReport getAssociatedSiteReport(){
        try {
            return this.getAssociatedSiteReportCallable.call();
        }
        catch (RuntimeException e){
            throw e;
        }
        catch(Exception e){
            LOGGER.error("Received checked exception. This should not happen.", e);
            throw new RuntimeException("Received checked exception while getting a test site report.");
        }
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

    public byte[] buildBitmask(DerivationType type) {
        DerivationParameter byteParameter = getDerivation(type);
        DerivationParameter bitParameter = getChildParameter(type);
        
        byte[] constructed = new byte[(Integer)byteParameter.getSelectedValue() + 1];
        constructed[(Integer)byteParameter.getSelectedValue()] = (byte)(1 << (Integer)bitParameter.getSelectedValue());
        return constructed;
    }

    @JsonValue
    private Map<String, DerivationParameter> jsonObject() {
        Map<String, DerivationParameter> res = new HashMap<>();
        for (DerivationParameter i : derivations) {
            res.put(i.getType().toString(), i);
        }
        return res;
    }

    public DerivationScope getUnderlyingScope() {
        return underlyingScope;
    }
    
}
