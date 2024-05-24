/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2020 Ruhr University Bochum and TÜV Informationstechnik GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.both.configuration_options;

import static org.junit.Assert.assertEquals;

import de.rub.nds.anvilcore.annotation.MethodCondition;
import de.rub.nds.anvilcore.annotation.NonCombinatorialAnvilTest;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlstest.framework.FeatureExtractionResult;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.ConfigOptionParameterType;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.ConfigurationOptionsDerivationManager;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionDerivationParameter.ConfigurationOptionDerivationParameter;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionDerivationParameter.DisablePskDerivation;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;

@Tag("co")
public class DisablePskDerivationVerify extends Tls12Test {

    public ConditionEvaluationResult disablePskOptionTested() {
        if (ConfigurationOptionsDerivationManager.getInstance().getAllActivatedCOTypes() != null
                && ConfigurationOptionsDerivationManager.getInstance()
                        .getAllActivatedCOTypes()
                        .contains(ConfigOptionParameterType.DISABLE_PSK)) {
            return ConditionEvaluationResult.enabled("");
        } else {
            return ConditionEvaluationResult.disabled(
                    "The DisablePsk config option is not tested.");
        }
    }

    public boolean onlyPskDisabledConfigOptionsSet(
            List<ConfigurationOptionDerivationParameter> possibleValue) {
        for (ConfigurationOptionDerivationParameter listedParameter : possibleValue) {
            if (listedParameter.getParameterIdentifier().getParameterType()
                    == ConfigOptionParameterType.DISABLE_PSK) {
                return ((DisablePskDerivation) listedParameter).getSelectedValue().isOptionSet();
            }
        }
        return false;
    }

    @NonCombinatorialAnvilTest(id = "XCO-B6aDKr3y8P")
    @MethodCondition(method = "disablePskOptionTested")
    public void pskCiphersuitesDisabled() {
        Map<List<ConfigurationOptionDerivationParameter>, FeatureExtractionResult>
                compoundFeatureExtractionResults =
                        ConfigurationOptionsDerivationManager.getInstance()
                                .getCompoundFeatureExtractionResult();
        List<List<ConfigurationOptionDerivationParameter>> relevantConfigOptionSets =
                compoundFeatureExtractionResults.keySet().stream()
                        .filter(
                                list -> {
                                    Optional<ConfigurationOptionDerivationParameter> pskParameter =
                                            list.stream()
                                                    .filter(
                                                            parameter ->
                                                                    parameter.getClass()
                                                                            == DisablePskDerivation
                                                                                    .class)
                                                    .findFirst();
                                    if (pskParameter.isPresent()) {
                                        return ((DisablePskDerivation) pskParameter.get())
                                                .getSelectedValue()
                                                .isOptionSet();
                                    }

                                    return false;
                                })
                        .collect(Collectors.toList());
        for (List<ConfigurationOptionDerivationParameter> configOptionSet :
                relevantConfigOptionSets) {
            FeatureExtractionResult extractionResult =
                    compoundFeatureExtractionResults.get(configOptionSet);

            List<TlsAnalyzedProperty> expectedDisabledProperties =
                    Arrays.asList(
                            TlsAnalyzedProperty.SUPPORTS_PSK_PLAIN,
                            TlsAnalyzedProperty.SUPPORTS_PSK_RSA,
                            TlsAnalyzedProperty.SUPPORTS_PSK_DHE,
                            TlsAnalyzedProperty.SUPPORTS_PSK_ECDHE);

            List<TlsAnalyzedProperty> nonDisabledProperties = new LinkedList<>();
            for (TlsAnalyzedProperty expectedDisabledProperty : expectedDisabledProperties) {
                if (extractionResult.getResult(expectedDisabledProperty) == TestResults.TRUE) {
                    // Unexpectedly enabled.
                    nonDisabledProperties.add(expectedDisabledProperty);
                }
            }
            assertEquals(
                    "Unexpectedly supported features: " + nonDisabledProperties.toString(),
                    0,
                    nonDisabledProperties.size());
        }
    }
}
