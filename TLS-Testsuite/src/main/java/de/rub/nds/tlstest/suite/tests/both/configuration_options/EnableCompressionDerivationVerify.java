/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2020 Ruhr University Bochum and TÜV Informationstechnik GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.both.configuration_options;

import static org.junit.Assert.assertTrue;

import de.rub.nds.anvilcore.annotation.MethodCondition;
import de.rub.nds.anvilcore.annotation.NonCombinatorialAnvilTest;
import de.rub.nds.anvilcore.teststate.AnvilTestCase;
import de.rub.nds.scanner.core.probe.result.ListResult;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlstest.framework.FeatureExtractionResult;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.ConfigOptionParameterType;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.ConfigurationOptionsDerivationManager;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionDerivationParameter.ConfigurationOptionDerivationParameter;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionDerivationParameter.EnableCompressionDerivation;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;

@Tag("co")
public class EnableCompressionDerivationVerify extends Tls12Test {

    public ConditionEvaluationResult enableCompressionOptionTested() {

        if (ConfigurationOptionsDerivationManager.getInstance().getAllActivatedCOTypes() != null
                && ConfigurationOptionsDerivationManager.getInstance()
                        .getAllActivatedCOTypes()
                        .contains(ConfigOptionParameterType.ENABLE_COMPRESSION)) {
            return ConditionEvaluationResult.enabled("");
        } else {
            return ConditionEvaluationResult.disabled(
                    "The EnableCompression config option is not tested.");
        }
    }

    public boolean onlyCompressionEnabledOptionsSet(
            List<ConfigurationOptionDerivationParameter> possibleValue) {
        for (ConfigurationOptionDerivationParameter listedParameter : possibleValue) {
            if (listedParameter.getParameterIdentifier().getParameterType()
                    == ConfigOptionParameterType.ENABLE_COMPRESSION) {
                return ((EnableCompressionDerivation) listedParameter)
                        .getSelectedValue()
                        .isOptionSet();
            }
        }
        return false;
    }

    @NonCombinatorialAnvilTest(id = "XCO-s74Cw9S5dF")
    @MethodCondition(method = "enableCompressionOptionTested")
    public void compressionEnabledByOption(AnvilTestCase testCase, WorkflowRunner runner) {
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
                                                                            == EnableCompressionDerivation
                                                                                    .class)
                                                    .findFirst();
                                    if (pskParameter.isPresent()) {
                                        return ((EnableCompressionDerivation) pskParameter.get())
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
            List<CompressionMethod> supportedNonNullCompressionMethods = new LinkedList<>();
            if (!(extractionResult.getResult(TlsAnalyzedProperty.SUPPORTED_COMPRESSION_METHODS)
                    instanceof ListResult)) {
                // Currently not scanned in client tests
                return;
            }

            ListResult<CompressionMethod> compressionsList =
                    (ListResult<CompressionMethod>)
                            extractionResult.getResult(
                                    TlsAnalyzedProperty.SUPPORTED_COMPRESSION_METHODS);

            compressionsList.getCollection().stream()
                    .filter(compression -> compression != CompressionMethod.NULL)
                    .forEach(supportedNonNullCompressionMethods::add);
            assertTrue(
                    "No compression method was enabled using the EnableCompressionDerivation.",
                    supportedNonNullCompressionMethods.size() > 0);
        }
    }
}
