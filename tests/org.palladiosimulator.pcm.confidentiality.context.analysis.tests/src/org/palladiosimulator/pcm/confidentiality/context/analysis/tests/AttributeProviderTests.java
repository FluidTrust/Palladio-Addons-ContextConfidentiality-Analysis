package org.palladiosimulator.pcm.confidentiality.context.analysis.tests;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.palladiosimulator.pcm.confidentiality.context.analysis.tests.base.BaseTestScenario;
import org.palladiosimulator.pcm.confidentiality.context.model.ContextAttribute;
import org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.api.Configuration;
import org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.api.PCMBlackBoard;
import org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.provider.ScenarioAnalysisSystemImpl;
import org.palladiosimulator.pcm.confidentiality.context.set.SetFactory;
import org.palladiosimulator.pcm.confidentiality.context.specification.assembly.AssemblyFactory;
import org.palladiosimulator.pcm.confidentiality.context.specification.assembly.AttributeProvider;

@Disabled("not implemented")
public class AttributeProviderTests extends BaseTestScenario {

    @BeforeEach
    @Override
    protected void initLocal() {
        this.blackBoard = new PCMBlackBoard(this.assembly, this.repo, this.usage);
        this.analysis = new ScenarioAnalysisSystemImpl();
        this.configuration = new Configuration(true);
    }

    @Test
    @DisplayName("01")
    void noContext() {

        getContextSetByName("AccessOperationPayCommision").getContexts().clear();
        var contextComission = createSingleContext("Context PayCommision");
        this.context.getContextContainer().get(0).getContext().add(contextComission);
        getContextSetByName("AccessOperationPayCommision").getContexts().add(contextComission);

        final var output = this.analysis.runScenarioAnalysis(this.blackBoard, this.context, this.configuration);

        assertNotNull(output.getScenariooutput());
        for (final var scenario : output.getScenariooutput()) {
            assertTrue(scenario.isResult());
        }
    }

    @Test
    @DisplayName("01_no_context_usage_model")
    void attributeSet() {

        getContextSetByName("AccessOperationPayCommision").getContexts().clear();
        var contextComission = createSingleContext("Context PayCommision");
        this.context.getContextContainer().get(0).getContext().add(contextComission);
        getContextSetByName("AccessOperationPayCommision").getContexts().add(contextComission);

        var attributeProvider = createAttributeProvider(contextComission);

        var policySpecification = getPolicySpecificationByName("AccessOperationPayCommision");
//        attributeProvider.setMethodspecification(policySpecification.getMethodspecification());

        final var output = this.analysis.runScenarioAnalysis(this.blackBoard, this.context, this.configuration);

        assertNotNull(output.getScenariooutput());
        for (final var scenario : output.getScenariooutput()) {
            assertTrue(scenario.isResult());
        }
    }

    private AttributeProvider createAttributeProvider(ContextAttribute... contextAttributes) {
        var attributeProvider = createAttributeProvider();

        var attributeSet = SetFactory.eINSTANCE.createContextSet();
        attributeSet.getContexts().addAll(Arrays.asList(contextAttributes));
        this.context.getSetContainer().get(0).getPolicies().add(attributeSet);

        attributeProvider.setContextset(attributeSet);
        return attributeProvider;
    }

    private AttributeProvider createAttributeProvider() {
        var attributeProvider = AssemblyFactory.eINSTANCE.createAttributeProvider();
        this.context.getPcmspecificationcontainer().getAttributeprovider().add(attributeProvider);
        return attributeProvider;
    }

}
