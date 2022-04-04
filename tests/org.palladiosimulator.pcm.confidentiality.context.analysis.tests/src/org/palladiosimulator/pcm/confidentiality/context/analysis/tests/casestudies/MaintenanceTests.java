package org.palladiosimulator.pcm.confidentiality.context.analysis.tests.casestudies;

import static org.junit.Assert.assertTrue;
import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.palladiosimulator.pcm.confidentiality.context.analysis.tests.base.casestudies.MaintenanceBaseTest;
import org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.api.Configuration;
import org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.api.PCMBlackBoard;
import org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.provider.ScenarioAnalysisSystemImpl;
import org.palladiosimulator.pcm.confidentiality.context.xacml.pdp.result.DecisionType;

public class MaintenanceTests extends MaintenanceBaseTest {

    @BeforeEach
    void initLocal() {
        this.blackBoard = new PCMBlackBoard(this.assembly, this.repo, this.usage);
        this.analysis = new ScenarioAnalysisSystemImpl();
        this.configuration = new Configuration(false, this.eval);
    }

    @Test
    void positiveCase() {
        generateXML();
        final var output = this.analysis.runScenarioAnalysis(this.blackBoard, this.context, this.configuration);
        assertAllPositive(output);
    }

    @Test
    void noContext() {

        // removes Machine Context from UsageScenario "Save MachineData"
        this.context.getPcmspecificationcontainer().getUsagespecification().stream()
                .filter(specification -> specification.getId().equals("_VeC9YrQJEeyBBMZUdAqcvg")).findAny()
                .ifPresent(e -> {
                    e.setAttribute(null);
                    e.setAttributevalue(null);
                });

        generateXML();
        final var output = this.analysis.runScenarioAnalysis(this.blackBoard, this.context, this.configuration);
        assertEquals(3, output.getScenariooutput().size());

        // only the "Save MachineData" should fail
        assertEquals(2,
                output.getScenariooutput().stream()
                        .filter(decision -> decision.getDecision().equals(DecisionType.PERMIT)).count());
        var resultProductStorage = output.getScenariooutput().stream().filter(e -> {
            var scenario = e.getScenario();
            if (scenario != null && e.getAssemblyContext().size() == 1 && e.getOperationsignature() != null) {
                return scenario.getEntityName().equals("Save MachineData")
                        && "Assembly_MachineComponent".equals(e.getAssemblyContext().get(0).getEntityName())
                        && "saveLogs".equals(e.getOperationsignature().getEntityName());
            }

            return false;
        }).findFirst();
        assertTrue(resultProductStorage.isPresent());
        assertEquals(DecisionType.DENY, resultProductStorage.get().getDecision());

    }

}
