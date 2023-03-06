package org.palladiosimulator.pcm.confidentiality.context.analysis.tests.casestudies;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.ScenarioOutput;
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
        this.generateXML();
        final var output = this.analysis.runScenarioAnalysis(this.blackBoard, this.context, this.configuration);

        var passed = new String[] { "ProductStorage", "Save MachineData", "MisusageMaintenance" };

        var failed = new String[] { "SaveMachineDataFailed", "MisusageMaintenanceFailed" };
        this.assertPassedFailed(output, passed, failed);
    }

    @Test
    void noContext() {

        // removes Machine Context from UsageScenario "Save MachineData"
        this.context.getPcmspecificationcontainer()
        .getUsagespecification()
        .stream()
        .filter(specification -> specification.getId()
                .equals("_VeC9YrQJEeyBBMZUdAqcvg"))
        .findAny()
        .ifPresent(e -> {
            e.setAttribute(null);
            e.setAttributevalue(null);
        });

        this.generateXML();
        final var output = this.analysis.runScenarioAnalysis(this.blackBoard, this.context, this.configuration);
        assertEquals(6, output.getScenariooutput()
                .size());

        // only the "Save MachineData" should fail
        assertEquals(3, output.getScenariooutput()
                .stream()
                .filter(ScenarioOutput::isPassed)
                .count());
        final var resultSaveMachineDataOpt = output.getScenariooutput()
                .stream()
                .filter(e -> "Save MachineData".equals(e.getScenario()
                        .getEntityName()))
                .findFirst();
        assertTrue(resultSaveMachineDataOpt.isPresent());
        assertFalse(resultSaveMachineDataOpt.get()
                .isPassed());

        /*
         * from the "Save MachineData" should only the initial save operation from the machine
         * should fail
         */
        final var resultSaveMachineData = resultSaveMachineDataOpt.get();
        assertEquals(2, resultSaveMachineData.getOperationOutput()
                .size());
        final var machineSaveOpt = resultSaveMachineData.getOperationOutput()
                .stream()
                .filter(e -> e.getAssemblyContext()
                        .get(0)
                        .getEntityName()
                        .equals("Assembly_MachineComponent"))
                .filter(e -> e.getOperationsignature()
                        .getEntityName()
                        .equals("saveLogs"))
                .findAny();
        assertTrue(machineSaveOpt.isPresent());
        assertEquals(DecisionType.DENY, machineSaveOpt.get()
                .getDecision());

    }

}
