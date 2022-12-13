package edu.kit.ipd.sdq.attacksurface.tests.evaluation;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.AttackerFactory;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.PcmIntegrationFactory;

public class PowerGridTest extends EvaluationTest {

    public PowerGridTest() {
        this.PATH_ATTACKER = "powerGrid-surface/My.attacker";
        this.PATH_ASSEMBLY = "powerGrid-surface/powerGrid.system";
        this.PATH_ALLOCATION = "powerGrid-surface/powerGrid.allocation";
        this.PATH_CONTEXT = "powerGrid-surface/My.context";
        this.PATH_MODIFICATION = "powerGrid-surface/My.kamp4attackmodificationmarks";
        this.PATH_REPOSITORY = "powerGrid-surface/powerGrid.repository";
        this.PATH_USAGE = "powerGrid-surface/powerGrid.usagemodel";
        this.PATH_RESOURCES = "powerGrid-surface/powerGrid.resourceenvironment";
    }

    @Test
    public void powerGridBaseTest() {
        final var entity = this.getSurfaceAttacker()
            .getTargetedElement()
            .getAssemblycontext()
            .get(0);
        final var changes = this.runAnalysisWithoutAttackPathGeneration();
        this.pathsTestHelper(changes, entity);
    }

    @Test
    public void powerGridBaseTestCompleteAnalysis() {
        final var entity = this.getSurfaceAttacker()
            .getTargetedElement()
            .getAssemblycontext()
            .get(0);
        final var changes = this.runAnalysis();
        final var pathsDirectlyAfterAnalysis = changes.getAttackpaths();
        Assertions.assertEquals(14, pathsDirectlyAfterAnalysis.size());

        this.pathsTestHelper(changes, entity);
    }

    @Test
    public void attackScenario() {
        final var entity = this.getSurfaceAttacker()
            .getTargetedElement()
            .getAssemblycontext()
            .get(0);
        final var startFilter = AttackerFactory.eINSTANCE.createStartElementFilterCriterion();
        final var pcmElement = PcmIntegrationFactory.eINSTANCE.createResourceEnvironmentElement();
        final var resource = this.getBlackboardWrapper()
            .getResourceEnvironment()
            .getResourceContainer_ResourceEnvironment()
            .stream()
            .filter(e -> e.getEntityName()
                .equals("Workstation01"))
            .findAny();
        Assertions.assertTrue(resource.isPresent());
        pcmElement.setResourcecontainer(resource.get());
        startFilter.getStartResources()
            .add(pcmElement);
        this.getSurfaceAttacker()
            .getFiltercriteria()
            .add(startFilter);

        final var changes = this.runAnalysis();
        final var pathsDirectlyAfterAnalysis = changes.getAttackpaths();

        Assertions.assertEquals(1, pathsDirectlyAfterAnalysis.size());
        Assertions.assertEquals(5, pathsDirectlyAfterAnalysis.get(0)
            .getAttackpathelement()
            .size());
        this.pathsTestHelper(changes, entity);

    }

}
