package edu.kit.ipd.sdq.attacksurface.tests.evaluation;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.AttackerFactory;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.PcmIntegrationFactory;

public class TargetBreachTest extends EvaluationTest {

    public TargetBreachTest() {
        this.PATH_ATTACKER = "targetBreach-surface/My.attacker";
        this.PATH_ASSEMBLY = "targetBreach-surface/target.system";
        this.PATH_ALLOCATION = "targetBreach-surface/target.allocation";
        this.PATH_CONTEXT = "targetBreach-surface/target.context";
        this.PATH_MODIFICATION = "targetBreach-surface/target.kamp4attackmodificationmarks";
        this.PATH_REPOSITORY = "targetBreach-surface/target.repository";
        this.PATH_USAGE = "targetBreach-surface/target.usagemodel";
        this.PATH_RESOURCES = "targetBreach-surface/target.resourceenvironment";
    }

    @Test
    public void targetBreachBaseTestCompleteAnalysis() {
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
    public void targetScenario() {
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
                .equals("SupplierMachine"))
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
        Assertions.assertEquals(4, pathsDirectlyAfterAnalysis.get(0)
            .getAttackpathelement()
            .size());

        this.pathsTestHelper(changes, entity);
    }
}
