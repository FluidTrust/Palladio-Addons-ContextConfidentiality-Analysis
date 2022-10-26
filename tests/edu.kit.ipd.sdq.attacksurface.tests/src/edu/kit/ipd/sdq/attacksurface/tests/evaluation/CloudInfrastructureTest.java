package edu.kit.ipd.sdq.attacksurface.tests.evaluation;

import static org.junit.jupiter.api.Assertions.fail;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.AttackerFactory;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.PcmIntegrationFactory;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;

public class CloudInfrastructureTest extends EvaluationTest {
    private static final String HYPERVISOR = "_RyWUMaOhEeyg1bkezwUNpA";
    private static final String ROOT = "_sKKUUe4ZEeu1msiU_4h_hw";
    private static final String ROOT_9 = "_VUQ7waOhEeyg1bkezwUNpA";
    private static final String ROOT_10 = "_c06CsaOhEeyg1bkezwUNpA";
    private static final String ROOT_11 = "_gAq0EaOhEeyg1bkezwUNpA";

    private static final String VULN_2012 = "cve-2012-3515";
    private static final String VULN_2013 = "cve-2013-4344";

    public CloudInfrastructureTest() {
        this.PATH_ATTACKER = "cloudInfrastructure/My.attacker";
        this.PATH_ASSEMBLY = "cloudInfrastructure/newAssembly.system";
        this.PATH_ALLOCATION = "cloudInfrastructure/newAllocation.allocation";
        this.PATH_CONTEXT = "cloudInfrastructure/My.context";
        this.PATH_MODIFICATION = "cloudInfrastructure/My.kamp4attackmodificationmarks";
        this.PATH_REPOSITORY = "cloudInfrastructure/NewRepository.repository";
        this.PATH_USAGE = "cloudInfrastructure/newUsageModel.usagemodel";
        this.PATH_RESOURCES = "cloudInfrastructure/newResourceEnvironment.resourceenvironment";
    }

    // Only evaluates whether the generated graph is correct.
    @Test
    public void cloudInfrastructureBaseTest() {
        final var changes = runAnalysisWithoutAttackPathGeneration();
        pathsTestHelper(changes, null);
    }

    // Only evaluates whether the generated graph is correct.
    @Test
    public void cloudInfrastructureBaseTestCompleteAnalysis() {
        final var entity = getSurfaceAttacker().getTargetedElement().getAssemblycontext().get(0);

        final var changes = runAnalysis();
        final var pathsDirectlyAfterAnalysis = changes.getAttackpaths();
        Assertions.assertEquals(14, pathsDirectlyAfterAnalysis.size());
        pathsTestHelper(changes, entity);
    }

    @Test
    void exampleDatabaseHypervisior01() {
        attackHypervisor("DB_VM");
    }

    @Test
    void exampleDatabaseHypervisior02() {
        attackHypervisor("APP_VM");
    }

    private void attackHypervisor(String name) {
        var criteria = getSurfaceAttacker().getFiltercriteria();
        var targetEntity = getSurfaceAttacker().getTargetedElement().getAssemblycontext().get(0);
        criteria.clear();
        var elementFilter = AttackerFactory.eINSTANCE.createStartElementFilterCriterion();
        var componentIntegration = PcmIntegrationFactory.eINSTANCE.createSystemComponent();
        var entity = getFirstEntityByName(name);
        if (entity instanceof AssemblyContext component) {
            componentIntegration.getAssemblycontext().add(component);
            elementFilter.getStartComponents().add(componentIntegration);
            criteria.add(elementFilter);
        } else {
            fail("No AssemblyContext found");
        }
        final var changes = runAnalysis();
        final var paths = changes.getAttackpaths();
        pathsTestHelper(changes, targetEntity);
        Assertions.assertEquals(1, paths.size());
    }

    @Test
    public void graphGenerationTest() {
        runAnalysis();
        generateGraph(false);
    }
}
