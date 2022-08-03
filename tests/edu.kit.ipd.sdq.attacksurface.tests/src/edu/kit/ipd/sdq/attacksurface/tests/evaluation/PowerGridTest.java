package edu.kit.ipd.sdq.attacksurface.tests.evaluation;


import org.junit.Assert;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.AttackerFactory;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.PcmIntegrationFactory;

public class PowerGridTest extends EvaluationTest {
    private static final String ICS_USER = "_lqiu8S8nEeylPOrRpUZy4w";
    private static final String BACKOFFICE_ADMIN = "_YpxbYDirEeyW5vhrbaBM1w";
    private static final String VPN_GATEWAY = "_R3dMsC8sEeylPOrRpUZy4w";

    private static final String VULN = "cveWithId_CVE-2014-1761";

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
        var entity = getSurfaceAttacker().getTargetedElement().getAssemblycontext().get(0);
        final var changes = runAnalysisWithoutAttackPathGeneration();
        pathsTestHelper(changes, entity);
    }

    @Test
    public void powerGridBaseTestCompleteAnalysis() {
        var entity = getSurfaceAttacker().getTargetedElement().getAssemblycontext().get(0);
        final var changes = runAnalysis();
        final var pathsDirectlyAfterAnalysis = changes.getAttackpaths();
        Assert.assertEquals(15, pathsDirectlyAfterAnalysis.size());

        pathsTestHelper(changes, entity);
    }

    @Test
    public void attackScenario() {
        var entity = getSurfaceAttacker().getTargetedElement().getAssemblycontext().get(0);
        var startFilter = AttackerFactory.eINSTANCE.createStartElementFilterCriterion();
        var pcmElement = PcmIntegrationFactory.eINSTANCE.createResourceEnvironmentElement();
        var resource = getBlackboardWrapper().getResourceEnvironment().getResourceContainer_ResourceEnvironment()
                .stream().filter(e -> e.getEntityName().equals("Workstation01")).findAny();
        Assertions.assertTrue(resource.isPresent());
        pcmElement.setResourcecontainer(resource.get());
        startFilter.getStartResources().add(pcmElement);
        getSurfaceAttacker().getFiltercriteria().add(startFilter);

        final var changes = runAnalysis();
        final var pathsDirectlyAfterAnalysis = changes.getAttackpaths();

        Assertions.assertEquals(1, pathsDirectlyAfterAnalysis.size());
        Assertions.assertEquals(6, pathsDirectlyAfterAnalysis.get(0).getAttackpathelement().size());
        pathsTestHelper(changes, entity);

    }

}
