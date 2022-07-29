package edu.kit.ipd.sdq.attacksurface.tests.evaluation;

import org.junit.Assert;
import org.junit.jupiter.api.Test;

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
        pathsTestHelper(changes, true, true);
    }

    // Only evaluates whether the generated graph is correct.
    @Test
    public void cloudInfrastructureBaseTestCompleteAnalysis() {
        final var changes = runAnalysis();
        final var pathsDirectlyAfterAnalysis = changes.getAttackpaths();
        Assert.assertEquals(14, pathsDirectlyAfterAnalysis.size());
        pathsTestHelper(changes, true, true);
    }

    @Test
    public void evaluationTestExample1Test2013() {
        final var changes = runAnalysis();
        final var paths = changes.getAttackpaths();
        final var pathsString = toString(paths);
        Assert.assertTrue(pathsString.contains("PATH\n"
                + "- | Assembly_DBVM\n"
                + VULN_2013 + " | Assembly_Hypervisor\n"
                + HYPERVISOR + " | DB VM Server\n"
                + "- | Assembly_Target_VM\n"
                + "VULNs used: " + VULN_2013));
    }

    @Test
    public void evaluationTestExample1Test2012() {
        final var changes = runAnalysis();
        final var paths = changes.getAttackpaths();
        final var pathsString = toString(paths);
        Assert.assertTrue(pathsString.contains("PATH\n"
                + VULN_2012 + " | Assembly_Source_VM\n"
                + VULN_2012 + " | Assembly_Source_VM\n"
                + HYPERVISOR + " | DB VM Server\n"
                + "- | Assembly_Target_VM\n"
                + "VULNs used: " + VULN_2012));
    }

    @Test
    public void evaluationTestExample2TestContainer() {
        setCriticalResourceContainer("Storage");
        final var changes = runAnalysis();
        final var paths = changes.getAttackpaths();
        final var pathsString = toString(paths);
        Assert.assertTrue(pathsString.contains("PATH\n"
                + "credentials initally necessary: " + ROOT + "\n"
                + "- | Nexus 7000 management device\n"
                + "- | Storage Device\n"
                + ROOT + " | Storage Device"));
    }

    @Test
    public void evaluationTestExample2TestContComponent() {
        setCriticalAssemblyContext("Stored");
        final var changes = runAnalysis();
        final var paths = changes.getAttackpaths();
        final var pathsString = toString(paths);
        Assert.assertTrue(pathsString.contains("PATH\n"
                + "credentials initally necessary: " + ROOT + "\n"
                + "- | Nexus 7000 management device\n"
                + "- | Storage Device\n"
                + ROOT + " | Storage Device\n"
                + "- | Stored VMs"));
    }

    @Test
    public void evaluationTestPath1Adapted() {
        setCriticalAssemblyContext("Stored");
        final var changes = runAnalysis();
        final var paths = changes.getAttackpaths();
        final var pathsString = toString(paths);
        Assert.assertTrue(pathsString.contains("PATH\n"
                + "credentials initally necessary: " + ROOT + "\n"
                + "- | Bridge 2-3\n"
                + "- | Storage Device\n"
                + ROOT + " | Storage Device\n"
                + "- | Stored VMs"));
    }

    @Test
    public void evaluationTestPath3HttpToApplication() {
        setCriticalResourceContainer("Application");
        final var changes = runAnalysis();
        final var paths = changes.getAttackpaths();
        final var pathsString = toString(paths);
        Assert.assertTrue(pathsString.contains("PATH\n"
                + "credentials initally necessary: " + ROOT_10 + "\n"
                + "credentials initally necessary: " + ROOT_11 + "\n"
                + ROOT_11 + " | http VM Server\n"
                + ROOT_11 + " | http VM Server\n"
                + "- | Application VM Server\n"
                + ROOT_10 + " | Application VM Server"));
    }

    @Test
    public void evaluationTestPath3ApplicationToFtp() {
        setCriticalResourceContainer("ftp");
        final var changes = runAnalysis();
        final var paths = changes.getAttackpaths();
        final var pathsString = toString(paths);
        Assert.assertTrue(pathsString.contains("PATH\n"
                + "credentials initally necessary: " + ROOT_9 +"\n"
                + "credentials initally necessary: " + ROOT_10 + "\n"
                + ROOT_10 + " | Application VM Server\n"
                + ROOT_10 + " | Application VM Server\n"
                + "- | ftp VM Server\n"
                + ROOT_9 + " | ftp VM Server"));
    }

    @Test
    public void evaluationTestPath4() {
        setCriticalResourceContainer("ftp");
        final var changes = runAnalysis();
        final var paths = changes.getAttackpaths();
        final var pathsString = toString(paths);
        Assert.assertTrue(pathsString.contains("PATH\n"
                + "credentials initally necessary: " + ROOT_9 +"\n"
                + ROOT_9 + " | ftp VM Server\n"
                + ROOT_9 + " | ftp VM Server"));
    }

    @Test
    public void graphGenerationTest() {
        runAnalysis();
        generateGraph(false);
    }
}
