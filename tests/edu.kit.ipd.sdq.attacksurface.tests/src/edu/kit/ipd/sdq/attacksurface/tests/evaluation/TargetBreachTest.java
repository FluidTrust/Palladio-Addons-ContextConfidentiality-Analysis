package edu.kit.ipd.sdq.attacksurface.tests.evaluation;


import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

import org.junit.Assert;
import org.junit.jupiter.api.Test;

public class TargetBreachTest extends EvaluationTest {
    private static final String USAGE_SUPPLIER = "_UPJtMAyYEeyaBLrK9rfqSA";
    private static final String DOMAIN_ADMIN = "_zklkoDf-Eey5OtKYIVrxdg";
    
    private static final String VULN_DEFAULT_PSW = "__G2OAAo3EeyKMtWTxnyP1g";
    private static final String VULN_WEAK_PSW = "_66uiMDfyEey5OtKYIVrxdg";
    private static final String VULN_ATTACKER_BUSINESS = "_owpDMApGEeyKMtWTxnyP1g";

    public TargetBreachTest() {
        this.PATH_ATTACKER = "targetBreach/My.attacker";
        this.PATH_ASSEMBLY = "targetBreach/target.system";
        this.PATH_ALLOCATION = "targetBreach/target.allocation";
        this.PATH_CONTEXT = "targetBreach/target.context";
        this.PATH_MODIFICATION = "targetBreach/target.kamp4attackmodificationmarks";
        this.PATH_REPOSITORY = "targetBreach/target.repository";
        this.PATH_USAGE = "targetBreach/target.usagemodel";
        this.PATH_RESOURCES = "targetBreach/target.resourceenvironment";
    }
    
    @Test
    public void targetBreachBaseTest() {
        final var changes = runAnalysisWithoutAttackPathGeneration();
        pathsTestHelper(changes, false, false);
    }
    
    @Test
    public void targetBreachBaseTestCompleteAnalysis() {
        final var changes = runAnalysis();
        final var pathsDirectlyAfterAnalysis = changes.getAttackpaths();
        printPaths(pathsDirectlyAfterAnalysis);
        Assert.assertEquals(826, pathsDirectlyAfterAnalysis.size());
        
        pathsTestHelper(changes, false, false);
    }
    
    @Test
    public void targetBreachBaseTestMax3Analysis() {
        setPathLengthFilter(3);
        final var changes = runAnalysis();
        final var pathsDirectlyAfterAnalysis = changes.getAttackpaths();
        printPaths(pathsDirectlyAfterAnalysis);
        Assert.assertEquals(18, pathsDirectlyAfterAnalysis.size());
        
        pathsTestHelper(changes, false, false);
    }
    
    @Test
    public void targetBreachBaseTestMax2Analysis() {
        setPathLengthFilter(2);
        final var changes = runAnalysis();
        final var pathsDirectlyAfterAnalysis = changes.getAttackpaths();
        printPaths(pathsDirectlyAfterAnalysis);
        Assert.assertEquals(3, pathsDirectlyAfterAnalysis.size());
        
        pathsTestHelper(changes, false, false);
    }
    
    @Test
    public void evaluationTestAttackStorageApplicationPath1() {
        setCriticalAssemblyContext("Assembly_BusinessServiceComponent");
        setPathLengthFilter(2);
        final var changes = runAnalysis();
        final var paths = changes.getAttackpaths();
        final var pathsString = toString(paths);
        Assert.assertTrue(pathsString.contains("PATH\n"
                + "- | Assembly_ExternalSupplier\n"
                + VULN_ATTACKER_BUSINESS + " | Assembly_BusinessServiceComponent\n"
                + "VULNs used: " + VULN_ATTACKER_BUSINESS));
    }
    
    @Test
    public void evaluationTestAttackStorageApplicationPath2a() {
        setCriticalAssemblyContext("Assembly_FTPComponent");
        final var changes = runAnalysis();
        final var paths = changes.getAttackpaths();
        final var pathsString = toString(paths);
        Assert.assertTrue(pathsString.contains("PATH\n"
                + "- | Assembly_BusinessServiceComponent\n"
                + VULN_DEFAULT_PSW + " | Assembly_POSComponent1\n"
                + VULN_DEFAULT_PSW + " | Assembly_FTPComponent\n"
                + "VULNs used: " + VULN_DEFAULT_PSW));
    }
    
    @Test
    public void evaluationTestAttackStorageApplicationPath2b() {
        setCriticalAssemblyContext("Assembly_FTPComponent");
        final var changes = runAnalysis();
        final var paths = changes.getAttackpaths();
        final var pathsString = toString(paths);
        Assert.assertTrue(pathsString.contains("PATH\n"
                + "- | Assembly_BusinessServiceComponent\n"
                + VULN_DEFAULT_PSW + " | Assembly_POSComponent2\n"
                + VULN_DEFAULT_PSW + " | Assembly_FTPComponent\n"
                + "VULNs used: " + VULN_DEFAULT_PSW));
    }
    
    @Test
    public void evaluationTestAttackStorageApplicationPath2c() {
        setCriticalAssemblyContext("Assembly_FTPComponent");
        final var changes = runAnalysis();
        final var paths = changes.getAttackpaths();
        final var pathsString = toString(paths);
        System.out.println(pathsString);
        Assert.assertTrue(pathsString.contains("PATH\n"
                + "- | Assembly_BusinessServiceComponent\n"
                + VULN_WEAK_PSW + " | Assembly_POSComponent3\n"
                + VULN_DEFAULT_PSW + " | Assembly_FTPComponent\n"
                + "VULNs used: " + VULN_WEAK_PSW + "\n"
                + "VULNs used: " + VULN_DEFAULT_PSW));
    }
    
    @Test
    public void evaluationTestAttackStorageApplicationPath3a() {
        setCriticalAssemblyContext("Assembly_FTPComponent");
        final var changes = runAnalysis();
        final var paths = changes.getAttackpaths();
        final var pathsString = toString(paths, "Supplier");
        System.out.println(pathsString);
        Assert.assertTrue(pathsString.contains("PATH\n"
                + "- | Assembly_ExternalSupplier\n"
                + VULN_ATTACKER_BUSINESS + " | Assembly_BusinessServiceComponent\n"
                + VULN_DEFAULT_PSW + " | Assembly_POSComponent1\n"
                + VULN_DEFAULT_PSW + " | Assembly_POSComponent1\n"
                + VULN_DEFAULT_PSW + " | Assembly_FTPComponent\n"
                + "VULNs used: " + VULN_DEFAULT_PSW + "\n"
                + "VULNs used: " + VULN_ATTACKER_BUSINESS));
    }
    
    @Test
    public void evaluationTestAttackStorageApplicationPath3b() {
        setCriticalAssemblyContext("Assembly_FTPComponent");
        final var changes = runAnalysis();
        final var paths = changes.getAttackpaths();
        final var pathsString = toString(paths, "Supplier");
        System.out.println(pathsString);
        Assert.assertTrue(pathsString.contains("PATH\n"
                + "- | Assembly_ExternalSupplier\n"
                + VULN_ATTACKER_BUSINESS + " | Assembly_BusinessServiceComponent\n"
                + VULN_DEFAULT_PSW + " | Assembly_POSComponent2\n"
                + VULN_DEFAULT_PSW + " | Assembly_POSComponent2\n"
                + VULN_DEFAULT_PSW + " | Assembly_FTPComponent\n"
                + "VULNs used: " + VULN_DEFAULT_PSW + "\n"
                + "VULNs used: " + VULN_ATTACKER_BUSINESS));
    }
    
    @Test //TODO later: does not work --> fix
    public void evaluationTestAttackStorageApplicationPath3c() throws IOException {
        setCriticalAssemblyContext("Assembly_FTPComponent");
        final var changes = runAnalysis();
        final var paths = changes.getAttackpaths();
        final var pathsString = toString(paths, "Supplier");
        System.out.println(pathsString);
        Assert.assertTrue(pathsString.contains("PATH\n"
                + "- | Assembly_ExternalSupplier\n"
                + VULN_ATTACKER_BUSINESS + " | Assembly_BusinessServiceComponent\n"
                + VULN_WEAK_PSW + " | Assembly_POSComponent3\n"
                + VULN_WEAK_PSW + " | Assembly_POSComponent3\n"
                + VULN_DEFAULT_PSW + " | Assembly_FTPComponent\n"
                + "VULNs used: " + VULN_WEAK_PSW + "\n"
                + "VULNs used: " + VULN_DEFAULT_PSW + "\n"
                + "VULNs used: " + VULN_ATTACKER_BUSINESS));
    }
    
    @Test
    public void graphGenerationTest() {
        runAnalysis();
        generateGraph(false);
    }
}
