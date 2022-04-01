package edu.kit.ipd.sdq.attacksurface.tests.evaluation;


import org.junit.Assert;
import org.junit.jupiter.api.Test;

public class PowerGridTest extends EvaluationTest {
    private static final String ICS_USER = "_lqiu8S8nEeylPOrRpUZy4w";
    private static final String BACKOFFICE_ADMIN = "_YpxbYDirEeyW5vhrbaBM1w";
    private static final String VPN_GATEWAY = "_R3dMsC8sEeylPOrRpUZy4w";
    
    private static final String VULN = "cveWithId_CVE-2014-1761";

    public PowerGridTest() {
        this.PATH_ATTACKER = "powerGrid/My.attacker";
        this.PATH_ASSEMBLY = "powerGrid/powerGrid.system";
        this.PATH_ALLOCATION = "powerGrid/powerGrid.allocation";
        this.PATH_CONTEXT = "powerGrid/My.context";
        this.PATH_MODIFICATION = "powerGrid/My.kamp4attackmodificationmarks";
        this.PATH_REPOSITORY = "powerGrid/powerGrid.repository";
        this.PATH_USAGE = "powerGrid/powerGrid.usagemodel";
        this.PATH_RESOURCES = "powerGrid/powerGrid.resourceenvironment";
    }
    
    @Test
    public void powerGridBaseTest() {
        final var changes = runAnalysisWithoutAttackPathGeneration();
        pathsTestHelper(changes, true, true);
    }
    
    @Test
    public void powerGridBaseTestCompleteAnalysis() {
        final var changes = runAnalysis();
        final var pathsDirectlyAfterAnalysis = changes.getAttackpaths();
        printPaths(pathsDirectlyAfterAnalysis);
        Assert.assertEquals(13, pathsDirectlyAfterAnalysis.size());
        
        pathsTestHelper(changes, true, true);
    }
    
    private void testHelperA (final String critical, final String container) {
        setCriticalAssemblyContext(critical);
        final var changes = runAnalysis();
        final var paths = changes.getAttackpaths();
        final var pathsString = toString(paths);
        System.out.println(pathsString);
        Assert.assertTrue(pathsString.contains("PATH\n"
                + "- | Workstation02\n"
                + "- | AssemblyWithVPNRights\n"
                + VULN + " | AssemblyWithVPNRights\n"
                + BACKOFFICE_ADMIN + " | " + container +"\n"
                + "- | " + critical + "\n"
                + "VULNs used: " + VULN));
    }
    
    @Test
    public void evaluationTestAttackStorageApplicationPath1a() {
        testHelperA("Assembly_StorageApplication", "DataCenter");
    }
    
    @Test
    public void evaluationTestAttackStorageApplicationPath1b() {
        setCriticalAssemblyContext("Assembly_StorageApplication");
        final var changes = runAnalysis();
        final var paths = changes.getAttackpaths();
        final var pathsString = toString(paths);
        Assert.assertTrue(pathsString.contains("PATH\n"
                + VULN + " | AssemblyWithVPNRights\n"
                + BACKOFFICE_ADMIN + " | Workstation02\n"
                + "- | AssemblyWithVPNRights\n"
                + VULN + " | AssemblyWithVPNRights\n"
                + BACKOFFICE_ADMIN + " | DataCenter\n"
                + "- | Assembly_StorageApplication\n"
                + "VULNs used: " + VULN));
    }
    
    @Test
    public void evaluationTestAttackCallCenterApplicationPath2() {
        testHelperA("Assembly_CallCenterApplication", "CallCenter");
    }
    
    
    @Test
    public void evaluationTestAttackExtVpnApplicationPath3() {
        testHelperA("ExternalVPNBridge", "VPNBridgeExternal");
    }
    
    @Test
    public void evaluationTestAttackDMSClientPath4() {
        setCriticalAssemblyContext("DMSClient");
        final var changes = runAnalysis();
        final var paths = changes.getAttackpaths();
        final var pathsString = toString(paths);
        Assert.assertTrue(pathsString.contains("PATH\n"
                + VULN + " | AssemblyWithVPNRights\n"
                + VULN + " | AssemblyWithVPNRights\n"
                + VPN_GATEWAY + " | VPNBridge\n"
                + "- | ICS-VPN-Bridge\n"
                + ICS_USER + " | DMSClientApplication\n"
                + "- | Assembly_DMSClientApplication\n"
                + "VULNs used: " + VULN));
    }
    
    @Test
    public void graphGenerationTest() {
        runAnalysis();
        generateGraph(false);
    }
}
