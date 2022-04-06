package edu.kit.ipd.sdq.attacksurface.tests.evaluation;

import java.util.List;

import org.junit.Assert;
import org.junit.jupiter.api.Test;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.AttackPath;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.ExploitabilityVulnerabilityFilterCriterion;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.ImpactVulnerabilityFilterCriterion;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.InitialCredentialFilterCriterion;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.AttackVector;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.AvailabilityImpact;

public class TravelPlannerTest extends EvaluationTest {
    private static final String VULN = "_CiKb4LM9EeyQ67qz7PIV5Q";
    private static final String CRED_ROOT = "_aOs_IbM8EeyQ67qz7PIV5Q";

    public TravelPlannerTest() {
        this.PATH_ATTACKER = "travelplanner/default.attacker";
        this.PATH_ASSEMBLY = "travelplanner/default.system";
        this.PATH_ALLOCATION = "travelplanner/default.allocation";
        this.PATH_CONTEXT = "travelplanner/default.context";
        this.PATH_MODIFICATION = "travelplanner/default.kamp4attackmodificationmarks";
        this.PATH_REPOSITORY = "travelplanner/default.repository";
        this.PATH_USAGE = "travelplanner/default.usagemodel";
        this.PATH_RESOURCES = "travelplanner/default.resourceenvironment";
    }
    
    @Test
    public void travelplannerBaseTest() {
        final var changes = runAnalysisWithoutAttackPathGeneration();
        pathsTestHelper(changes, false, true);
    }
    
    @Test
    public void travelplannerBaseTestCompleteAnalysis() {
        final var changes = runAnalysis();
        final var pathsDirectlyAfterAnalysis = changes.getAttackpaths();
        printPaths(pathsDirectlyAfterAnalysis);
        Assert.assertEquals(8, pathsDirectlyAfterAnalysis.size());
        pathsTestHelper(changes, false, true);
    }
    
    private void areAllPathsThereHelper(final List<AttackPath> paths,
            final int maxPathLength, final boolean allowVuln, final boolean allowRootCred) {
        final var pathsString = toString(paths);
        if (allowVuln) {
            if (maxPathLength < 3) {
                Assert.assertTrue(paths.isEmpty());
                return;
            } else {
                Assert.assertTrue(pathsString.contains("3 PATH\n"
                        + "- | TravelPlanner <TravelPlanner>\n"
                        + VULN + " | TravelAgency <TravelAgency>\n"
                        + CRED_ROOT + " | AgencyServer\n"
                        + "VULNs used: " + VULN));
                Assert.assertTrue(pathsString.contains("3 PATH\n"
                        + "- | Airline <Airline>\n"
                        + VULN + " | TravelAgency <TravelAgency>\n"
                        + CRED_ROOT + " | AgencyServer\n"
                        + "VULNs used: " + VULN));
                Assert.assertTrue(pathsString.contains("3 PATH\n"
                        + "- | AirlineServer\n"
                        + VULN + " | TravelAgency <TravelAgency>\n"
                        + CRED_ROOT + " | AgencyServer\n"
                        + "VULNs used: " + VULN));
                Assert.assertTrue(pathsString.contains("3 PATH\n"
                        + VULN + " | TravelAgency <TravelAgency>\n"
                        + VULN + " | TravelAgency <TravelAgency>\n"
                        + CRED_ROOT + " | AgencyServer\n"
                        + "VULNs used: " + VULN));
            }
        
            if (maxPathLength >= 4) {
                Assert.assertEquals(8, paths.size());
                
                Assert.assertTrue(pathsString.contains("4 PATH\n"
                    + "- | TravelPlanner <TravelPlanner>\n"
                    + VULN + " | TravelAgency <TravelAgency>\n"
                    + VULN + " | TravelAgency <TravelAgency>\n"
                    + CRED_ROOT + " | AgencyServer\n"
                    + "VULNs used: " + VULN));
                Assert.assertTrue(pathsString.contains("4 PATH\n"
                        + "- | Airline <Airline>\n"
                        + VULN + " | TravelAgency <TravelAgency>\n"
                        + VULN + " | TravelAgency <TravelAgency>\n"
                        + CRED_ROOT + " | AgencyServer\n"
                        + "VULNs used: " + VULN));
                Assert.assertTrue(pathsString.contains("4 PATH\n"
                        + "- | AirlineServer\n"
                        + VULN + " | TravelAgency <TravelAgency>\n"
                        + VULN + " | TravelAgency <TravelAgency>\n"
                        + CRED_ROOT + " | AgencyServer\n"
                        + "VULNs used: " + VULN));
                Assert.assertTrue(pathsString.contains("4 PATH\n"
                        + "- | AgencyServer\n"
                        + "- | TravelAgency <TravelAgency>\n"
                        + VULN + " | TravelAgency <TravelAgency>\n"
                        + CRED_ROOT + " | AgencyServer\n"
                        + "VULNs used: " + VULN));
            } else {
                Assert.assertEquals(4, paths.size());
                Assert.assertTrue(paths
                        .stream()
                        .allMatch(p -> p.getPath().size() <= 3));
            }
        } else {
            // no vulnerability attacks --> initial credentials necessary
            if (allowRootCred) {
                Assert.assertTrue(pathsString.contains("2 PATH\n"
                        + "credentials initally necessary: " + CRED_ROOT + "\n"
                        + CRED_ROOT + " | AgencyServer\n"
                        + CRED_ROOT + " | AgencyServer"));
                if (maxPathLength < 3) {
                    Assert.assertEquals(1, paths.size());
                } else {
                    Assert.assertTrue(pathsString.contains("3 PATH\n"
                            + "credentials initally necessary: " + CRED_ROOT + "\n"
                            + "- | TravelPlanner <TravelPlanner>\n"
                            + "- | AgencyServer\n"
                            + CRED_ROOT + " | AgencyServer"));
                    Assert.assertTrue(pathsString.contains("3 PATH\n"
                            + "credentials initally necessary: " + CRED_ROOT + "\n"
                            + "- | Airline <Airline>\n"
                            + "- | AgencyServer\n"
                            + CRED_ROOT + " | AgencyServer"));
                    Assert.assertTrue(pathsString.contains("3 PATH\n"
                            + "credentials initally necessary: " + CRED_ROOT + "\n"
                            + "- | TravelAgency <TravelAgency>\n"
                            + "- | AgencyServer\n"
                            + CRED_ROOT + " | AgencyServer"));
                    Assert.assertTrue(pathsString.contains("3 PATH\n"
                            + "credentials initally necessary: " + CRED_ROOT + "\n"
                            + "- | AirlineServer\n"
                            + "- | AgencyServer\n"
                            + CRED_ROOT + " | AgencyServer"));
                }
            } else {
                Assert.assertTrue(paths.isEmpty());
            }
        }
    }
    
    @Test
    public void evalAnalysisWithoutFilters() {
        getSurfaceAttacker().getFiltercriteria().clear();
        final var changes = runAnalysis();
        final var pathsDirectlyAfterAnalysis = changes.getAttackpaths();
        printPaths(pathsDirectlyAfterAnalysis);
        areAllPathsThereHelper(pathsDirectlyAfterAnalysis, 4, true, true);
    }
    
    @Test
    public void evalAnalysisWithNotFilteringFilters() {
        final var changes = runAnalysis();
        final var pathsDirectlyAfterAnalysis = changes.getAttackpaths();
        printPaths(pathsDirectlyAfterAnalysis);
        areAllPathsThereHelper(pathsDirectlyAfterAnalysis, 4, true, true);
    }
    
    @Test
    public void evalAnalysisWithMaxPathFilter3() {
        this.setPathLengthFilter(3);
        final var changes = runAnalysis();
        final var pathsDirectlyAfterAnalysis = changes.getAttackpaths();
        printPaths(pathsDirectlyAfterAnalysis);
        areAllPathsThereHelper(pathsDirectlyAfterAnalysis, 3, true, true);
    }
    
    @Test
    public void evalAnalysisWithMaxPathFilter2() {
        this.setPathLengthFilter(2);
        final var changes = runAnalysis();
        final var pathsDirectlyAfterAnalysis = changes.getAttackpaths();
        printPaths(pathsDirectlyAfterAnalysis);
        areAllPathsThereHelper(pathsDirectlyAfterAnalysis, 2, true, true);
    }
    
    @Test
    public void evalAnalysisRootUnusableButVulnerabilityUsable() {
        this.setRootUnusable();
        final var changes = runAnalysis();
        final var pathsDirectlyAfterAnalysis = changes.getAttackpaths();
        printPaths(pathsDirectlyAfterAnalysis);
        areAllPathsThereHelper(pathsDirectlyAfterAnalysis, 4, true, false);
    }
    
    @Test
    public void evalAnalysisRootUnusableButVulnerabilityUsableAnd3() {
        this.setRootUnusable();
        this.setPathLengthFilter(3);
        final var changes = runAnalysis();
        final var pathsDirectlyAfterAnalysis = changes.getAttackpaths();
        printPaths(pathsDirectlyAfterAnalysis);
        areAllPathsThereHelper(pathsDirectlyAfterAnalysis, 3, true, false);
    }
    
    @Test
    public void evalAnalysisRootUnusableButVulnerabilityUsableAnd2() {
        this.setRootUnusable();
        this.setPathLengthFilter(2);
        final var changes = runAnalysis();
        final var pathsDirectlyAfterAnalysis = changes.getAttackpaths();
        printPaths(pathsDirectlyAfterAnalysis);
        areAllPathsThereHelper(pathsDirectlyAfterAnalysis, 2, true, false);
    }
    
    @Test
    public void evalAnalysisRootUsableButVulnerabilityNotUsableDueToAttackVector() {
        this.setVulnerabilityUnusable(true);
        final var changes = runAnalysis();
        final var pathsDirectlyAfterAnalysis = changes.getAttackpaths();
        printPaths(pathsDirectlyAfterAnalysis);
        areAllPathsThereHelper(pathsDirectlyAfterAnalysis, 4, false, true);
    }
    
    @Test
    public void evalAnalysisRootUsableButVulnerabilityNotUsableDueToAttackVectorAnd3() {
        this.setVulnerabilityUnusable(true);
        this.setPathLengthFilter(3);
        final var changes = runAnalysis();
        final var pathsDirectlyAfterAnalysis = changes.getAttackpaths();
        printPaths(pathsDirectlyAfterAnalysis);
        areAllPathsThereHelper(pathsDirectlyAfterAnalysis, 3, false, true);
    }
    
    @Test
    public void evalAnalysisRootUsableButVulnerabilityNotUsableDueToAttackVectorAnd2() {
        this.setVulnerabilityUnusable(true);
        this.setPathLengthFilter(2);
        final var changes = runAnalysis();
        final var pathsDirectlyAfterAnalysis = changes.getAttackpaths();
        printPaths(pathsDirectlyAfterAnalysis);
        areAllPathsThereHelper(pathsDirectlyAfterAnalysis, 2, false, true);
    }
    
    @Test
    public void evalAnalysisRootUsableButVulnerabilityNotUsableDueToAvailabilityImpact() {
        this.setVulnerabilityUnusable(false);
        final var changes = runAnalysis();
        final var pathsDirectlyAfterAnalysis = changes.getAttackpaths();
        printPaths(pathsDirectlyAfterAnalysis);
        areAllPathsThereHelper(pathsDirectlyAfterAnalysis, 4, false, true);
    }
    
    @Test
    public void evalAnalysisRootAndVulnerabilityUnusableDueToAttackVector() {
        this.setRootUnusable();
        this.setVulnerabilityUnusable(true);
        final var changes = runAnalysis();
        final var pathsDirectlyAfterAnalysis = changes.getAttackpaths();
        printPaths(pathsDirectlyAfterAnalysis);
        areAllPathsThereHelper(pathsDirectlyAfterAnalysis, 4, false, false);
    }
    
    @Test
    public void evalAnalysisRootAndVulnerabilityUnusableDueToAvailabilityImpact() {
        this.setRootUnusable();
        this.setVulnerabilityUnusable(false);
        final var changes = runAnalysis();
        final var pathsDirectlyAfterAnalysis = changes.getAttackpaths();
        printPaths(pathsDirectlyAfterAnalysis);
        areAllPathsThereHelper(pathsDirectlyAfterAnalysis, 4, false, false);
    }
    
    private void setVulnerabilityUnusable(final boolean dueToAttackVector) {
        if (dueToAttackVector) {
            this.getSurfaceAttacker().getFiltercriteria()
                .stream()
                .filter(ExploitabilityVulnerabilityFilterCriterion.class::isInstance)
                .map(ExploitabilityVulnerabilityFilterCriterion.class::cast)
                .forEach(f -> f.setAttackVectorMaximum(AttackVector.NETWORK));
        } else { // due to availability impact
            this.getSurfaceAttacker().getFiltercriteria()
            .stream()
            .filter(ImpactVulnerabilityFilterCriterion.class::isInstance)
            .map(ImpactVulnerabilityFilterCriterion.class::cast)
            .forEach(f -> f.setAvailabilityImpactMinimum(AvailabilityImpact.HIGH));
        }
    }

    private void setRootUnusable() {
        final var root = createRootCredentialsIfNecessary();
        this.getSurfaceAttacker().getFiltercriteria()
            .stream()
            .filter(InitialCredentialFilterCriterion.class::isInstance)
            .map(InitialCredentialFilterCriterion.class::cast)
            .forEach(f -> f.getProhibitedInitialCredentials().add(root));
    }

    @Test
    public void graphGenerationTest() {
        runAnalysis();
        generateGraph(false);
    }
}