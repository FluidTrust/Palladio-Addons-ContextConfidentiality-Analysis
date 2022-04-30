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
        this.PATH_ATTACKER = "travelplanner-surface/default.attacker";
        this.PATH_ASSEMBLY = "travelplanner-surface/default.system";
        this.PATH_ALLOCATION = "travelplanner-surface/default.allocation";
        this.PATH_CONTEXT = "travelplanner-surface/default.context";
        this.PATH_MODIFICATION = "travelplanner-surface/default.kamp4attackmodificationmarks";
        this.PATH_REPOSITORY = "travelplanner-surface/default.repository";
        this.PATH_USAGE = "travelplanner-surface/default.usagemodel";
        this.PATH_RESOURCES = "travelplanner-surface/default.resourceenvironment";
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
        setPathLengthFilter(3);
        final var changes = runAnalysis();
        final var pathsDirectlyAfterAnalysis = changes.getAttackpaths();
        printPaths(pathsDirectlyAfterAnalysis);
        areAllPathsThereHelper(pathsDirectlyAfterAnalysis, 3, true, true);
    }

    @Test
    public void evalAnalysisWithMaxPathFilter2() {
        setPathLengthFilter(2);
        final var changes = runAnalysis();
        final var pathsDirectlyAfterAnalysis = changes.getAttackpaths();
        printPaths(pathsDirectlyAfterAnalysis);
        areAllPathsThereHelper(pathsDirectlyAfterAnalysis, 2, true, true);
    }

    @Test
    public void evalAnalysisRootUnusableButVulnerabilityUsable() {
        setRootUnusable();
        final var changes = runAnalysis();
        final var pathsDirectlyAfterAnalysis = changes.getAttackpaths();
        printPaths(pathsDirectlyAfterAnalysis);
        areAllPathsThereHelper(pathsDirectlyAfterAnalysis, 4, true, false);
    }

    @Test
    public void evalAnalysisRootUnusableButVulnerabilityUsableAnd3() {
        setRootUnusable();
        setPathLengthFilter(3);
        final var changes = runAnalysis();
        final var pathsDirectlyAfterAnalysis = changes.getAttackpaths();
        printPaths(pathsDirectlyAfterAnalysis);
        areAllPathsThereHelper(pathsDirectlyAfterAnalysis, 3, true, false);
    }

    @Test
    public void evalAnalysisRootUnusableButVulnerabilityUsableAnd2() {
        setRootUnusable();
        setPathLengthFilter(2);
        final var changes = runAnalysis();
        final var pathsDirectlyAfterAnalysis = changes.getAttackpaths();
        printPaths(pathsDirectlyAfterAnalysis);
        areAllPathsThereHelper(pathsDirectlyAfterAnalysis, 2, true, false);
    }

    @Test
    public void evalAnalysisRootUsableButVulnerabilityNotUsableDueToAttackVector() {
        setVulnerabilityUnusable(true);
        final var changes = runAnalysis();
        final var pathsDirectlyAfterAnalysis = changes.getAttackpaths();
        printPaths(pathsDirectlyAfterAnalysis);
        areAllPathsThereHelper(pathsDirectlyAfterAnalysis, 4, false, true);
    }

    @Test
    public void evalAnalysisRootUsableButVulnerabilityNotUsableDueToAttackVectorAnd3() {
        setVulnerabilityUnusable(true);
        setPathLengthFilter(3);
        final var changes = runAnalysis();
        final var pathsDirectlyAfterAnalysis = changes.getAttackpaths();
        printPaths(pathsDirectlyAfterAnalysis);
        areAllPathsThereHelper(pathsDirectlyAfterAnalysis, 3, false, true);
    }

    @Test
    public void evalAnalysisRootUsableButVulnerabilityNotUsableDueToAttackVectorAnd2() {
        setVulnerabilityUnusable(true);
        setPathLengthFilter(2);
        final var changes = runAnalysis();
        final var pathsDirectlyAfterAnalysis = changes.getAttackpaths();
        printPaths(pathsDirectlyAfterAnalysis);
        areAllPathsThereHelper(pathsDirectlyAfterAnalysis, 2, false, true);
    }

    @Test
    public void evalAnalysisRootUsableButVulnerabilityNotUsableDueToAvailabilityImpact() {
        setVulnerabilityUnusable(false);
        final var changes = runAnalysis();
        final var pathsDirectlyAfterAnalysis = changes.getAttackpaths();
        printPaths(pathsDirectlyAfterAnalysis);
        areAllPathsThereHelper(pathsDirectlyAfterAnalysis, 4, false, true);
    }

    @Test
    public void evalAnalysisRootUsableButVulnerabilityNotUsableDueToAvailabilityImpactAnd3() {
        setVulnerabilityUnusable(false);
        setPathLengthFilter(3);
        final var changes = runAnalysis();
        final var pathsDirectlyAfterAnalysis = changes.getAttackpaths();
        printPaths(pathsDirectlyAfterAnalysis);
        areAllPathsThereHelper(pathsDirectlyAfterAnalysis, 3, false, true);
    }

    @Test
    public void evalAnalysisRootUsableButVulnerabilityNotUsableDueToAvailabilityImpactAnd2() {
        setVulnerabilityUnusable(false);
        setPathLengthFilter(2);
        final var changes = runAnalysis();
        final var pathsDirectlyAfterAnalysis = changes.getAttackpaths();
        printPaths(pathsDirectlyAfterAnalysis);
        areAllPathsThereHelper(pathsDirectlyAfterAnalysis, 2, false, true);
    }

    @Test
    public void evalAnalysisRootAndVulnerabilityUnusableDueToAttackVector() {
        setRootUnusable();
        setVulnerabilityUnusable(true);
        final var changes = runAnalysis();
        final var pathsDirectlyAfterAnalysis = changes.getAttackpaths();
        printPaths(pathsDirectlyAfterAnalysis);
        areAllPathsThereHelper(pathsDirectlyAfterAnalysis, 4, false, false);
    }

    @Test
    public void evalAnalysisRootAndVulnerabilityUnusableDueToAvailabilityImpact() {
        setRootUnusable();
        setVulnerabilityUnusable(false);
        final var changes = runAnalysis();
        final var pathsDirectlyAfterAnalysis = changes.getAttackpaths();
        printPaths(pathsDirectlyAfterAnalysis);
        areAllPathsThereHelper(pathsDirectlyAfterAnalysis, 4, false, false);
    }

    private void setVulnerabilityUnusable(final boolean dueToAttackVector) {
        if (dueToAttackVector) {
            getSurfaceAttacker().getFiltercriteria()
                .stream()
                .filter(ExploitabilityVulnerabilityFilterCriterion.class::isInstance)
                .map(ExploitabilityVulnerabilityFilterCriterion.class::cast)
                .forEach(f -> f.setAttackVectorMaximum(AttackVector.NETWORK));
        } else { // due to availability impact
            getSurfaceAttacker().getFiltercriteria()
            .stream()
            .filter(ImpactVulnerabilityFilterCriterion.class::isInstance)
            .map(ImpactVulnerabilityFilterCriterion.class::cast)
            .forEach(f -> f.setAvailabilityImpactMinimum(AvailabilityImpact.HIGH));
        }
    }

    private void setRootUnusable() {
        final var root = createRootCredentialsIfNecessary();
        getSurfaceAttacker().getFiltercriteria()
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
