package edu.kit.ipd.sdq.attacksurface.tests.change;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import org.eclipse.emf.common.util.EList;
import org.eclipse.emf.ecore.util.EcoreUtil;
import org.junit.Assert;
import org.junit.jupiter.api.Test;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.AttackPath;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.MaximumPathLengthFilterCriterion;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.AttackVector;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.ConfidentialityImpact;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.Privileges;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.PcmIntegrationFactory;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.SystemIntegration;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;

import com.google.common.graph.EndpointPair;

import edu.kit.ipd.sdq.attacksurface.core.AttackSurfaceAnalysis;
import edu.kit.ipd.sdq.attacksurface.core.changepropagation.changes.AssemblyContextPropagationVulnerability;
import edu.kit.ipd.sdq.attacksurface.graph.AttackPathSurface;
import edu.kit.ipd.sdq.attacksurface.graph.AttackStatusEdge;
import edu.kit.ipd.sdq.attacksurface.graph.AttackStatusEdgeContent;
import edu.kit.ipd.sdq.attacksurface.graph.AttackStatusNodeContent;
import edu.kit.ipd.sdq.attacksurface.graph.PCMElementType;
import edu.kit.ipd.sdq.attacksurface.graph.VulnerabilitySurface;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksFactory;

public class PropagationOverviewTest extends AbstractChangeTests {
    private static final String DEFAULT = "default";
    private static final String CRITICAL = "critical";
    private static final String R11 = "R.1.1";
    private static final String R12 = "R.1.2";
    private static final String P21 = "P.2.1";
    private static final String VULN_ID = "TestVulnerabilityId123456";

    private static final boolean IS_ROOT_SELF_ATTACKING = true;
    private static final boolean IS_DEBUG = true;

    public PropagationOverviewTest() {
        this.PATH_ATTACKER = "simpleAttackmodels/DesignOverviewDiaModel/My.attacker";
        this.PATH_ASSEMBLY = "simpleAttackmodels/DesignOverviewDiaModel/My.system";
        this.PATH_ALLOCATION = "simpleAttackmodels/DesignOverviewDiaModel/My.allocation";
        this.PATH_CONTEXT = "simpleAttackmodels/DesignOverviewDiaModel/My.context";
        this.PATH_MODIFICATION = "simpleAttackmodels/DesignOverviewDiaModel/My.kamp4attackmodificationmarks";
        this.PATH_REPOSITORY = "simpleAttackmodels/DesignOverviewDiaModel/My.repository";
        this.PATH_USAGE = "simpleAttackmodels/DesignOverviewDiaModel/My.usagemodel";
        this.PATH_RESOURCES = "simpleAttackmodels/DesignOverviewDiaModel/My.resourceenvironment";
    }

    private void runAssemblyAssemblyPropagation(final CredentialChange change) {
        generateXML();
        final var wrapper = getBlackboardWrapper();
        final var assemblyChange = new AssemblyContextPropagationVulnerability(wrapper, change, getAttackGraph());
        assemblyChange.calculateAssemblyContextToAssemblyContextPropagation();
    }

    private void runSingleIteration(final boolean doChecks) {
        runAssemblyAssemblyPropagation(getChanges());

        if (doChecks) {
            final var criticalNode = getAttackGraph().getRootNodeContent();
            final var criticalEntity = criticalNode.getContainedElement();

            Assert.assertTrue(getAttackGraph().isAnyCompromised(criticalEntity));
            Assert.assertEquals(1, getAttackGraph().getCompromisationCauseIds(criticalNode).size());
            Assert.assertEquals(VULN_ID,
                    getAttackGraph().getCompromisationCauseIds(criticalNode).toArray(String[]::new)[0]);

            final AssemblyContext r11 = getAssemblyContext(R11);
            final var r11Node = getAttackGraph().findNode(new AttackStatusNodeContent(r11));
            Assert.assertTrue(getAttackGraph().isAnyCompromised(r11));
            Assert.assertEquals(1, getAttackGraph().getCompromisationCauseIds(r11Node).size());
            Assert.assertEquals(VULN_ID, getAttackGraph().getCompromisationCauseIds(r11Node).toArray(String[]::new)[0]);

            // check edges
            Assert.assertTrue(getAttackGraph().getEdge(criticalNode, r11Node).contains(VULN_ID));
            Assert.assertTrue(getAttackGraph().getEdge(criticalNode, criticalNode).contains(VULN_ID));
            Assert.assertTrue(getAttackGraph().getEdge(r11Node, r11Node).contains(VULN_ID));
            // all other edges have no causes
            Assert.assertTrue(getAttackGraph().getNodes().stream()
                    .filter(start -> !start.equals(criticalNode) && !start.equals(r11Node))
                    .map(start -> getAttackGraph().getNodes().stream()
                            .filter(end -> !end.equals(criticalNode) && !end.equals(r11Node))
                            .map(end -> getAttackGraph().getEdge(start, end)).collect(Collectors.toSet()))
                    .flatMap(Set::stream).allMatch(e -> e == null || e.getCauseIds().isEmpty()));
        }
    }

    private AssemblyContext getAssemblyContext(final String searchStr) {
        if (searchStr.equals(CRITICAL)) {
            return getAttackGraph().getRootNodeContent().getContainedElementAsPCMElement().getAssemblycontext();
        }

        return getBlackboardWrapper().getAssembly().getAssemblyContexts__ComposedStructure().stream()
                .filter(e -> e.getEntityName().contains(searchStr)).findFirst().orElse(null);
    }

    private void runUntilNotChangedIterations(final boolean doChecks) {
        do {
            getChanges().setChanged(false);
            runSingleIteration(doChecks);
        } while (getChanges().isChanged());
    }

    @Test
    public void assemblyToAssemblyVulnerabilityTest() {
        runSingleIteration(true);
    }

    @Test
    public void assemblyToAssemblyVulnerabilityTestIterate() {
        runUntilNotChangedIterations(true);
    }

    @Test
    public void attackSurfacePathGenerationTest() {
        runUntilNotChangedIterations(true);
        final var attackPaths = getAttackGraph().findAllAttackPaths(getBlackboardWrapper(), getChanges());

        final var attackPathsSet = new HashSet<>(attackPaths);
        final AttackPathSurface[] expectedPaths = { generateSimpleAttackPath(CRITICAL, VULN_ID, CRITICAL, DEFAULT), // self
                                                                                                                    // attack
                generateSimpleAttackPath(CRITICAL, VULN_ID, R11, DEFAULT), // direct attack from r.1.1
                generateSimpleAttackPath(CRITICAL, VULN_ID, // attack via r.1.1 starting from r.1.1
                        R11, VULN_ID, R11, DEFAULT),
                generateSimpleAttackPath(CRITICAL, VULN_ID, // attack via r.1.1 starting from critical
                        R11, VULN_ID, CRITICAL, DEFAULT),
                generateSimpleAttackPath(CRITICAL, VULN_ID, R12, DEFAULT), // attack starting from r.1.2
                generateSimpleAttackPath(CRITICAL, VULN_ID, P21, DEFAULT), // attack starting from p.2.1
        };
        final var expectedPathsSet = new HashSet<>(addSelfLoopPaths(Arrays.asList(expectedPaths)));
        debugsysouts(expectedPathsSet, attackPathsSet);
        Assert.assertEquals(11, attackPaths.size());
        Assert.assertEquals(expectedPathsSet, attackPathsSet);

        attackPaths.forEach(p -> Assert.assertEquals(1, p.getUsedVulnerabilites(getBlackboardWrapper()).size()));
        attackPaths.forEach(p -> Assert.assertTrue(p.getUsedVulnerabilites(getBlackboardWrapper()).stream()
                .map(v -> v.getId()).collect(Collectors.toSet()).contains(VULN_ID)));
    }

    private List<AttackPathSurface> addSelfLoopPaths(final List<AttackPathSurface> paths) {
        final List<AttackPathSurface> allPaths = new ArrayList<>();
        for (final var path : paths) {
            allPaths.add(path);
            final var pathCopy = path.getCopy();
            // add self attack in the end of each path
            if (IS_ROOT_SELF_ATTACKING && (path.size() > 1
                    || !pathCopy.get(0).getNodes().target().equals(pathCopy.get(0).getNodes().source()))) {
                final var edgeContent = new AttackStatusEdgeContent();
                final var vulnSurface = new VulnerabilitySurface(VULN_ID);
                edgeContent.addSet(new HashSet<>(Arrays.asList(vulnSurface)));
                final var rootNode = getAttackGraph().getRootNodeContent();
                final var edge = new AttackStatusEdge(edgeContent, EndpointPair.ordered(rootNode, rootNode));
                pathCopy.add(edge);
                allPaths.add(pathCopy);
            }
        }
        return allPaths;
    }

    private void debugsysouts(final Set<AttackPathSurface> expectedPathsSet, final Set<AttackPathSurface> attackPaths) {
        if (IS_DEBUG) {
            attackPaths.forEach(p -> System.out.println(p));
            System.out.println("--------------------------------\nexpected:");
            expectedPathsSet.forEach(p -> System.out.println(p));
            System.out.println("--------------------------------\nunexpected (is there, but should not be there):");
            attackPaths.forEach(p -> {
                if (!expectedPathsSet.contains(p)) {
                    System.out.println(p);
                }
            });
            System.out.println("--------------------------------\nunexpected (should be there, but is not there):");
            expectedPathsSet.forEach(p -> {
                if (!attackPaths.contains(p)) {
                    System.out.println(p);
                }
            });
        }
    }

    private AttackPathSurface generateSimpleAttackPath(String... elementVuln) {
        final AttackPathSurface ret = new AttackPathSurface();

        for (int i = 0; i < elementVuln.length - 2; i += 2) {
            final var elementSearchStr = elementVuln[i];
            final var vulnIdStr = elementVuln[i + 1];
            final var vulnSurface = new VulnerabilitySurface(vulnIdStr);

            final var assemblyContext = getAssemblyContext(elementSearchStr);
            final var nodeInGraph = getAttackGraph().findNode(new AttackStatusNodeContent(assemblyContext));

            final var nextElement = getAssemblyContext(elementVuln[i + 2]);
            final var nextNode = getAttackGraph().findNode(new AttackStatusNodeContent(nextElement));
            final var edgeContent = new AttackStatusEdgeContent();
            edgeContent.addSet(new HashSet<>(Arrays.asList(vulnSurface)));
            final var edge = new AttackStatusEdge(edgeContent, EndpointPair.ordered(nextNode, nodeInGraph));
            ret.addFirst(edge);
        }

        return ret;
    }

    @Test
    public void filterPathLength0Test() {
        setMaximumPathLength(0);
        final var board = getBlackboardWrapper();
        runUntilNotChangedIterations(false);
        final var pathsConverter = new AttackSurfaceAnalysis(true, board);
        final var attackPathsSurface = getAttackGraph().findAllAttackPaths(board, getChanges());
        final var attackPaths = pathsConverter.toAttackPaths(attackPathsSurface, board);
        Assert.assertTrue(attackPaths.isEmpty());
    }

    private void setMaximumPathLength(int length) {
        getSurfaceAttacker().getFiltercriteria().stream().filter(MaximumPathLengthFilterCriterion.class::isInstance)
                .map(MaximumPathLengthFilterCriterion.class::cast).forEach(m -> m.setMaximumPathLength(length));
    }

    @Test
    public void filterPathLength1Test() {
        setMaximumPathLength(1);
        final var board = getBlackboardWrapper();
        runUntilNotChangedIterations(false);
        final var attackPathsSurface = getAttackGraph().findAllAttackPaths(board, getChanges());
        final var pathsConverter = new AttackSurfaceAnalysis(true, board);
        final var attackPaths = pathsConverter.toAttackPaths(attackPathsSurface, board);
        Assert.assertTrue(attackPaths.isEmpty()); // since there is always the attacker node (path size is counted as
                                                  // node count)
    }

    @Test
    public void filterPathLength2Test() {
        setMaximumPathLength(2);
        final var board = getBlackboardWrapper();
        runUntilNotChangedIterations(false);
        final var attackPathsSurface = getAttackGraph().findAllAttackPaths(board, getChanges());
        final var pathsConverter = new AttackSurfaceAnalysis(true, board);
        final var attackPaths = pathsConverter.toAttackPaths(attackPathsSurface, board);
        Assert.assertFalse(attackPaths.isEmpty());
        attackPaths.forEach(p -> {
            System.out.println("\n");
            p.getPath().forEach(s -> System.out.println(s.getIdOfContent() + " | " + s.getPcmelement().getAssemblycontext().getEntityName()));
        });
        Assert.assertTrue(attackPaths.stream().allMatch(p -> p.getPath().size() == 2));
        final AttackPathSurface[] expectedSurfacePaths = { 
                generateSimpleAttackPath(CRITICAL, VULN_ID, CRITICAL, DEFAULT), // self attack
                generateSimpleAttackPath(CRITICAL, VULN_ID, R11, CRITICAL), // direct attack from r.1.1
                generateSimpleAttackPath(CRITICAL, VULN_ID, R12, DEFAULT), // attack starting from r.1.2
                generateSimpleAttackPath(CRITICAL, VULN_ID, P21, DEFAULT), // attack starting from p.2.1
        };
        Arrays.asList(expectedSurfacePaths).forEach(p -> System.out.println(p));
        final var expectedPaths = pathsConverter.toAttackPaths(
                Arrays.asList(expectedSurfacePaths), board);
        expectedPaths.forEach(p -> {
            System.out.println("\nEXP\n");
            p.getPath().forEach(s -> System.out.println(s.getIdOfContent() + " | " + s.getPcmelement().getAssemblycontext().getEntityName()));
        });
        final var expectedPathsSet = new HashSet<>(expectedPaths);
        Assert.assertEquals(4, attackPaths.size());
        Assert.assertTrue(areAllPathsEquals(expectedPathsSet, attackPaths.stream().collect(Collectors.toSet())));

        attackPaths.forEach(p -> Assert.assertEquals(1, p.getVulnerabilitesUsed().size()));
        attackPaths.forEach(p -> Assert.assertTrue(p.getVulnerabilitesUsed().stream()
                .map(v -> v.getId()).collect(Collectors.toSet()).contains(VULN_ID)));
    }

    private boolean areAllPathsEquals(
                Set<AttackPath> expectedPathsSet, Set<AttackPath> actualPaths) {
        if (expectedPathsSet.size() != actualPaths.size()) {
            return false;
        }
        
        boolean isEquals = true;
        
        for (final var expected : expectedPathsSet) {
            boolean isLocalEquals = false;
            for (final var actual : actualPaths) {
                isLocalEquals |= isPathEquals(expected, actual);
                if (isLocalEquals) {
                    break;
                }
            }
            isEquals = isLocalEquals;
            if (!isEquals) {
                break;
            }
        }
        
        return isEquals;
    }

    private boolean isPathEquals(AttackPath expected, AttackPath actual) {
        if (expected.getPath().size() != actual.getPath().size()) {
            return false;
        }
        final int size = expected.getPath().size();
        for (int i = 0; i < size; i++) {
            final var sysIntegActual = actual.getPath().get(i);
            final var actualEntity = PCMElementType.typeOf(sysIntegActual.getPcmelement())
                    .getEntity(sysIntegActual.getPcmelement());
            final var sysIntegExpected = expected.getPath().get(i);
            final boolean elementEquals = 
                    PCMElementType.typeOf(sysIntegExpected.getPcmelement())
                        .getElementEqualityPredicate(actualEntity).test(sysIntegExpected);
            if (!elementEquals) {
                return false;
            }
            final boolean idOfContentEquals = 
                    Objects.equals(sysIntegExpected.getIdOfContent(), sysIntegActual.getIdOfContent());
            if (!idOfContentEquals) {
                return false;
            }
        }
        return true;
    }

    @Test
    public void attackPathGenerationTest() {
        final var pathsConverter = new AttackSurfaceAnalysis();
        final var allAttackPathsSurface = getAttackGraph().findAllAttackPaths(getBlackboardWrapper(), getChanges());
        final var attackPaths = pathsConverter.toAttackPaths(allAttackPathsSurface, getBlackboardWrapper());

        Assert.assertEquals(allAttackPathsSurface.size(), attackPaths.size());
        for (int i = 0; i < attackPaths.size(); i++) {
            final var attackPath = attackPaths.get(i);
            final var path = attackPath.getPath();
            final var surface = allAttackPathsSurface.get(i);
            final var nodeList = getNodeList(surface);
            Assert.assertEquals(nodeList.size(), path.size());
            for (int c = 0; c < path.size(); c++) {
                final var nodeEntity = nodeList.get(c).getContainedElement();
                final var edgeCauseIds = getEdgeCauseIdsOfNodeIndex(surface, c);

                final var sysInteg = path.get(c);
                final var pcmElement = sysInteg.getPcmelement();
                final var entity = PCMElementType.typeOf(pcmElement).getEntity(pcmElement);
                Assert.assertTrue(EcoreUtil.equals(nodeEntity, entity));

                final var causeId = sysInteg.getIdOfContent();
                Assert.assertTrue(edgeCauseIds.contains(causeId)); // TODO show also that all edge cause ids are
                                                                   // represented

                Assert.assertEquals(1, attackPath.getVulnerabilitesUsed().size());
                Assert.assertTrue(attackPath.getVulnerabilitesUsed().stream().map(v -> v.getId())
                        .collect(Collectors.toSet()).contains(VULN_ID));
            }
        }
    }

    private Set<String> getEdgeCauseIdsOfNodeIndex(final AttackPathSurface surface, final int nodeIndex) {
        final int edgeIndex = nodeIndex;
        return surface.get(edgeIndex).getContent().getCauseIds();
    }

    private List<AttackStatusNodeContent> getNodeList(final AttackPathSurface surface) {
        return surface.stream().map(e -> e.getNodes()).map(n -> Arrays.asList(n.source(), n.target()))
                .reduce(new LinkedList<>(), (a, b) -> {
                    final List<AttackStatusNodeContent> ret = new LinkedList<>();
                    ret.addAll(a);
                    ret.add(b.get(1)); // b.get(0) ^= a.get(1), so only b.get(1) needs to be added
                    return ret;
                });
    }
}
