package edu.kit.ipd.sdq.attacksurface.tests.evaluation;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.StringJoiner;
import java.util.stream.Collectors;

import org.eclipse.emf.cdo.CDOLock;
import org.eclipse.emf.cdo.CDOObjectHistory;
import org.eclipse.emf.cdo.CDOState;
import org.eclipse.emf.cdo.common.id.CDOID;
import org.eclipse.emf.cdo.common.lock.CDOLockState;
import org.eclipse.emf.cdo.common.revision.CDORevision;
import org.eclipse.emf.cdo.common.security.CDOPermission;
import org.eclipse.emf.cdo.eresource.CDOResource;
import org.eclipse.emf.cdo.view.CDOView;
import org.eclipse.emf.common.notify.Adapter;
import org.eclipse.emf.common.notify.Notification;
import org.eclipse.emf.common.util.EList;
import org.eclipse.emf.common.util.TreeIterator;
import org.eclipse.emf.ecore.EClass;
import org.eclipse.emf.ecore.EObject;
import org.eclipse.emf.ecore.EOperation;
import org.eclipse.emf.ecore.EReference;
import org.eclipse.emf.ecore.EStructuralFeature;
import org.eclipse.emf.ecore.resource.Resource;
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
import org.palladiosimulator.pcm.confidentiality.context.system.UsageSpecification;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;

import com.google.common.graph.EndpointPair;

import de.uka.ipd.sdq.identifier.Identifier;
import edu.kit.ipd.sdq.attacksurface.core.AttackSurfaceAnalysis;
import edu.kit.ipd.sdq.attacksurface.core.changepropagation.changes.AssemblyContextPropagationVulnerability;
import edu.kit.ipd.sdq.attacksurface.graph.AttackPathSurface;
import edu.kit.ipd.sdq.attacksurface.graph.AttackStatusEdge;
import edu.kit.ipd.sdq.attacksurface.graph.AttackStatusEdgeContent;
import edu.kit.ipd.sdq.attacksurface.graph.AttackStatusNodeContent;
import edu.kit.ipd.sdq.attacksurface.graph.PCMElementType;
import edu.kit.ipd.sdq.attacksurface.graph.VulnerabilitySurface;
import edu.kit.ipd.sdq.attacksurface.tests.change.AbstractChangeTests;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksFactory;
import edu.kit.kastel.sdq.kamp4attack.graph.impl.output.DotCreation;

public class CloudInfrastructureTest extends AbstractChangeTests {
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

    private void runAssemblyAssemblyPropagation(final CredentialChange change) {
        generateXML();
        final var wrapper = getBlackboardWrapper();
        final var assemblyChange = new AssemblyContextPropagationVulnerability(wrapper, change, getAttackGraph());
        assemblyChange.calculateAssemblyContextToAssemblyContextPropagation();
    }

    private AssemblyContext getAssemblyContext(final String searchStr) {
        return getBlackboardWrapper().getAssembly().getAssemblyContexts__ComposedStructure().stream()
                .filter(e -> e.getEntityName().contains(searchStr)).findFirst().orElse(null);
    }
    
    @Test
    public void cloudInfrastructureBaseTest() {
        final var changes = runAnalysisWithoutAttackPathGeneration();
        pathsTestHelper(changes);
    }
    
    private void pathsTestHelper(final CredentialChange changes) {
        final var attacked = getAttackGraph().getAttackedNodes();
        final var compromised = getAttackGraph().getCompromisedNodes();
        System.out.println("attacked: " + attacked);
        System.out.println("attack edges: " + getAttackGraph().getEdges().stream().filter(e -> 
            attacked.contains(e.getNodes().source())).map(e -> e.createReverseEdge()).collect(Collectors.toSet()));
        System.out.println("compromised: " + compromised);
        
        System.out.println("\n\nAll attack edges:\n");
        getAttackGraph().getEdges().forEach(e -> System.out.println(e.createReverseEdge()));
        
        System.out.println("\n\ncredentials:\n");
        System.out.println(getAttackGraph().getAllCredentials());
        System.out.println("children of root: " + this.getAttackGraph().getChildrenOfNode(this.getAttackGraph().getRootNodeContent()));
        
        Assert.assertTrue(this.getAttackGraph().getRootNodeContent().isCompromised());
        Assert.assertTrue(this.getAttackGraph().findNode(
                new AttackStatusNodeContent(
                        this.getResource(this.getAttackGraph().getRootNodeContent()
                                .getContainedElementAsPCMElement().getAssemblycontext()))).isCompromised());

        final var surfacePaths = getAttackGraph().findAllAttackPaths(getBlackboardWrapper(), changes);
        System.out.println("\n\nAll attack paths (surface):\n");
        surfacePaths.forEach(p -> System.out.println(p));
        final var attackPathGenerator = new AttackSurfaceAnalysis(true, getBlackboardWrapper());
        final var paths = attackPathGenerator.toAttackPaths(surfacePaths, getBlackboardWrapper());
        System.out.println("\n\nAll attack paths:\n");
        printPaths(paths);
        System.out.println(surfacePaths.size());
        Assert.assertEquals(surfacePaths.size(), paths.size());
    }
    
    private String toString(final List<AttackPath> paths) {
        final StringJoiner joiner = new StringJoiner("\n");
        paths.forEach(p -> {
            joiner.add("PATH");
            if (!p.getCredentialsInitiallyNecessary().isEmpty()) {
                p.getCredentialsInitiallyNecessary().stream().sorted(this::compareIds).forEach(c -> {
                    final var credId = c.getId();
                    joiner.add("credentials initally necessary: " + credId);
                });
            }
            p.getPath().forEach(s -> {
                final var id = s.getIdOfContent() != null ? s.getIdOfContent().getId() : "-";
                final var entity = PCMElementType.typeOf(s.getPcmelement()).getEntity(s.getPcmelement());
                joiner.add(id + " | " + entity.getEntityName());
            });
            p.getVulnerabilitesUsed().forEach(v -> {
                final var vulnId = v.getId();
                joiner.add("VULNs used: " + vulnId);
            });
            joiner.add("\n");
        });
        return joiner.toString();
    }
    
    private int compareIds(Identifier o1, Identifier o2) {
        return o1.getId().compareTo(o2.getId());
    }            
    
    private void printPaths(final List<AttackPath> paths) {
        System.out.println(toString(paths));
    }
    
    @Test
    public void cloudInfrastructureBaseTestCompleteAnalysis() {
        final var changes = runAnalysis();
        final var pathsDirectlyAfterAnalysis = changes.getAttackpaths();
        printPaths(pathsDirectlyAfterAnalysis);
        Assert.assertEquals(16, pathsDirectlyAfterAnalysis.size());
        
        pathsTestHelper(changes);
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
        System.out.println(pathsString);
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
        System.out.println(pathsString);
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
        System.out.println(pathsString);
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
        System.out.println(pathsString);
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
        System.out.println(pathsString);
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
        System.out.println(pathsString);
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
