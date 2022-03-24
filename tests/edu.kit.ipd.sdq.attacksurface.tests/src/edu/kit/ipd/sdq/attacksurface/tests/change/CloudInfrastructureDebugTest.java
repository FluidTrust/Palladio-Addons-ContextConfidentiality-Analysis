package edu.kit.ipd.sdq.attacksurface.tests.change;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
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
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksFactory;
import edu.kit.kastel.sdq.kamp4attack.graph.impl.output.DotCreation;

public class CloudInfrastructureDebugTest extends AbstractChangeTests {
    public CloudInfrastructureDebugTest() {
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
    
    private void printPaths(final List<AttackPath> paths) {
        paths.forEach(p -> {
            p.getPath().forEach(s -> {
                final var id = s.getIdOfContent() != null ? s.getIdOfContent().getId() : "-";
                final var entity = PCMElementType.typeOf(s.getPcmelement()).getEntity(s.getPcmelement());
                System.out.println(id + " | " + entity.getEntityName());
            });
            System.out.println("\n");
        });
    }
    
    @Test
    public void cloudInfrastructureBaseTestCompleteAnalysis() {
        final var changes = runAnalysis();
        final var pathsDirectlyAfterAnalysis = changes.getAttackpaths();
        Assert.assertEquals(10, pathsDirectlyAfterAnalysis.size());
        printPaths(pathsDirectlyAfterAnalysis);
        
        pathsTestHelper(changes);
    }
    
    @Test
    public void graphGenerationTest() {
        runAnalysis();
        generateGraph(false);
    }
}
