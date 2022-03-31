package edu.kit.ipd.sdq.attacksurface.tests.evaluation;

import java.util.List;
import java.util.StringJoiner;
import java.util.stream.Collectors;

import org.junit.Assert;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.AttackPath;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;

import de.uka.ipd.sdq.identifier.Identifier;
import edu.kit.ipd.sdq.attacksurface.core.AttackSurfaceAnalysis;
import edu.kit.ipd.sdq.attacksurface.core.changepropagation.changes.AssemblyContextPropagationVulnerability;
import edu.kit.ipd.sdq.attacksurface.graph.AttackStatusNodeContent;
import edu.kit.ipd.sdq.attacksurface.graph.PCMElementType;
import edu.kit.ipd.sdq.attacksurface.tests.change.AbstractChangeTests;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;

public abstract class EvaluationTest extends AbstractChangeTests {
    

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
    
    protected void pathsTestHelper(final CredentialChange changes) {
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
    
    protected String toString(final List<AttackPath> paths) {
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
    
    protected void printPaths(final List<AttackPath> paths) {
        System.out.println(toString(paths));
    }
}
