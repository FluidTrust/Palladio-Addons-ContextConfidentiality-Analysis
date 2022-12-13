package edu.kit.ipd.sdq.attacksurface.graph.tests;

import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.palladiosimulator.pcm.allocation.AllocationContext;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.AttackVector;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.VulnerabilitySystemIntegration;
import org.palladiosimulator.pcm.resourceenvironment.LinkingResource;

import edu.kit.ipd.sdq.attacksurface.graph.ArchitectureNode;
import edu.kit.ipd.sdq.attacksurface.graph.AttackEdge;
import edu.kit.ipd.sdq.attacksurface.graph.AttackGraphCreation;

public class GraphResourceTest extends AttackGraphCreationTest {

    @Test
    void testResource2LinkingCredentials() {

        this.getBlackboardWrapper()
            .getVulnerabilitySpecification()
            .getVulnerabilities()
            .clear();

        this.resetVulnerabilityCache();
        final var graphCreation = new AttackGraphCreation(this.getBlackboardWrapper());

        graphCreation.calculateResourceContainerToLinkingResourcePropagation();

        final var graph = graphCreation.getGraph();

        final var resourceContainers = Arrays.asList(this.getFirstEntityByName("Critical Resource Container"),
                this.getFirstEntityByName("ResourceContainer R.1"), this.getFirstEntityByName("Bridge 1-2"),
                this.getFirstEntityByName("ResourceContainer P.2"), this.getFirstEntityByName("Bridge 1-3"));

        final var linkingResource = this.getFirstEntityByName("LinkingResource1");

        // correct amount of nodes and edges
        Assertions.assertEquals(resourceContainers.size() + 1, graph.nodes()
            .size()); // offset for
                      // linkingResource
        Assertions.assertEquals(resourceContainers.size(), graph.edges()
            .size());

        Assertions.assertTrue(graph.nodes()
            .contains(new ArchitectureNode(linkingResource)));
        for (final var entity : resourceContainers) {
            Assertions.assertTrue(graph.nodes()
                .contains(new ArchitectureNode(entity)));
            final var edge = new AttackEdge(entity, linkingResource, null,
                    List.of(this.getFirstByName("root usage spec")));
            Assertions.assertTrue(graph.edges()
                .contains(edge));
        }
    }

    @Test
    void testResource2LinkingVulnerability() {

        this.context.getPolicyset()
            .getPolicy()
            .clear();
        this.context.getPolicyset()
            .getPolicyset()
            .clear();

        final var linkingResource = this.getFirstEntityByName("LinkingResource1");
        final var integration = (VulnerabilitySystemIntegration) this
            .getFirstEntityByName("Critical Test Vulnerability Integration");
        integration.getPcmelement()
            .setLinkingresource((LinkingResource) linkingResource);

        this.resetVulnerabilityCache();
        final var graphCreation = new AttackGraphCreation(this.getBlackboardWrapper());

        graphCreation.calculateResourceContainerToLinkingResourcePropagation();

        final var graph = graphCreation.getGraph();

        final var resourceContainers = Arrays.asList(this.getFirstEntityByName("Critical Resource Container"),
                this.getFirstEntityByName("ResourceContainer R.1"), this.getFirstEntityByName("Bridge 1-2"),
                this.getFirstEntityByName("ResourceContainer P.2"), this.getFirstEntityByName("Bridge 1-3"));

        // correct amount of nodes and edges
        Assertions.assertEquals(resourceContainers.size() + 1, graph.nodes()
            .size()); // offset for
                      // linkingResource
        Assertions.assertEquals(resourceContainers.size(), graph.edges()
            .size());

        Assertions.assertTrue(graph.nodes()
            .contains(new ArchitectureNode(linkingResource)));
        for (final var entity : resourceContainers) {
            Assertions.assertTrue(graph.nodes()
                .contains(new ArchitectureNode(entity)));
            final var edge = new AttackEdge(entity, linkingResource, integration.getVulnerability(), null);
            Assertions.assertTrue(graph.edges()
                .contains(edge));
        }
    }

    @Test
    void testResource2LinkingEmpty() {

        this.context.getPolicyset()
            .getPolicy()
            .clear();
        this.context.getPolicyset()
            .getPolicyset()
            .clear();
        this.getBlackboardWrapper()
            .getVulnerabilitySpecification()
            .getVulnerabilities()
            .clear();

        this.resetVulnerabilityCache();
        final var graphCreation = new AttackGraphCreation(this.getBlackboardWrapper());

        graphCreation.calculateResourceContainerToLinkingResourcePropagation();

        final var graph = graphCreation.getGraph();

        // correct amount of nodes and edges
        Assertions.assertEquals(0, graph.nodes()
            .size());
        Assertions.assertEquals(0, graph.edges()
            .size());

    }

    @Test
    void testResource2LocalAssembly() {

        this.context.getPolicyset()
            .getPolicy()
            .clear();
        this.context.getPolicyset()
            .getPolicyset()
            .clear();
        this.getBlackboardWrapper()
            .getVulnerabilitySpecification()
            .getVulnerabilities()
            .clear();

        final var saveAllocation = this.getFirstEntityByName("Allocation_Assembly_Component 3.1");

        this.getBlackboardWrapper()
            .getAllocation()
            .getAllocationContexts_Allocation()
            .clear();
        this.getBlackboardWrapper()
            .getAllocation()
            .getAllocationContexts_Allocation()
            .add((AllocationContext) saveAllocation);

        this.resetVulnerabilityCache();
        final var graphCreation = new AttackGraphCreation(this.getBlackboardWrapper());

        graphCreation.calculateResourceContainerToLocalAssemblyContextPropagation();

        final var graph = graphCreation.getGraph();

        // correct amount of nodes and edges
        Assertions.assertEquals(2, graph.nodes()
            .size());
        Assertions.assertEquals(1, graph.edges()
            .size());

        final var resource = this.getFirstEntityByName("ResourceContainer3");
        final var assembly = this.getFirstEntityByName("Assembly_Component 3.1");
        Assertions.assertTrue(graph.nodes()
            .contains(new ArchitectureNode(resource)));
        Assertions.assertTrue(graph.nodes()
            .contains(new ArchitectureNode(assembly)));

        final var edge = new AttackEdge(resource, assembly, null, List.of(), true, AttackVector.LOCAL);
        Assertions.assertTrue(graph.edges()
            .contains(edge));

    }

    @Test
    void testResource2LocalAssemblyEmpty() {

        this.context.getPolicyset()
            .getPolicy()
            .clear();
        this.context.getPolicyset()
            .getPolicyset()
            .clear();
        this.getBlackboardWrapper()
            .getVulnerabilitySpecification()
            .getVulnerabilities()
            .clear();

        this.getBlackboardWrapper()
            .getAllocation()
            .getAllocationContexts_Allocation()
            .clear();

        this.resetVulnerabilityCache();
        final var graphCreation = new AttackGraphCreation(this.getBlackboardWrapper());

        graphCreation.calculateResourceContainerToLocalAssemblyContextPropagation();

        final var graph = graphCreation.getGraph();

        // correct amount of nodes and edges
        Assertions.assertEquals(0, graph.nodes()
            .size());
        Assertions.assertEquals(0, graph.edges()
            .size());

    }

}
