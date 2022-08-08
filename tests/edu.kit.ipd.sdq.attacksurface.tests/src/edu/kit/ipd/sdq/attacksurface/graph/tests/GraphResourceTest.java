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

        getBlackboardWrapper().getVulnerabilitySpecification().getVulnerabilities().clear();

        var graphCreation = new AttackGraphCreation(getBlackboardWrapper());

        graphCreation.calculateResourceContainerToLinkingResourcePropagation();

        var graph = graphCreation.getGraph();

        var resourceContainers = Arrays.asList(getFirstEntityByName("Critical Resource Container"), getFirstEntityByName("ResourceContainer R.1"), getFirstEntityByName("Bridge 1-2"), getFirstEntityByName("ResourceContainer P.2"), getFirstEntityByName("Bridge 1-3"));

        var linkingResource = getFirstEntityByName("LinkingResource1");

        // correct amount of nodes and edges
        Assertions.assertEquals(resourceContainers.size() + 1, graph.nodes().size()); // offset for
                                                                                      // linkingResource
        Assertions.assertEquals(resourceContainers.size(), graph.edges().size());

        Assertions.assertTrue(graph.nodes().contains(new ArchitectureNode(linkingResource)));
        for (var entity : resourceContainers) {
            Assertions.assertTrue(graph.nodes().contains(new ArchitectureNode(entity)));
            var edge = new AttackEdge(entity, linkingResource, null, List.of(getFirstByName("root usage spec")));
            Assertions.assertTrue(graph.edges().contains(edge));
        }
    }

    @Test
    void testResource2LinkingVulnerability() {

        this.context.getPolicyset().getPolicy().clear();
        this.context.getPolicyset().getPolicyset().clear();

        var linkingResource = getFirstEntityByName("LinkingResource1");
        var integration = (VulnerabilitySystemIntegration) getFirstEntityByName(
                "Critical Test Vulnerability Integration");
        integration.getPcmelement().setLinkingresource((LinkingResource) linkingResource);


        var graphCreation = new AttackGraphCreation(getBlackboardWrapper());

        graphCreation.calculateResourceContainerToLinkingResourcePropagation();

        var graph = graphCreation.getGraph();

        var resourceContainers = Arrays.asList(getFirstEntityByName("Critical Resource Container"),
                getFirstEntityByName("ResourceContainer R.1"), getFirstEntityByName("Bridge 1-2"),
                getFirstEntityByName("ResourceContainer P.2"), getFirstEntityByName("Bridge 1-3"));


        // correct amount of nodes and edges
        Assertions.assertEquals(resourceContainers.size() + 1, graph.nodes().size()); // offset for
                                                                                      // linkingResource
        Assertions.assertEquals(resourceContainers.size(), graph.edges().size());

        Assertions.assertTrue(graph.nodes().contains(new ArchitectureNode(linkingResource)));
        for (var entity : resourceContainers) {
            Assertions.assertTrue(graph.nodes().contains(new ArchitectureNode(entity)));
            var edge = new AttackEdge(entity, linkingResource, integration.getVulnerability(), null);
            Assertions.assertTrue(graph.edges().contains(edge));
        }
    }

    @Test
    void testResource2LinkingEmpty() {

        this.context.getPolicyset().getPolicy().clear();
        this.context.getPolicyset().getPolicyset().clear();
        getBlackboardWrapper().getVulnerabilitySpecification().getVulnerabilities().clear();

        var graphCreation = new AttackGraphCreation(getBlackboardWrapper());

        graphCreation.calculateResourceContainerToLinkingResourcePropagation();

        var graph = graphCreation.getGraph();

        // correct amount of nodes and edges
        Assertions.assertEquals(0, graph.nodes().size());
        Assertions.assertEquals(0, graph.edges().size());

    }

    @Test
    void testResource2LocalAssembly() {

        this.context.getPolicyset().getPolicy().clear();
        this.context.getPolicyset().getPolicyset().clear();
        getBlackboardWrapper().getVulnerabilitySpecification().getVulnerabilities().clear();

        var saveAllocation = getFirstEntityByName("Allocation_Assembly_Component 3.1");

        getBlackboardWrapper().getAllocation().getAllocationContexts_Allocation().clear();
        getBlackboardWrapper().getAllocation().getAllocationContexts_Allocation()
                .add((AllocationContext) saveAllocation);

        var graphCreation = new AttackGraphCreation(getBlackboardWrapper());

        graphCreation.calculateResourceContainerToLocalAssemblyContextPropagation();

        var graph = graphCreation.getGraph();

        // correct amount of nodes and edges
        Assertions.assertEquals(2, graph.nodes().size());
        Assertions.assertEquals(1, graph.edges().size());

        var resource = getFirstEntityByName("ResourceContainer3");
        var assembly = getFirstEntityByName("Assembly_Component 3.1");
        Assertions.assertTrue(graph.nodes().contains(new ArchitectureNode(resource)));
        Assertions.assertTrue(graph.nodes().contains(new ArchitectureNode(assembly)));

        var edge = new AttackEdge(resource, assembly, null, List.of(), true, AttackVector.LOCAL);
        Assertions.assertTrue(graph.edges().contains(edge));

    }

    @Test
    void testResource2LocalAssemblyEmpty() {

        this.context.getPolicyset().getPolicy().clear();
        this.context.getPolicyset().getPolicyset().clear();
        getBlackboardWrapper().getVulnerabilitySpecification().getVulnerabilities().clear();

        getBlackboardWrapper().getAllocation().getAllocationContexts_Allocation().clear();

        var graphCreation = new AttackGraphCreation(getBlackboardWrapper());

        graphCreation.calculateResourceContainerToLocalAssemblyContextPropagation();

        var graph = graphCreation.getGraph();

        // correct amount of nodes and edges
        Assertions.assertEquals(0, graph.nodes().size());
        Assertions.assertEquals(0, graph.edges().size());

    }


}
