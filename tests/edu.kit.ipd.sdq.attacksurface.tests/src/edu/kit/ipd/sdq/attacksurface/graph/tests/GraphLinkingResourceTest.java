package edu.kit.ipd.sdq.attacksurface.graph.tests;

import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.VulnerabilitySystemIntegration;
import org.palladiosimulator.pcm.resourceenvironment.ResourceContainer;

import edu.kit.ipd.sdq.attacksurface.graph.ArchitectureNode;
import edu.kit.ipd.sdq.attacksurface.graph.AttackEdge;
import edu.kit.ipd.sdq.attacksurface.graph.AttackGraphCreation;

public class GraphLinkingResourceTest extends AttackGraphCreationTest {

    @Test
    void testLinking2ResourceCredentials() {

        this.getBlackboardWrapper()
            .getVulnerabilitySpecification()
            .getVulnerabilities()
            .clear();

        this.resetVulnerabilityCache();
        final var graphCreation = new AttackGraphCreation(this.getBlackboardWrapper());

        graphCreation.calculateLinkingResourceToResourcePropagation();

        final var graph = graphCreation.getGraph();

        final var resourceContainer = this.getFirstEntityByName("Critical Resource Container");
        final var linkingResource = this.getFirstEntityByName("LinkingResource1");

        // correct amount of nodes and edges
        Assertions.assertEquals(2, graph.nodes()
            .size());
        Assertions.assertEquals(1, graph.edges()
            .size());

        // correct nodes and edges
        Assertions.assertTrue(graph.nodes()
            .contains(new ArchitectureNode(resourceContainer)));
        Assertions.assertTrue(graph.nodes()
            .contains(new ArchitectureNode(linkingResource)));

        final var edge = new AttackEdge(linkingResource, resourceContainer, null,
                List.of(this.getFirstByName("root usage spec")));

        graph.edges();
        Assertions.assertTrue(graph.edges()
            .contains(edge));

    }

    @Test
    void testLinking2ResourceNoEdge() {
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

        graphCreation.calculateLinkingResourceToResourcePropagation();

        final var graph = graphCreation.getGraph();

        // correct amount of nodes and edges
        Assertions.assertEquals(0, graph.nodes()
            .size());
        Assertions.assertEquals(0, graph.edges()
            .size());
    }

    @Test
    void testLinking2ResourceVulnerability() {
        this.context.getPolicyset()
            .getPolicy()
            .clear();
        this.context.getPolicyset()
            .getPolicyset()
            .clear();

        final var resourceContainer = this.getFirstEntityByName("Critical Resource Container");
        final var linkingResource = this.getFirstEntityByName("LinkingResource1");

        final var integration = (VulnerabilitySystemIntegration) this
            .getFirstEntityByName("Critical Test Vulnerability Integration");
        integration.getPcmelement()
            .getAssemblycontext()
            .clear();
        integration.getPcmelement()
            .setResourcecontainer((ResourceContainer) resourceContainer);

        this.resetVulnerabilityCache();
        final var graphCreation = new AttackGraphCreation(this.getBlackboardWrapper());

        graphCreation.calculateLinkingResourceToResourcePropagation();

        final var graph = graphCreation.getGraph();

        // correct amount of nodes and edges
        Assertions.assertEquals(2, graph.nodes()
            .size());
        Assertions.assertEquals(1, graph.edges()
            .size());

        // correct nodes and edges
        Assertions.assertTrue(graph.nodes()
            .contains(new ArchitectureNode(resourceContainer)));
        Assertions.assertTrue(graph.nodes()
            .contains(new ArchitectureNode(linkingResource)));

        final var edge = new AttackEdge(linkingResource, resourceContainer, integration.getVulnerability(), null);

        graph.edges();
        Assertions.assertTrue(graph.edges()
            .contains(edge));

    }

}
