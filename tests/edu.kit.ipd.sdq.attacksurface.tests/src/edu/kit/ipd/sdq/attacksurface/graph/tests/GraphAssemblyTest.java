package edu.kit.ipd.sdq.attacksurface.graph.tests;

import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.VulnerabilitySystemIntegration;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;

import edu.kit.ipd.sdq.attacksurface.graph.ArchitectureNode;
import edu.kit.ipd.sdq.attacksurface.graph.AttackEdge;
import edu.kit.ipd.sdq.attacksurface.graph.AttackGraphCreation;

public class GraphAssemblyTest extends AttackGraphCreationTest {

    @Test
    void Assembly2AssemblyCredentials() {

        this.getBlackboardWrapper()
            .getVulnerabilitySpecification()
            .getVulnerabilities()
            .clear();

        this.resetVulnerabilityCache();
        final var graphCreation = new AttackGraphCreation(this.getBlackboardWrapper());

        graphCreation.calculateAssemblyContextToAssemblyContextPropagation();

        final var graph = graphCreation.getGraph();

        final var assemblies = Arrays.asList(this.getFirstEntityByName("Assembly_Component P.2.1"),
                this.getFirstEntityByName("Assembly_Component R.1.1"),
                this.getFirstEntityByName("Assembly_Component R.1.2"));

        final var targetedAssembly = this.getFirstEntityByName("Assembly_Critical");

        // correct amount of nodes and edges
        Assertions.assertEquals(assemblies.size() + 1, graph.nodes()
            .size()); // offset for
                      // linkingResource
        Assertions.assertEquals(assemblies.size(), graph.edges()
            .size());

        Assertions.assertTrue(graph.nodes()
            .contains(new ArchitectureNode(targetedAssembly)));
        for (final var entity : assemblies) {
            Assertions.assertTrue(graph.nodes()
                .contains(new ArchitectureNode(entity)));
            final var edge = new AttackEdge(entity, targetedAssembly, null,
                    List.of(this.getFirstByName("root usage spec")));
            Assertions.assertTrue(graph.edges()
                .contains(edge));
        }

    }

    @Test
    void Assembly2AssemblyVulnerability() {

        this.context.getPolicyset()
            .getPolicy()
            .clear();
        this.context.getPolicyset()
            .getPolicyset()
            .clear();

        final var targetedAssembly = this.getFirstEntityByName("Assembly_Critical");
        final var integration = (VulnerabilitySystemIntegration) this
            .getFirstEntityByName("Critical Test Vulnerability Integration");
        integration.getPcmelement()
            .getAssemblycontext()
            .add((AssemblyContext) targetedAssembly);

        this.resetVulnerabilityCache();
        final var graphCreation = new AttackGraphCreation(this.getBlackboardWrapper());

        graphCreation.calculateAssemblyContextToAssemblyContextPropagation();

        final var graph = graphCreation.getGraph();

        final var assemblies = Arrays.asList(this.getFirstEntityByName("Assembly_Component P.2.1"),
                this.getFirstEntityByName("Assembly_Component R.1.1"),
                this.getFirstEntityByName("Assembly_Component R.1.2"));

        // correct amount of nodes and edges
        Assertions.assertEquals(assemblies.size() + 1, graph.nodes()
            .size()); // offset assembly

        Assertions.assertEquals(assemblies.size(), graph.edges()
            .size());

        Assertions.assertTrue(graph.nodes()
            .contains(new ArchitectureNode(targetedAssembly)));
        for (final var entity : assemblies) {
            Assertions.assertTrue(graph.nodes()
                .contains(new ArchitectureNode(entity)));
            final var edge = new AttackEdge(entity, targetedAssembly, integration.getVulnerability(), null);
            Assertions.assertTrue(graph.edges()
                .contains(edge));
        }

    }

    @Test
    void Assembly2AssemblyEmpty() {

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

        graphCreation.calculateAssemblyContextToAssemblyContextPropagation();

        final var graph = graphCreation.getGraph();

        // correct amount of nodes and edges
        Assertions.assertEquals(0, graph.nodes()
            .size());
        Assertions.assertEquals(0, graph.edges()
            .size());

    }

    @Test
    void Assembly2AssemblyCredentialsGlobal() {

        this.getBlackboardWrapper()
            .getVulnerabilitySpecification()
            .getVulnerabilities()
            .clear();

        this.resetVulnerabilityCache();
        final var graphCreation = new AttackGraphCreation(this.getBlackboardWrapper());

        graphCreation.calculateAssemblyContextToGlobalAssemblyContextPropagation();

        final var graph = graphCreation.getGraph();

        final var assemblies = Arrays.asList(this.getFirstEntityByName("Assembly_Component P.2.1"),
                this.getFirstEntityByName("Assembly_Component R.1.1"),
                this.getFirstEntityByName("Assembly_Component R.1.2"));

        final var targetedAssembly = this.getFirstEntityByName("Assembly_Critical");

        // correct amount of nodes and edges
        Assertions.assertEquals(assemblies.size() + 1, graph.nodes()
            .size()); // offset for
                      // linkingResource
        Assertions.assertEquals(assemblies.size(), graph.edges()
            .size());

        Assertions.assertTrue(graph.nodes()
            .contains(new ArchitectureNode(targetedAssembly)));
        for (final var entity : assemblies) {
            Assertions.assertTrue(graph.nodes()
                .contains(new ArchitectureNode(entity)));
            final var edge = new AttackEdge(entity, targetedAssembly, null,
                    List.of(this.getFirstByName("root usage spec")));
            Assertions.assertTrue(graph.edges()
                .contains(edge));
        }

    }

    @Test
    void Assembly2AssemblyVulnerabilityGlobal() {

        this.context.getPolicyset()
            .getPolicy()
            .clear();
        this.context.getPolicyset()
            .getPolicyset()
            .clear();

        final var targetedAssembly = this.getFirstEntityByName("Assembly_Critical");
        final var integration = (VulnerabilitySystemIntegration) this
            .getFirstEntityByName("Critical Test Vulnerability Integration");
        integration.getPcmelement()
            .getAssemblycontext()
            .add((AssemblyContext) targetedAssembly);

        this.resetVulnerabilityCache();
        final var graphCreation = new AttackGraphCreation(this.getBlackboardWrapper());

        graphCreation.calculateAssemblyContextToGlobalAssemblyContextPropagation();

        final var graph = graphCreation.getGraph();

        final var assemblies = Arrays.asList(this.getFirstEntityByName("Assembly_Component P.2.1"),
                this.getFirstEntityByName("Assembly_Component R.1.1"),
                this.getFirstEntityByName("Assembly_Component R.1.2"));

        // correct amount of nodes and edges
        Assertions.assertEquals(assemblies.size() + 1, graph.nodes()
            .size()); // offset assembly

        Assertions.assertEquals(assemblies.size(), graph.edges()
            .size());

        Assertions.assertTrue(graph.nodes()
            .contains(new ArchitectureNode(targetedAssembly)));
        for (final var entity : assemblies) {
            Assertions.assertTrue(graph.nodes()
                .contains(new ArchitectureNode(entity)));
            final var edge = new AttackEdge(entity, targetedAssembly, integration.getVulnerability(), null);
            Assertions.assertTrue(graph.edges()
                .contains(edge));
        }

    }

}
