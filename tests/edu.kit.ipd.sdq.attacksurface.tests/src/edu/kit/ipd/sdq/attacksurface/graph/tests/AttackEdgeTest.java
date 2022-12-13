package edu.kit.ipd.sdq.attacksurface.graph.tests;

import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.AttackSpecificationFactory;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.AttackVector;
import org.palladiosimulator.pcm.confidentiality.context.system.SystemFactory;
import org.palladiosimulator.pcm.core.composition.CompositionFactory;

import edu.kit.ipd.sdq.attacksurface.graph.AttackEdge;

public class AttackEdgeTest {

    @Test
    void equalAssemblyVulnerabilityTest() {
        final var assemblySource = CompositionFactory.eINSTANCE.createAssemblyContext();
        final var assemblyTarget = CompositionFactory.eINSTANCE.createAssemblyContext();
        final var vulnerability = AttackSpecificationFactory.eINSTANCE.createCVEVulnerability();

        final var edge = new AttackEdge(assemblySource, assemblyTarget, vulnerability, null);
        final var edgeCompare = new AttackEdge(assemblySource, assemblyTarget, vulnerability, null);

        Assertions.assertEquals(edge, edgeCompare);
    }

    @Test
    void equalAssemblyVulnerabilityTestWithDifferentVulnerability() {
        final var assemblySource = CompositionFactory.eINSTANCE.createAssemblyContext();
        final var assemblyTarget = CompositionFactory.eINSTANCE.createAssemblyContext();
        final var vulnerability1 = AttackSpecificationFactory.eINSTANCE.createCVEVulnerability();
        vulnerability1.setId("test");
        final var vulnerability2 = AttackSpecificationFactory.eINSTANCE.createCVEVulnerability();
        vulnerability1.setId("test2");
        final var edge = new AttackEdge(assemblySource, assemblyTarget, vulnerability1, null);
        final var edgeCompare = new AttackEdge(assemblySource, assemblyTarget, vulnerability2, null);

        Assertions.assertNotEquals(edge, edgeCompare);
    }

    @Test
    void nonEqualAssemblyVulnerabilityTestwithSwitchedTargetAndSource() {
        final var assemblySource = CompositionFactory.eINSTANCE.createAssemblyContext();
        final var assemblyTarget = CompositionFactory.eINSTANCE.createAssemblyContext();
        final var vulnerability = AttackSpecificationFactory.eINSTANCE.createCVEVulnerability();

        final var edge = new AttackEdge(assemblyTarget, assemblySource, vulnerability, null);
        final var edgeCompare = new AttackEdge(assemblySource, assemblyTarget, vulnerability, null);

        Assertions.assertNotEquals(edge, edgeCompare);
    }

    @Test
    void nonEqualAssemblyVulnerabilityTestwithDifferentTargetandSource() {
        final var assemblySource1 = CompositionFactory.eINSTANCE.createAssemblyContext();
        final var assemblyTarget1 = CompositionFactory.eINSTANCE.createAssemblyContext();
        final var assemblySource2 = CompositionFactory.eINSTANCE.createAssemblyContext();
        final var assemblyTarget2 = CompositionFactory.eINSTANCE.createAssemblyContext();
        final var vulnerability = AttackSpecificationFactory.eINSTANCE.createCVEVulnerability();

        final var edge = new AttackEdge(assemblySource1, assemblyTarget1, vulnerability, null);
        final var edgeCompare = new AttackEdge(assemblySource2, assemblyTarget2, vulnerability, null);

        Assertions.assertNotEquals(edge, edgeCompare);
    }

    @Test
    void equalAssemblyVulnerabilityTestwithAttackVector() {
        final var assemblySource = CompositionFactory.eINSTANCE.createAssemblyContext();
        final var assemblyTarget = CompositionFactory.eINSTANCE.createAssemblyContext();
        final var vulnerability = AttackSpecificationFactory.eINSTANCE.createCVEVulnerability();

        final var edge = new AttackEdge(assemblySource, assemblyTarget, vulnerability, null, false,
                AttackVector.ADJACENT_NETWORK);
        final var edgeCompare = new AttackEdge(assemblySource, assemblyTarget, vulnerability, null);

        Assertions.assertNotEquals(edge, edgeCompare);
    }

    @Test
    void equalAssemblyVulnerabilityTestwithCredentials() {

        final var assemblySource = CompositionFactory.eINSTANCE.createAssemblyContext();
        final var assemblyTarget = CompositionFactory.eINSTANCE.createAssemblyContext();

        final var usage = SystemFactory.eINSTANCE.createUsageSpecification();

        final var edge = new AttackEdge(assemblySource, assemblyTarget, null, List.of(usage));
        final var edgeCompare = new AttackEdge(assemblySource, assemblyTarget, null, List.of(usage));

        Assertions.assertTrue(edge.equals(edgeCompare));
    }

    @Test
    void notEqualAssemblyVulnerabilityTestwithCredentials() {

        final var assemblySource = CompositionFactory.eINSTANCE.createAssemblyContext();
        final var assemblyTarget = CompositionFactory.eINSTANCE.createAssemblyContext();

        final var usage1 = SystemFactory.eINSTANCE.createUsageSpecification();
        usage1.setId("test");
        final var usage2 = SystemFactory.eINSTANCE.createUsageSpecification();
        usage2.setId("test2");

        final var edge = new AttackEdge(assemblySource, assemblyTarget, null, List.of(usage1));
        final var edgeCompare = new AttackEdge(assemblySource, assemblyTarget, null, List.of(usage2));

        Assertions.assertFalse(edge.equals(edgeCompare));
    }

}
