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
        var assemblySource = CompositionFactory.eINSTANCE.createAssemblyContext();
        var assemblyTarget = CompositionFactory.eINSTANCE.createAssemblyContext();
        var vulnerability = AttackSpecificationFactory.eINSTANCE.createCVEVulnerability();

        var edge = new AttackEdge(assemblySource, assemblyTarget, vulnerability, null);
        var edgeCompare = new AttackEdge(assemblySource, assemblyTarget, vulnerability, null);

        Assertions.assertEquals(edge, edgeCompare);
    }

    @Test
    void equalAssemblyVulnerabilityTestWithDifferentVulnerability() {
        var assemblySource = CompositionFactory.eINSTANCE.createAssemblyContext();
        var assemblyTarget = CompositionFactory.eINSTANCE.createAssemblyContext();
        var vulnerability1 = AttackSpecificationFactory.eINSTANCE.createCVEVulnerability();
        vulnerability1.setId("test");
        var vulnerability2 = AttackSpecificationFactory.eINSTANCE.createCVEVulnerability();
        vulnerability1.setId("test2");
        var edge = new AttackEdge(assemblySource, assemblyTarget, vulnerability1, null);
        var edgeCompare = new AttackEdge(assemblySource, assemblyTarget, vulnerability2, null);

        Assertions.assertNotEquals(edge, edgeCompare);
    }

    @Test
    void nonEqualAssemblyVulnerabilityTestwithSwitchedTargetAndSource() {
        var assemblySource = CompositionFactory.eINSTANCE.createAssemblyContext();
        var assemblyTarget = CompositionFactory.eINSTANCE.createAssemblyContext();
        var vulnerability = AttackSpecificationFactory.eINSTANCE.createCVEVulnerability();

        var edge = new AttackEdge(assemblyTarget, assemblySource, vulnerability, null);
        var edgeCompare = new AttackEdge(assemblySource, assemblyTarget, vulnerability, null);

        Assertions.assertNotEquals(edge, edgeCompare);
    }

    @Test
    void nonEqualAssemblyVulnerabilityTestwithDifferentTargetandSource() {
        var assemblySource1 = CompositionFactory.eINSTANCE.createAssemblyContext();
        var assemblyTarget1 = CompositionFactory.eINSTANCE.createAssemblyContext();
        var assemblySource2 = CompositionFactory.eINSTANCE.createAssemblyContext();
        var assemblyTarget2 = CompositionFactory.eINSTANCE.createAssemblyContext();
        var vulnerability = AttackSpecificationFactory.eINSTANCE.createCVEVulnerability();

        var edge = new AttackEdge(assemblySource1, assemblyTarget1, vulnerability, null);
        var edgeCompare = new AttackEdge(assemblySource2, assemblyTarget2, vulnerability, null);

        Assertions.assertNotEquals(edge, edgeCompare);
    }

    @Test
    void equalAssemblyVulnerabilityTestwithAttackVector() {
        var assemblySource = CompositionFactory.eINSTANCE.createAssemblyContext();
        var assemblyTarget = CompositionFactory.eINSTANCE.createAssemblyContext();
        var vulnerability = AttackSpecificationFactory.eINSTANCE.createCVEVulnerability();

        var edge = new AttackEdge(assemblySource, assemblyTarget, vulnerability, null, false,
                AttackVector.ADJACENT_NETWORK);
        var edgeCompare = new AttackEdge(assemblySource, assemblyTarget, vulnerability, null);

        Assertions.assertNotEquals(edge, edgeCompare);
    }

    @Test
    void equalAssemblyVulnerabilityTestwithCredentials() {

        var assemblySource = CompositionFactory.eINSTANCE.createAssemblyContext();
        var assemblyTarget = CompositionFactory.eINSTANCE.createAssemblyContext();

        var usage = SystemFactory.eINSTANCE.createUsageSpecification();

        var edge = new AttackEdge(assemblySource, assemblyTarget, null, List.of(usage));
        var edgeCompare = new AttackEdge(assemblySource, assemblyTarget, null, List.of(usage));

        Assertions.assertTrue(edge.equals(edgeCompare));
    }

    @Test
    void notEqualAssemblyVulnerabilityTestwithCredentials() {

        var assemblySource = CompositionFactory.eINSTANCE.createAssemblyContext();
        var assemblyTarget = CompositionFactory.eINSTANCE.createAssemblyContext();

        var usage1 = SystemFactory.eINSTANCE.createUsageSpecification();
        usage1.setId("test");
        var usage2 = SystemFactory.eINSTANCE.createUsageSpecification();
        usage2.setId("test2");

        var edge = new AttackEdge(assemblySource, assemblyTarget, null, List.of(usage1));
        var edgeCompare = new AttackEdge(assemblySource, assemblyTarget, null, List.of(usage2));

        Assertions.assertFalse(edge.equals(edgeCompare));
    }

}
