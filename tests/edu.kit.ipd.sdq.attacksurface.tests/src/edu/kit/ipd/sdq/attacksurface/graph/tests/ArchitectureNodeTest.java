package edu.kit.ipd.sdq.attacksurface.graph.tests;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.palladiosimulator.pcm.core.composition.CompositionFactory;

import edu.kit.ipd.sdq.attacksurface.graph.ArchitectureNode;

public class ArchitectureNodeTest {

    @Test
    void equalsTest() {
        var entity = CompositionFactory.eINSTANCE.createAssemblyContext();

        var node1 = new ArchitectureNode(entity);
        var node2 = new ArchitectureNode(entity);

        Assertions.assertEquals(node1, node2);

    }

    @Test
    void notEqualsTest() {
        var entity1 = CompositionFactory.eINSTANCE.createAssemblyContext();
        var entity2 = CompositionFactory.eINSTANCE.createAssemblyContext();

        var node1 = new ArchitectureNode(entity1);
        var node2 = new ArchitectureNode(entity2);

        Assertions.assertNotEquals(node1, node2);

    }

    @Test
    void getEntity() {
        var entity = CompositionFactory.eINSTANCE.createAssemblyContext();

        var node = new ArchitectureNode(entity);

        Assertions.assertEquals(entity, node.getEntity());

    }

}
