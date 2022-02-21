package edu.kit.ipd.sdq.attacksurface.tests.attackhandlers;

import java.util.Arrays;

import org.junit.Assert;
import org.junit.jupiter.api.Test;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.data.DataHandlerAttacker;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.AttackVector;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;
import org.palladiosimulator.pcm.core.entity.Entity;

import edu.kit.ipd.sdq.attacksurface.core.changepropagation.attackhandlers.vulnerability.AssemblyContextVulnerability;
import edu.kit.ipd.sdq.attacksurface.graph.AttackGraph;
import edu.kit.ipd.sdq.attacksurface.graph.AttackStatusNodeContent;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;

public class AssemblyContextHandlerTest extends AbstractAttackHandlerTest {
    
    @Test
    public void attackAssemblyContextVulnerabilitySelfAttackTest() {
        final var dataHandler = new DataHandlerAttacker(getChanges());
        final var handler = new AssemblyContextVulnerability(this.getBlackboardWrapper(), 
                dataHandler, AttackVector.NETWORK, getAttackGraph());
        final var rootNode = getAttackGraph().getRootNodeContent();
        final var criticalComponent = rootNode.getContainedElementAsPCMElement().getAssemblycontext();
        handler.attackAssemblyContext(Arrays.asList(criticalComponent), getChanges(), criticalComponent);
        Assert.assertTrue(rootNode.isCompromised());
        Assert.assertFalse(getAttackGraph().getCompromisationCauseIds(rootNode).isEmpty());
        Assert.assertEquals("TestVulnerabilityId123456", getAttackGraph().getCompromisationCauseIds(rootNode).toArray(String[]::new)[0]);
    }
    
    @Test
    public void attackAssemblyContextVulnerabilityAttackViaUncompromisedTest() {
        final var dataHandler = new DataHandlerAttacker(getChanges());
        final var handler = new AssemblyContextVulnerability(this.getBlackboardWrapper(), 
                dataHandler, AttackVector.NETWORK, getAttackGraph());
        final var rootNode = getAttackGraph().getRootNodeContent();
        final var criticalComponent = rootNode.getContainedElementAsPCMElement().getAssemblycontext();
        final AssemblyContext attackerComponent = getBlackboardWrapper()
                .getAssembly()
                .getAssemblyContexts__ComposedStructure()
                .stream()
                .filter(e -> e.getEntityName().contains("P"))
                .findFirst().orElse(null);
        
        final var attackerNode = getAttackGraph().addOrFindChild(rootNode, new AttackStatusNodeContent(attackerComponent));

        handler.attackAssemblyContext(Arrays.asList(attackerComponent), getChanges(), attackerComponent);
        Assert.assertFalse(attackerNode.isCompromised());
        Assert.assertTrue(getAttackGraph().getCompromisationCauseIds(attackerNode).isEmpty());
        
        // attack and compromise root node
        handler.attackAssemblyContext(Arrays.asList(criticalComponent), getChanges(), attackerComponent);
        Assert.assertTrue(rootNode.isCompromised());
        Assert.assertFalse(getAttackGraph().getCompromisationCauseIds(rootNode).isEmpty());
        Assert.assertEquals("TestVulnerabilityId123456", getAttackGraph().getCompromisationCauseIds(rootNode).toArray(String[]::new)[0]);
    }
    
    @Test
    public void attackAssemblyContextVulnerabilityCompromisedAttackTest() {
        final var dataHandler = new DataHandlerAttacker(getChanges());
        final var handler = new AssemblyContextVulnerability(this.getBlackboardWrapper(), 
                dataHandler, AttackVector.NETWORK, getAttackGraph());
        final var rootNode = getAttackGraph().getRootNodeContent();
        final var criticalComponent = rootNode.getContainedElementAsPCMElement().getAssemblycontext();
        final AssemblyContext attackerComponent = getBlackboardWrapper()
                .getAssembly()
                .getAssemblyContexts__ComposedStructure()
                .stream()
                .filter(e -> e.getEntityName().contains("R.1.1"))
                .findFirst().orElse(null);

        final var attackerNode = getAttackGraph().addOrFindChild(rootNode, new AttackStatusNodeContent(attackerComponent));
        
        // attack and compromise attackerNode
        handler.attackAssemblyContext(Arrays.asList(attackerComponent), getChanges(), attackerComponent);
        Assert.assertTrue(attackerNode.isCompromised());
        Assert.assertFalse(getAttackGraph().getCompromisationCauseIds(attackerNode).isEmpty());
        Assert.assertEquals("TestVulnerabilityId123456", getAttackGraph().getCompromisationCauseIds(attackerNode).toArray(String[]::new)[0]);
        
        // attack and compromise root node
        handler.attackAssemblyContext(Arrays.asList(criticalComponent), getChanges(), attackerComponent);
        Assert.assertTrue(rootNode.isCompromised());
        Assert.assertFalse(getAttackGraph().getCompromisationCauseIds(rootNode).isEmpty());
        Assert.assertEquals("TestVulnerabilityId123456", getAttackGraph().getCompromisationCauseIds(rootNode).toArray(String[]::new)[0]);
    }
}
