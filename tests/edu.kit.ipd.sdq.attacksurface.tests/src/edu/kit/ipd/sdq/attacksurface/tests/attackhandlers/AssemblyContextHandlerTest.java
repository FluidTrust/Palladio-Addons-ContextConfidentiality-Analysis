package edu.kit.ipd.sdq.attacksurface.tests.attackhandlers;

import java.util.Arrays;
import java.util.stream.Collectors;

import org.eclipse.emf.ecore.util.EcoreUtil;
import org.junit.Assert;
import org.junit.jupiter.api.Test;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.data.DataHandlerAttacker;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.AttackVector;
import org.palladiosimulator.pcm.confidentiality.context.system.UsageSpecification;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;
import org.palladiosimulator.pcm.core.entity.Entity;
import org.palladiosimulator.pcm.resourceenvironment.ResourceContainer;

import edu.kit.ipd.sdq.attacksurface.core.changepropagation.attackhandlers.ResourceContainerHandler;
import edu.kit.ipd.sdq.attacksurface.core.changepropagation.attackhandlers.vulnerability.AssemblyContextVulnerability;
import edu.kit.ipd.sdq.attacksurface.core.changepropagation.attackhandlers.vulnerability.ResourceContainerVulnerability;
import edu.kit.ipd.sdq.attacksurface.graph.AttackGraph;
import edu.kit.ipd.sdq.attacksurface.graph.AttackStatusNodeContent;
import edu.kit.ipd.sdq.attacksurface.core.changepropagation.attackhandlers.context.AssemblyContextContext;
import edu.kit.ipd.sdq.attacksurface.core.changepropagation.attackhandlers.context.ResourceContainerContext;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.ContextChange;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksFactory;

public class AssemblyContextHandlerTest extends AbstractAttackHandlerTest {
    private static final String VULN_ID = "TestVulnerabilityId123456";
    private static final String CRED_ID  = "_fmYV4VWvEeyAu8-8Lz7_vA";
    
    @Test
    public void attackAssemblyContextVulnerabilitySelfAttackTest() {
        final var dataHandler = new DataHandlerAttacker(getChanges());
        final var handler = new AssemblyContextVulnerability(this.getBlackboardWrapper(), 
                dataHandler, AttackVector.NETWORK, getAttackGraph());
        final var rootNode = getAttackGraph().getRootNodeContent();
        final var criticalComponent = rootNode.getContainedElementAsPCMElement().getAssemblycontext();
        handler.attackAssemblyContext(Arrays.asList(criticalComponent), getChanges(), criticalComponent, false);
        Assert.assertTrue(rootNode.isCompromised());
        Assert.assertFalse(getAttackGraph().getCompromisationCauseIds(rootNode).isEmpty());
        Assert.assertEquals(VULN_ID, getAttackGraph().getCompromisationCauseIds(rootNode).toArray(String[]::new)[0]);
        Assert.assertTrue(getAttackGraph().getEdge(rootNode, rootNode).contains(VULN_ID));
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

        handler.attackAssemblyContext(Arrays.asList(attackerComponent), getChanges(), attackerComponent, false);
        Assert.assertFalse(attackerNode.isCompromised());
        Assert.assertTrue(getAttackGraph().getCompromisationCauseIds(attackerNode).isEmpty());
        Assert.assertNull(getAttackGraph().getEdge(attackerNode, attackerNode));
        
        // attack and compromise root node
        handler.attackAssemblyContext(Arrays.asList(criticalComponent), getChanges(), attackerComponent, false);
        Assert.assertTrue(rootNode.isCompromised());
        Assert.assertFalse(getAttackGraph().getCompromisationCauseIds(rootNode).isEmpty());
        Assert.assertEquals(VULN_ID, getAttackGraph().getCompromisationCauseIds(rootNode).toArray(String[]::new)[0]);
        Assert.assertTrue(getAttackGraph().getEdge(rootNode, attackerNode).contains(VULN_ID));
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
        handler.attackAssemblyContext(Arrays.asList(attackerComponent), getChanges(), attackerComponent, false);
        Assert.assertTrue(attackerNode.isCompromised());
        Assert.assertFalse(getAttackGraph().getCompromisationCauseIds(attackerNode).isEmpty());
        Assert.assertEquals(VULN_ID, getAttackGraph().getCompromisationCauseIds(attackerNode).toArray(String[]::new)[0]);
        Assert.assertTrue(getAttackGraph().getEdge(attackerNode, attackerNode).contains(VULN_ID));
        
        // attack and compromise root node
        handler.attackAssemblyContext(Arrays.asList(criticalComponent), getChanges(), attackerComponent, false);
        Assert.assertTrue(rootNode.isCompromised());
        Assert.assertFalse(getAttackGraph().getCompromisationCauseIds(rootNode).isEmpty());
        Assert.assertEquals(VULN_ID, getAttackGraph().getCompromisationCauseIds(rootNode).toArray(String[]::new)[0]);
        Assert.assertTrue(getAttackGraph().getEdge(rootNode, attackerNode).contains(VULN_ID));
    }
    
    @Test
    public void attackAssemblyContextVulnerabilityAttackViaUncompromisedResourceContainerTest() {
        final var dataHandler = new DataHandlerAttacker(getChanges());
        final var handler = new AssemblyContextVulnerability(this.getBlackboardWrapper(), 
                dataHandler, AttackVector.NETWORK, getAttackGraph());
        final var rootNode = getAttackGraph().getRootNodeContent();
        final var criticalComponent = rootNode.getContainedElementAsPCMElement().getAssemblycontext();
        final ResourceContainer attackerResource = getResourceContainer(criticalComponent);
        
        final var attackerNode = getAttackGraph().addOrFindChild(rootNode, new AttackStatusNodeContent(attackerResource));

        Assert.assertFalse(attackerNode.isCompromised());
        Assert.assertTrue(getAttackGraph().getCompromisationCauseIds(attackerNode).isEmpty());
        Assert.assertNull(getAttackGraph().getEdge(attackerNode, attackerNode));
        
        // attack and compromise root node
        handler.attackAssemblyContext(Arrays.asList(criticalComponent), getChanges(), attackerResource, false);
        Assert.assertTrue(rootNode.isCompromised());
        Assert.assertFalse(getAttackGraph().getCompromisationCauseIds(rootNode).isEmpty());
        Assert.assertEquals(VULN_ID, getAttackGraph().getCompromisationCauseIds(rootNode).toArray(String[]::new)[0]);
        Assert.assertTrue(getAttackGraph().getEdge(rootNode, attackerNode).contains(VULN_ID));
    }
    
    @Test
    public void attackAssemblyContextVulnerabilityAttackViaCompromisedResourceContainerTest() {
        final var dataHandler = new DataHandlerAttacker(getChanges());
        final var handler = new AssemblyContextVulnerability(this.getBlackboardWrapper(), 
                dataHandler, AttackVector.NETWORK, getAttackGraph());
        final var rootNode = getAttackGraph().getRootNodeContent();
        final var criticalComponent = rootNode.getContainedElementAsPCMElement().getAssemblycontext();
        final ResourceContainer attackerResource = getResourceContainer(criticalComponent);

        final var attackerNode = getAttackGraph().addOrFindChild(rootNode, new AttackStatusNodeContent(attackerResource));
        
        // attack and compromise attackerNode
        final var resourceHandler = new ResourceContainerVulnerability(this.getBlackboardWrapper(),
                dataHandler, AttackVector.NETWORK, getAttackGraph());
        resourceHandler.attackResourceContainer(Arrays.asList(attackerResource), getChanges(), attackerResource);
        Assert.assertTrue(attackerNode.isCompromised());
        Assert.assertFalse(getAttackGraph().getCompromisationCauseIds(attackerNode).isEmpty());
        Assert.assertEquals(VULN_ID, getAttackGraph().getCompromisationCauseIds(attackerNode).toArray(String[]::new)[0]);
        Assert.assertTrue(getAttackGraph().getEdge(attackerNode, attackerNode).contains(VULN_ID));
        
        // attack and compromise root node
        handler.attackAssemblyContext(Arrays.asList(criticalComponent), getChanges(), attackerResource, false);
        Assert.assertTrue(rootNode.isCompromised());
        Assert.assertFalse(getAttackGraph().getCompromisationCauseIds(rootNode).isEmpty());
        Assert.assertEquals(VULN_ID, getAttackGraph().getCompromisationCauseIds(rootNode).toArray(String[]::new)[0]);
        Assert.assertTrue(getAttackGraph().getEdge(rootNode, attackerNode).contains(VULN_ID));
    }
    
    // context tests
    @Test
    public void attackAssemblyContextContextViaUncompromisedTest() {
        final var dataHandler = new DataHandlerAttacker(getChanges());
        final var handler = new AssemblyContextContext(this.getBlackboardWrapper(), 
                dataHandler, getAttackGraph());
        final var rootNode = getAttackGraph().getRootNodeContent();
        final var criticalComponent = rootNode.getContainedElementAsPCMElement().getAssemblycontext();
        
        handler.attackAssemblyContext(Arrays.asList(criticalComponent), getChanges(), criticalComponent, false);
        Assert.assertFalse(rootNode.isCompromised());
        Assert.assertTrue(getAttackGraph().getCompromisationCauseIds(rootNode).isEmpty());
        Assert.assertNull(getAttackGraph().getEdge(rootNode, rootNode));
    }

    @Test
    public void attackAssemblyContextContextAttackViaUncompromisedResourceContainerTest() {
        final var dataHandler = new DataHandlerAttacker(getChanges());
        final var handler = new AssemblyContextContext(this.getBlackboardWrapper(), 
                dataHandler, getAttackGraph());
        final var rootNode = getAttackGraph().getRootNodeContent();
        final var criticalComponent = rootNode.getContainedElementAsPCMElement().getAssemblycontext();
        final var criticalResource = getResourceContainer(criticalComponent);
        final ResourceContainer attackerResource = getConnectedResourceContainers(criticalResource).get(0);
        
        final var attackerNode = getAttackGraph().addOrFindChild(rootNode, new AttackStatusNodeContent(attackerResource));

        Assert.assertFalse(attackerNode.isCompromised());
        Assert.assertTrue(getAttackGraph().getCompromisationCauseIds(attackerNode).isEmpty());
        Assert.assertNull(getAttackGraph().getEdge(attackerNode, attackerNode));
        
        // attack and not compromise root node
        handler.attackAssemblyContext(Arrays.asList(criticalComponent), getChanges(), attackerResource, false);
        Assert.assertFalse(rootNode.isCompromised());
        Assert.assertTrue(getAttackGraph().getCompromisationCauseIds(rootNode).isEmpty());
        Assert.assertNull(getAttackGraph().getEdge(rootNode, rootNode));
    }
    
    @Test
    public void attackAssemblyContextContextAttackViaCompromisedResourceContainerTest() {
        final var dataHandler = new DataHandlerAttacker(getChanges());
        final var handler = new AssemblyContextContext(this.getBlackboardWrapper(), 
                dataHandler, getAttackGraph());
        final var rootNode = getAttackGraph().getRootNodeContent();
        final var criticalComponent = rootNode.getContainedElementAsPCMElement().getAssemblycontext();
        final ResourceContainer attackerResource = getResourceContainer(criticalComponent);

        final var attackerNode = getAttackGraph().addOrFindChild(rootNode, new AttackStatusNodeContent(attackerResource));
        addRootAccess();
        
        // attack and compromise attackerNode
        final var resourceHandler = new ResourceContainerContext(this.getBlackboardWrapper(),
                dataHandler, getAttackGraph());
        
        resourceHandler.attackResourceContainer(Arrays.asList(attackerResource), getChanges(), attackerResource);
        Assert.assertTrue(attackerNode.isCompromised());
        Assert.assertFalse(getAttackGraph().getCompromisationCauseIds(attackerNode).isEmpty());
        Assert.assertEquals(CRED_ID, getAttackGraph().getCompromisationCauseIds(attackerNode).toArray(String[]::new)[0]);
        Assert.assertTrue(getAttackGraph().getEdge(attackerNode, attackerNode).contains(CRED_ID));
        
        // attack and compromise root node
        handler.attackAssemblyContext(Arrays.asList(criticalComponent), getChanges(), attackerResource, true);
        Assert.assertTrue(rootNode.isCompromised());
    }
    
}
