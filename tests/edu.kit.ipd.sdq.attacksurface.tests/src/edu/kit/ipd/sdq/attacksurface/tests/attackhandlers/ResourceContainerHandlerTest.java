package edu.kit.ipd.sdq.attacksurface.tests.attackhandlers;

import java.util.Arrays;

import org.eclipse.emf.ecore.util.EcoreUtil;
import org.junit.Assert;
import org.junit.jupiter.api.Test;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.data.DataHandlerAttacker;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.AttackVector;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.Vulnerability;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.PcmIntegrationFactory;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.SystemIntegration;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.VulnerabilitySystemIntegration;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;
import org.palladiosimulator.pcm.core.entity.Entity;
import org.palladiosimulator.pcm.resourceenvironment.ResourceContainer;

import edu.kit.ipd.sdq.attacksurface.core.changepropagation.attackhandlers.ResourceContainerHandler;
import edu.kit.ipd.sdq.attacksurface.core.changepropagation.attackhandlers.context.AssemblyContextContext;
import edu.kit.ipd.sdq.attacksurface.core.changepropagation.attackhandlers.context.ResourceContainerContext;
import edu.kit.ipd.sdq.attacksurface.core.changepropagation.attackhandlers.vulnerability.AssemblyContextVulnerability;
import edu.kit.ipd.sdq.attacksurface.core.changepropagation.attackhandlers.vulnerability.ResourceContainerVulnerability;
import edu.kit.ipd.sdq.attacksurface.graph.AttackGraph;
import edu.kit.ipd.sdq.attacksurface.graph.AttackStatusNodeContent;
import edu.kit.ipd.sdq.attacksurface.graph.PCMElementType;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;

public class ResourceContainerHandlerTest extends AbstractAttackHandlerTest {
    private static final String VULN_ID = "TestVulnerabilityId123456";
    private static final String CRED_ID  = "_fmYV4VWvEeyAu8-8Lz7_vA";
    
    @Test
    public void attackResourceContainerVulnerabilitySelfAttackTest() {
        final var dataHandler = new DataHandlerAttacker(getChanges());
        final var handler = new ResourceContainerVulnerability(this.getBlackboardWrapper(),
                dataHandler, AttackVector.NETWORK, getAttackGraph());
        final var rootNode = getAttackGraph().getRootNodeContent();
        final var resource = getResourceContainer(
                rootNode.getContainedElementAsPCMElement().getAssemblycontext());
        final var resourceNode = getAttackGraph().addOrFindChild(rootNode, new AttackStatusNodeContent(resource));
        handler.attackResourceContainer(Arrays.asList(resource), getChanges(), resource);
        Assert.assertTrue(resourceNode.isCompromised());
        Assert.assertFalse(getAttackGraph().getCompromisationCauseIds(resourceNode).isEmpty());
        Assert.assertEquals(VULN_ID, getAttackGraph().getCompromisationCauseIds(resourceNode).toArray(String[]::new)[0]);
        Assert.assertTrue(getAttackGraph().getEdge(resourceNode, resourceNode).contains(VULN_ID));
    }
    
    @Test
    public void attackResourceContainerVulnerabilityAttackViaUncompromisedTest() {
        final var dataHandler = new DataHandlerAttacker(getChanges());
        final var handler = new ResourceContainerVulnerability(this.getBlackboardWrapper(),
                dataHandler, AttackVector.NETWORK, getAttackGraph());
        final var rootNode = getAttackGraph().getRootNodeContent();
        final var resource = getResourceContainer(
                rootNode.getContainedElementAsPCMElement().getAssemblycontext());
        final var resourceNode = getAttackGraph().addOrFindChild(rootNode, new AttackStatusNodeContent(resource));
        
        final var attackerResource = getConnectedResourceContainers(resource)
                .stream()
                .filter(r -> r.getEntityName().contains("P"))
                .findFirst().orElse(null);
        final var attackerNode = getAttackGraph().addOrFindChild(resourceNode, new AttackStatusNodeContent(attackerResource));

        handler.attackResourceContainer(Arrays.asList(attackerResource), getChanges(), attackerResource);
        Assert.assertFalse(attackerNode.isCompromised());
        Assert.assertTrue(getAttackGraph().getCompromisationCauseIds(attackerNode).isEmpty());
        Assert.assertNull(getAttackGraph().getEdge(attackerNode, attackerNode));
        
        // attack and compromise container node
        handler.attackResourceContainer(Arrays.asList(resource), getChanges(), attackerResource);
        Assert.assertTrue(resourceNode.isCompromised());
        Assert.assertFalse(getAttackGraph().getCompromisationCauseIds(resourceNode).isEmpty());
        Assert.assertEquals(VULN_ID, getAttackGraph().getCompromisationCauseIds(resourceNode).toArray(String[]::new)[0]);
        Assert.assertTrue(getAttackGraph().getEdge(resourceNode, attackerNode).contains(VULN_ID));
    }
    
    @Test
    public void attackResourceContainerVulnerabilityCompromisedAttackTest() {
        final var dataHandler = new DataHandlerAttacker(getChanges());
        final var handler = new ResourceContainerVulnerability(this.getBlackboardWrapper(),
                dataHandler, AttackVector.NETWORK, getAttackGraph());
        final var rootNode = getAttackGraph().getRootNodeContent();
        final var resource = getResourceContainer(rootNode.getContainedElementAsPCMElement().getAssemblycontext());
        final var resourceNode = getAttackGraph().addOrFindChild(rootNode, new AttackStatusNodeContent(resource));

        final var attackerResource = getConnectedResourceContainers(resource)
                .stream()
                .filter(r -> r.getEntityName().contains("P"))
                .findFirst().orElse(null);
        final var vulnList = getBlackboardWrapper().getVulnerabilitySpecification().getVulnerabilities();
        vulnList.add(createVulnerabilitySystemIntegration(attackerResource));
        final var attackerNode = getAttackGraph().addOrFindChild(resourceNode, new AttackStatusNodeContent(attackerResource));
        
        // attack and compromise attackerNode
        handler.attackResourceContainer(Arrays.asList(attackerResource), getChanges(), attackerResource);
        Assert.assertTrue(attackerNode.isCompromised());
        Assert.assertFalse(getAttackGraph().getCompromisationCauseIds(attackerNode).isEmpty());
        Assert.assertEquals(VULN_ID, getAttackGraph().getCompromisationCauseIds(attackerNode).toArray(String[]::new)[0]);
        Assert.assertTrue(getAttackGraph().getEdge(attackerNode, attackerNode).contains(VULN_ID));
        
        // attack and compromise resource node
        handler.attackResourceContainer(Arrays.asList(resource), getChanges(), attackerResource);
        Assert.assertTrue(resourceNode.isCompromised());
        Assert.assertFalse(getAttackGraph().getCompromisationCauseIds(resourceNode).isEmpty());
        Assert.assertEquals(VULN_ID, getAttackGraph().getCompromisationCauseIds(resourceNode).toArray(String[]::new)[0]);
        Assert.assertTrue(getAttackGraph().getEdge(resourceNode, attackerNode).contains(VULN_ID));
        
        final int size = vulnList.size();
        vulnList.remove(size - 1);
    }
    
    private SystemIntegration createVulnerabilitySystemIntegration(final ResourceContainer resource) {
        final var sysInteg = PcmIntegrationFactory.eINSTANCE.createVulnerabilitySystemIntegration();
        sysInteg.setPcmelement(PCMElementType.typeOf(resource).toPCMElement(resource));
        sysInteg.setVulnerability(getVulnerability());
        return sysInteg;
    }

    private Vulnerability getVulnerability() {
        return getBlackboardWrapper().getVulnerabilitySpecification().getVulnerabilities()
                .stream()
                .filter(s -> s.getIdOfContent().equals(VULN_ID))
                .map(VulnerabilitySystemIntegration.class::cast)
                .map(s -> s.getVulnerability())
                .findFirst().orElse(null);
    }

    @Test
    public void attackResourceContainerVulnerabilityAttackViaUncompromisedAssemblyContextTest() {
        final var dataHandler = new DataHandlerAttacker(getChanges());
        final var assemblyHandler = new AssemblyContextVulnerability(this.getBlackboardWrapper(), 
                dataHandler, AttackVector.NETWORK, getAttackGraph());
        final var rootNode = getAttackGraph().getRootNodeContent();
        final var criticalResource = getResourceContainer(
                rootNode.getContainedElementAsPCMElement().getAssemblycontext());
        final var criticalNode = getAttackGraph().addOrFindChild(rootNode, new AttackStatusNodeContent(criticalResource));
        final var attackerComponent = getBlackboardWrapper()
                .getAssembly()
                .getAssemblyContexts__ComposedStructure()
                .stream()
                .filter(e -> e.getEntityName().contains("P"))
                .findFirst().orElse(null);
        final var attackerNode = getAttackGraph().addOrFindChild(criticalNode, new AttackStatusNodeContent(attackerComponent));

        assemblyHandler.attackAssemblyContext(Arrays.asList(attackerComponent), getChanges(), attackerComponent, false);
        Assert.assertFalse(attackerNode.isCompromised());
        Assert.assertTrue(getAttackGraph().getCompromisationCauseIds(attackerNode).isEmpty());
        Assert.assertNull(getAttackGraph().getEdge(attackerNode, attackerNode));
        
        // attack and compromise critical container
        final var handler = new ResourceContainerVulnerability(this.getBlackboardWrapper(),
                dataHandler, AttackVector.NETWORK, getAttackGraph());
        handler.attackResourceContainer(Arrays.asList(criticalResource), getChanges(), attackerComponent);
        Assert.assertTrue(criticalNode.isCompromised());
        Assert.assertFalse(getAttackGraph().getCompromisationCauseIds(criticalNode).isEmpty());
        Assert.assertEquals(VULN_ID, getAttackGraph().getCompromisationCauseIds(criticalNode).toArray(String[]::new)[0]);
        Assert.assertTrue(getAttackGraph().getEdge(criticalNode, attackerNode).contains(VULN_ID));
    }
    
    @Test
    public void attackResourceContainerVulnerabilityAttackViaCompromisedAssemblyTest() {
        final var dataHandler = new DataHandlerAttacker(getChanges());
        final var assemblyHandler = new AssemblyContextVulnerability(this.getBlackboardWrapper(), 
                dataHandler, AttackVector.NETWORK, getAttackGraph());
        final var rootNode = getAttackGraph().getRootNodeContent();
        final var criticalResource = getResourceContainer(
                rootNode.getContainedElementAsPCMElement().getAssemblycontext());
        final var criticalNode = getAttackGraph().addOrFindChild(rootNode, new AttackStatusNodeContent(criticalResource));
        final var attackerComponent = getBlackboardWrapper()
                .getAssembly()
                .getAssemblyContexts__ComposedStructure()
                .stream()
                .filter(e -> e.getEntityName().contains("R.1.1"))
                .findFirst().orElse(null);
        final var attackerNode = getAttackGraph().addOrFindChild(criticalNode, new AttackStatusNodeContent(attackerComponent));
        
        // attack and compromise attackerNode
        assemblyHandler.attackAssemblyContext(Arrays.asList(attackerComponent), getChanges(), attackerComponent, false);
        Assert.assertTrue(attackerNode.isCompromised());
        Assert.assertFalse(getAttackGraph().getCompromisationCauseIds(attackerNode).isEmpty());
        Assert.assertEquals(VULN_ID, getAttackGraph().getCompromisationCauseIds(attackerNode).toArray(String[]::new)[0]);
        Assert.assertTrue(getAttackGraph().getEdge(attackerNode, attackerNode).contains(VULN_ID));
        
        final var handler = new ResourceContainerVulnerability(this.getBlackboardWrapper(),
                dataHandler, AttackVector.NETWORK, getAttackGraph());
        // attack and compromise root node
        handler.attackResourceContainer(Arrays.asList(criticalResource), getChanges(), attackerComponent);
        Assert.assertTrue(criticalNode.isCompromised());
        Assert.assertFalse(getAttackGraph().getCompromisationCauseIds(criticalNode).isEmpty());
        Assert.assertEquals(VULN_ID, getAttackGraph().getCompromisationCauseIds(criticalNode).toArray(String[]::new)[0]);
        Assert.assertTrue(getAttackGraph().getEdge(criticalNode, attackerNode).contains(VULN_ID));
    }
    
    // context tests
    @Test
    public void attackResourceContainerContextSelfAttackTest() {
        final var dataHandler = new DataHandlerAttacker(getChanges());
        final var rootNode = getAttackGraph().getRootNodeContent();
        final var criticalComponent = rootNode.getContainedElementAsPCMElement().getAssemblycontext();
        final ResourceContainer attackerResource = getResourceContainer(criticalComponent);

        final var attackerNode = getAttackGraph().addOrFindChild(rootNode, new AttackStatusNodeContent(attackerResource));
        final var changes = addRootAccess();
        
        // attack and compromise attackerNode
        final var resourceHandler = new ResourceContainerContext(this.getBlackboardWrapper(),
                dataHandler, getAttackGraph());
        
        resourceHandler.attackResourceContainer(Arrays.asList(attackerResource), changes, attackerResource);
        Assert.assertTrue(attackerNode.isCompromised());
        Assert.assertFalse(getAttackGraph().getCompromisationCauseIds(attackerNode).isEmpty());
        Assert.assertEquals(CRED_ID, getAttackGraph().getCompromisationCauseIds(attackerNode).toArray(String[]::new)[0]);
        Assert.assertTrue(getAttackGraph().getEdge(attackerNode, attackerNode).contains(CRED_ID));
        
        removeRootAccess();
    }
    
    @Test
    public void attackResourceContainerContextAttackViaUncompromisedTest() {
        final var dataHandler = new DataHandlerAttacker(getChanges());
        final var handler = new ResourceContainerContext(this.getBlackboardWrapper(),
                dataHandler, getAttackGraph());
        final var rootNode = getAttackGraph().getRootNodeContent();
        final var resource = getResourceContainer(
                rootNode.getContainedElementAsPCMElement().getAssemblycontext());
        final var resourceNode = getAttackGraph().addOrFindChild(rootNode, new AttackStatusNodeContent(resource));
        
        final var attackerResource = getConnectedResourceContainers(resource)
                .stream()
                .filter(r -> r.getEntityName().contains("P"))
                .findFirst().orElse(null);
        final var attackerNode = getAttackGraph().addOrFindChild(resourceNode, new AttackStatusNodeContent(attackerResource));
        final var changes = addRootAccess();
        
        handler.attackResourceContainer(Arrays.asList(attackerResource), changes, attackerResource);
        Assert.assertFalse(attackerNode.isCompromised());
        Assert.assertTrue(getAttackGraph().getCompromisationCauseIds(attackerNode).isEmpty());
        Assert.assertNull(getAttackGraph().getEdge(attackerNode, attackerNode));
        
        // attack and compromise container node
        handler.attackResourceContainer(Arrays.asList(resource), changes, attackerResource);
        Assert.assertTrue(resourceNode.isCompromised());
        Assert.assertFalse(getAttackGraph().getCompromisationCauseIds(resourceNode).isEmpty());
        Assert.assertEquals(CRED_ID, getAttackGraph().getCompromisationCauseIds(resourceNode).toArray(String[]::new)[0]);
        Assert.assertTrue(getAttackGraph().getEdge(resourceNode, attackerNode).contains(CRED_ID));
        
        removeRootAccess();
    }
}
