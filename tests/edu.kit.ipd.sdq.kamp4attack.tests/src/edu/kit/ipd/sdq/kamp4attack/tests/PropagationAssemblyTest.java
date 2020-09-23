package edu.kit.ipd.sdq.kamp4attack.tests;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Optional;

import org.eclipse.emf.ecore.util.EcoreUtil;
import org.junit.jupiter.api.Test;
import org.palladiosimulator.pcm.allocation.AllocationContext;
import org.palladiosimulator.pcm.confidentiality.context.model.ModelFactory;
import org.palladiosimulator.pcm.confidentiality.context.model.SingleAttributeContext;
import org.palladiosimulator.pcm.confidentiality.context.set.ContextSet;
import org.palladiosimulator.pcm.confidentiality.context.set.SetFactory;
import org.palladiosimulator.pcm.confidentiality.context.specification.assembly.AssemblyFactory;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;
import org.palladiosimulator.pcm.resourceenvironment.ResourceContainer;

import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.AssemblyChange;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedAssembly;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksFactory;

public class PropagationAssemblyTest extends AbstractChangeTests {



    @Test
    void testAssemblyToResourcePropagationNoContextsNoSpecification() {
        var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();

        var infectedAssembly = createAssembly(change);

        runAssemblyResourcePropagation(change);

        isNoAssemblyPropagation(change, infectedAssembly);
        assertTrue(change.getContextchange().isEmpty());
    }

    private void isNoAssemblyPropagation(CredentialChange change, CompromisedAssembly infectedAssembly) {
        assertTrue(change.getCompromisedresource().isEmpty());
        assertTrue(change.getCompromisedlinkingresource().isEmpty());
        assertEquals(1,change.getCompromisedassembly().size());
        assertTrue(EcoreUtil.equals(change.getCompromisedassembly().get(0), infectedAssembly));
        assertFalse(change.isChanged());
    }

    @Test
    void testAssemblyToResourcePropagationNoContextAttacker() {
        var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();

        var infectedAssembly = createAssembly(change);

        infectedAssembly.getAffectedElement();

        var resourceOpt = getResource(infectedAssembly);

        // create Context and Contextset and add to containers
        var contextAccess = createContext("Test");
        var contextSetAccessResource = createContextSet(contextAccess);

        var policyRessource = AssemblyFactory.eINSTANCE.createSystemPolicySpecification();
        policyRessource.setResourcecontainer(resourceOpt.get());
        policyRessource.getPolicy().add(contextSetAccessResource);
        context.getPcmspecificationcontainer().getPolicyspecification().add(policyRessource);

        runAssemblyResourcePropagation(change);

        isNoAssemblyPropagation(change, infectedAssembly);
        assertTrue(change.getContextchange().isEmpty());
    }

    @Test
    void testAssemblyToResourcePropagationWrongContextAttacker() {
        var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();

        var infectedAssembly = createAssembly(change);

        infectedAssembly.getAffectedElement();

        var resourceOpt = getResource(infectedAssembly);

        // create Context and Contextset and add to containers
        var contextAccess = createContext("Test");
        var contextSetAccessResource = createContextSet(contextAccess);

        var policyRessource = AssemblyFactory.eINSTANCE.createSystemPolicySpecification();
        policyRessource.setResourcecontainer(resourceOpt.get());
        policyRessource.getPolicy().add(contextSetAccessResource);
        context.getPcmspecificationcontainer().getPolicyspecification().add(policyRessource);

        var attackerContext = createContext("Attacker");
        // ((CredentialAttack)attacker.getAttacks().getAttack().get(0)).getContexts().add(attackerContext);
        var contextChange = KAMP4attackModificationmarksFactory.eINSTANCE.createContextChange();
        contextChange.setAffectedElement(attackerContext);
        change.getContextchange().add(contextChange);

        runAssemblyResourcePropagation(change);

        isNoAssemblyPropagation(change, infectedAssembly);
        assertEquals(1, change.getContextchange().size());
        assertTrue(EcoreUtil.equals(change.getContextchange().get(0), contextChange));
    }

    @Test
    void testAssemblyToResourcePropagation() {

        var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();

        var infectedAssembly = createAssembly(change);

        var resourceOpt = getResource(infectedAssembly);

        // create Context and Contextset and add to containers
        var contextAccess = createContext("Test");
        var contextSetAccessResource = createContextSet(contextAccess);

        var policyRessource = AssemblyFactory.eINSTANCE.createSystemPolicySpecification();
        policyRessource.setResourcecontainer(resourceOpt.get());
        policyRessource.getPolicy().add(contextSetAccessResource);
        context.getPcmspecificationcontainer().getPolicyspecification().add(policyRessource);

        // ((CredentialAttack)attacker.getAttacks().getAttack().get(0)).getContexts().add(attackerContext);
        var contextChange = KAMP4attackModificationmarksFactory.eINSTANCE.createContextChange();
        contextChange.setAffectedElement(contextAccess);
        change.getContextchange().add(contextChange);

        runAssemblyResourcePropagation(change);

        assertTrue(change.getCompromisedlinkingresource().isEmpty());
        assertEquals(1, change.getContextchange().size());
        assertTrue(EcoreUtil.equals(change.getContextchange().get(0), contextChange));

        assertEquals(1, change.getCompromisedassembly().size());
        assertTrue(EcoreUtil.equals(change.getCompromisedassembly().get(0), infectedAssembly));

        assertEquals(1, change.getCompromisedresource().size());
        assertTrue(EcoreUtil.equals(change.getCompromisedresource().get(0).getAffectedElement(), resourceOpt.get()));
        assertTrue(change.isChanged());
    }
    @Test
    void testAssemblyToResourcePropagationDuplicate() {

        var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();

        var infectedAssembly = createAssembly(change);

        var resourceOpt = getResource(infectedAssembly);
        
        var resourceChange = KAMP4attackModificationmarksFactory.eINSTANCE.createCompromisedResource();
        resourceChange.setAffectedElement(resourceOpt.get());
        change.getCompromisedresource().add(resourceChange);

        // create Context and Contextset and add to containers
        var contextAccess = createContext("Test");
        var contextSetAccessResource = createContextSet(contextAccess);

        var policyRessource = AssemblyFactory.eINSTANCE.createSystemPolicySpecification();
        policyRessource.setResourcecontainer(resourceOpt.get());
        policyRessource.getPolicy().add(contextSetAccessResource);
        context.getPcmspecificationcontainer().getPolicyspecification().add(policyRessource);

        // ((CredentialAttack)attacker.getAttacks().getAttack().get(0)).getContexts().add(attackerContext);
        var contextChange = KAMP4attackModificationmarksFactory.eINSTANCE.createContextChange();
        contextChange.setAffectedElement(contextAccess);
        change.getContextchange().add(contextChange);

        runAssemblyResourcePropagation(change);

        assertTrue(change.getCompromisedlinkingresource().isEmpty());
        assertEquals(1, change.getContextchange().size());
        assertTrue(EcoreUtil.equals(change.getContextchange().get(0), contextChange));

        assertEquals(1, change.getCompromisedassembly().size());
        assertTrue(EcoreUtil.equals(change.getCompromisedassembly().get(0), infectedAssembly));

        assertEquals(1, change.getCompromisedresource().size());
        assertTrue(EcoreUtil.equals(change.getCompromisedresource().get(0).getAffectedElement(), resourceOpt.get()));

        //no change happened
        assertFalse(change.isChanged());
    }
    
    
    
    @Test
    void testAssemblyToContextPropagation() {

        var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();

        var infectedAssembly = createAssembly(change);

        // create Context and Contextset
        var contextAccess = createContext("Test");
        var contextSet = createContextSet(contextAccess);

        createAttributeProvider(contextSet, infectedAssembly.getAffectedElement());

       
        runAssemblyToContext(change);
        

        isContextPropagation(change, infectedAssembly, contextAccess);
        
    }
    
    @Test
    void testAssemblyToContextNoPropagationNoAttributeProvider() {

        var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();

        var infectedAssembly = createAssembly(change);

        // create Context and Contextset
        var contextAccess = createContext("Test");
        createContextSet(contextAccess);
       
        runAssemblyToContext(change);
        

        isNoPropagation(change, infectedAssembly);
        
    }
    
    @Test
    void testAssemblyToContextNoPropagationWrongAttributeProvider() {

        var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();

        var infectedAssembly = createAssembly(change);

        // create Context and Contextset
        var contextAccess = createContext("Test");
        var contextSet = createContextSet(contextAccess);
       
        createAttributeProvider(contextSet, assembly.getAssemblyContexts__ComposedStructure().get(2));
        
        runAssemblyToContext(change);
        

        isNoPropagation(change, infectedAssembly);
        
    }

    private void isNoPropagation(CredentialChange change, CompromisedAssembly infectedAssembly) {
        assertFalse(change.isChanged());
        assertTrue(change.getCompromisedlinkingresource().isEmpty());
        assertTrue(change.getCompromisedresource().isEmpty());
        assertTrue(change.getContextchange().isEmpty());
        assertEquals(1, change.getCompromisedassembly().size());
        assertTrue(EcoreUtil.equals(change.getCompromisedassembly().get(0), infectedAssembly));
    }
    
    @Test
    void testAssemblyToContextPropagationWrongAttributeProvider() {

        var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();

        var infectedAssembly = createAssembly(change);

        // create Context and Contextset
        var contextAccess = createContext("Test");
        var contextSet = createContextSet(contextAccess);
       
        var contextOtherComponent = createContext("Other");
        var otherSet = createContextSet(contextOtherComponent);
        
        createAttributeProvider(contextSet, infectedAssembly.getAffectedElement());
        createAttributeProvider(otherSet, assembly.getAssemblyContexts__ComposedStructure().get(2));
        
        
        runAssemblyToContext(change);
        

        isContextPropagation(change, infectedAssembly, contextAccess);
        
    }
    
    @Test
    void testAssemblyToContextPropagationDuplicate() {

        var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();
        

        var infectedAssembly = createAssembly(change);

        // create Context and Contextset
        var contextAccess = createContext("Test");
        var contextSet = createContextSet(contextAccess);
       
        var contextChange = KAMP4attackModificationmarksFactory.eINSTANCE.createContextChange();
        contextChange.setAffectedElement(contextAccess);
        change.getContextchange().add(contextChange);
        
        createAttributeProvider(contextSet, infectedAssembly.getAffectedElement());
        
        
        runAssemblyToContext(change);
        

        contextChangePropagation(change, infectedAssembly, contextAccess);
        
    }

    private void isContextPropagation(CredentialChange change, CompromisedAssembly infectedAssembly,
            SingleAttributeContext contextAccess) {
        contextChangePropagation(change, infectedAssembly, contextAccess);
        
        assertTrue(change.isChanged());

    }

    private void contextChangePropagation(CredentialChange change, CompromisedAssembly infectedAssembly,
            SingleAttributeContext contextAccess) {
        assertTrue(change.getCompromisedlinkingresource().isEmpty());
        assertTrue(change.getCompromisedresource().isEmpty());
        assertEquals(1, change.getContextchange().size());
        assertTrue(EcoreUtil.equals(change.getContextchange().get(0).getAffectedElement(), contextAccess));
        assertEquals(1, change.getCompromisedassembly().size());
        assertTrue(EcoreUtil.equals(change.getCompromisedassembly().get(0), infectedAssembly));
    }



    private void runAssemblyToContext(CredentialChange change) {
        var wrapper = getBlackboardWrapper();
        var assemblyChange = new AssemblyChange(wrapper);
        assemblyChange.calculateAssemblyToContextPropagation(change);
    }
    

    private void runAssemblyResourcePropagation(CredentialChange change) {
        var wrapper = getBlackboardWrapper();
        var assemblyChange = new AssemblyChange(wrapper);
        assemblyChange.calculateAssemblyToResourcePropagation(change);
    }

    private Optional<ResourceContainer> getResource(CompromisedAssembly infectedAssembly) {
        var resourceOpt = this.allocation.getAllocationContexts_Allocation().stream().filter(
                e -> EcoreUtil.equals(e.getAssemblyContext_AllocationContext(), infectedAssembly.getAffectedElement()))
                .map(AllocationContext::getResourceContainer_AllocationContext).findAny();
        if (resourceOpt.isEmpty()) {
            fail("Wrong Test Input");
        }
        return resourceOpt;
    }

    private CompromisedAssembly createAssembly(CredentialChange change) {
        var infectedAssembly = KAMP4attackModificationmarksFactory.eINSTANCE.createCompromisedAssembly();
        var assemblyContext = this.assembly.getAssemblyContexts__ComposedStructure().get(0);
        infectedAssembly.setAffectedElement(assemblyContext);
        change.getCompromisedassembly().add(infectedAssembly);
        return infectedAssembly;
    }
}
