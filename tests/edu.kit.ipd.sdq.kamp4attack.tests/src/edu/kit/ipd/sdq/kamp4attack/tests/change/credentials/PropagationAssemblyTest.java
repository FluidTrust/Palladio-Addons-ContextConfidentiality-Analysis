package edu.kit.ipd.sdq.kamp4attack.tests.change.credentials;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Optional;

import org.eclipse.emf.ecore.util.EcoreUtil;
import org.junit.jupiter.api.Test;
import org.palladiosimulator.pcm.allocation.AllocationContext;
import org.palladiosimulator.pcm.confidentiality.context.system.UsageSpecification;
import org.palladiosimulator.pcm.resourceenvironment.ResourceContainer;

import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.AssemblyContextPropagationContext;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedAssembly;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksFactory;
import edu.kit.ipd.sdq.kamp4attack.tests.change.AbstractChangeTests;

class PropagationAssemblyTest extends AbstractChangeTests {

    private void contextChangePropagation(final CredentialChange change, final CompromisedAssembly infectedAssembly,
            final UsageSpecification contextAccess) {
        assertTrue(change.getCompromisedlinkingresource().isEmpty());
        assertTrue(change.getCompromisedresource().isEmpty());
        assertEquals(1, change.getContextchange().size());
        assertTrue(EcoreUtil.equals(change.getContextchange().get(0).getAffectedElement(), contextAccess));
        assertEquals(1, change.getCompromisedassembly().size());
        assertTrue(EcoreUtil.equals(change.getCompromisedassembly().get(0), infectedAssembly));
    }

    private Optional<ResourceContainer> getResource(final CompromisedAssembly infectedAssembly) {
        final var resourceOpt = this.allocation.getAllocationContexts_Allocation().stream().filter(
                e -> EcoreUtil.equals(e.getAssemblyContext_AllocationContext(), infectedAssembly.getAffectedElement()))
                .map(AllocationContext::getResourceContainer_AllocationContext).findAny();
        if (resourceOpt.isEmpty()) {
            fail("Wrong Test Input");
        }
        return resourceOpt;
    }

    private void isContextPropagation(final CredentialChange change, final CompromisedAssembly infectedAssembly,
            final UsageSpecification contextAccess) {
        contextChangePropagation(change, infectedAssembly, contextAccess);

        assertTrue(change.isChanged());

    }

    private void isNoAssemblyPropagation(final CredentialChange change, final CompromisedAssembly infectedAssembly) {
        assertTrue(change.getCompromisedresource().isEmpty());
        assertTrue(change.getCompromisedlinkingresource().isEmpty());
        assertEquals(1, change.getCompromisedassembly().size());
        assertTrue(EcoreUtil.equals(change.getCompromisedassembly().get(0), infectedAssembly));
        assertFalse(change.isChanged());
    }

    private void isNoPropagation(final CredentialChange change, final CompromisedAssembly infectedAssembly) {
        assertFalse(change.isChanged());
        assertTrue(change.getCompromisedlinkingresource().isEmpty());
        assertTrue(change.getCompromisedresource().isEmpty());
        assertTrue(change.getContextchange().isEmpty());
        assertEquals(1, change.getCompromisedassembly().size());
        assertTrue(EcoreUtil.equals(change.getCompromisedassembly().get(0), infectedAssembly));
    }

    private void runAssemblyResourcePropagation(final CredentialChange change) {
        generateXML();
        final var wrapper = getBlackboardWrapper();
        final var assemblyChange = new AssemblyContextPropagationContext(wrapper);
        assemblyChange.calculateAssemblyContextToLocalResourcePropagation(change);

    }

    private void runAssemblyToContext(final CredentialChange change) {
        generateXML();
        final var wrapper = getBlackboardWrapper();
        final var assemblyChange = new AssemblyContextPropagationContext(wrapper);
        assemblyChange.calculateAssemblyContextToContextPropagation(change);
    }

    @Test
    void testAssemblyToContextNoPropagationNoAttributeProvider() {

        final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();

        final var infectedAssembly = this.createAssembly(change);

        runAssemblyToContext(change);

        isNoPropagation(change, infectedAssembly);

    }

    @Test
    void testAssemblyToContextNoPropagationWrongAttributeProvider() {

        final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();

        final var infectedAssembly = this.createAssembly(change);

        // create Context and Contextset
        final var contextSet = createContext("Test");

        this.createAttributeProvider(contextSet, this.assembly.getAssemblyContexts__ComposedStructure().get(2));

        runAssemblyToContext(change);

        isNoPropagation(change, infectedAssembly);

    }

    @Test
    void testAssemblyToContextPropagation() {

        final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();

        final var infectedAssembly = this.createAssembly(change);

        // create Context and Contextset
        final var contextSet = createContext("Test");

        this.createAttributeProvider(contextSet, infectedAssembly.getAffectedElement());

        runAssemblyToContext(change);

        isContextPropagation(change, infectedAssembly, contextSet);

    }

    @Test
    void testAssemblyToContextPropagationDuplicate() {

        final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();

        final var infectedAssembly = this.createAssembly(change);

        // create Context and Contextset
        final var contextSet = createContext("Test");

        final var contextChange = KAMP4attackModificationmarksFactory.eINSTANCE.createContextChange();
        contextChange.setAffectedElement(contextSet);
        change.getContextchange().add(contextChange);

        this.createAttributeProvider(contextSet, infectedAssembly.getAffectedElement());

        runAssemblyToContext(change);

        contextChangePropagation(change, infectedAssembly, contextSet);

    }

    @Test
    void testAssemblyToContextPropagationWrongAttributeProvider() {

        final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();

        final var infectedAssembly = this.createAssembly(change);

        // create Context and Contextset

        final var contextSet = createContext("Test");

        final var contextOtherComponent = createContext("Other");

        this.createAttributeProvider(contextSet, infectedAssembly.getAffectedElement());
        this.createAttributeProvider(contextOtherComponent,
                this.assembly.getAssemblyContexts__ComposedStructure().get(2));

        runAssemblyToContext(change);

        isContextPropagation(change, infectedAssembly, contextSet);

    }

    @Test
    void testAssemblyToResourcePropagation() {

        final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();

        final var infectedAssembly = this.createAssembly(change);

        final var resourceOpt = getResource(infectedAssembly);

        // create Context and Contextset and add to containers
        final var contextAccess = createContext("Test");


        createPolicyEntity(contextAccess, resourceOpt.get());

        // ((CredentialAttack)attacker.getAttacks().getAttack().get(0)).getContexts().add(attackerContext);
        final var contextChange = KAMP4attackModificationmarksFactory.eINSTANCE.createContextChange();
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

        final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();

        final var infectedAssembly = this.createAssembly(change);

        final var resourceOpt = getResource(infectedAssembly);

        final var resourceChange = KAMP4attackModificationmarksFactory.eINSTANCE.createCompromisedResource();
        resourceChange.setAffectedElement(resourceOpt.get());
        change.getCompromisedresource().add(resourceChange);

        // create Context and Contextset and add to containers
        final var contextAccess = createContext("Test");

        createPolicyEntity(contextAccess, resourceOpt.get());

        // ((CredentialAttack)attacker.getAttacks().getAttack().get(0)).getContexts().add(attackerContext);
        final var contextChange = KAMP4attackModificationmarksFactory.eINSTANCE.createContextChange();
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

        // no change happened
        assertFalse(change.isChanged());
    }

    @Test
    void testAssemblyToResourcePropagationNoContextAttacker() {
        final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();

        final var infectedAssembly = this.createAssembly(change);

        infectedAssembly.getAffectedElement();

        final var resourceOpt = getResource(infectedAssembly);

        // create Context and Contextset and add to containers
        final var contextAccess = createContext("Test");

        createPolicyEntity(contextAccess, resourceOpt.get());

        runAssemblyResourcePropagation(change);

        isNoAssemblyPropagation(change, infectedAssembly);
        assertTrue(change.getContextchange().isEmpty());
    }

    @Test
    void testAssemblyToResourcePropagationNoContextsNoSpecification() {
        final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();

        final var infectedAssembly = this.createAssembly(change);

        runAssemblyResourcePropagation(change);

        isNoAssemblyPropagation(change, infectedAssembly);
        assertTrue(change.getContextchange().isEmpty());
    }

    @Test
    void testAssemblyToResourcePropagationWrongContextAttacker() {
        final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();

        final var infectedAssembly = this.createAssembly(change);

        infectedAssembly.getAffectedElement();

        final var resourceOpt = getResource(infectedAssembly);

        // create Context and Contextset and add to containers
        final var contextAccess = createContext("Test");

        createPolicyEntity(contextAccess, resourceOpt.get());

        final var attackerContext = createContext("Attacker");
        // ((CredentialAttack)attacker.getAttacks().getAttack().get(0)).getContexts().add(attackerContext);
        final var contextChange = KAMP4attackModificationmarksFactory.eINSTANCE.createContextChange();
        contextChange.setAffectedElement(attackerContext);
        change.getContextchange().add(contextChange);

        runAssemblyResourcePropagation(change);

        isNoAssemblyPropagation(change, infectedAssembly);
        assertEquals(1, change.getContextchange().size());
        assertTrue(EcoreUtil.equals(change.getContextchange().get(0), contextChange));
    }

}
