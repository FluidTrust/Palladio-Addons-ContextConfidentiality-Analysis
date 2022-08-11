package edu.kit.ipd.sdq.kamp4attack.tests.change.credentials;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.eclipse.emf.ecore.util.EcoreUtil;
import org.junit.jupiter.api.Test;
import org.palladiosimulator.pcm.confidentiality.context.system.UsageSpecification;

import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.AssemblyContextPropagationContext;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.ResourceContainerPropagationContext;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksFactory;
import edu.kit.ipd.sdq.kamp4attack.tests.change.AbstractChangeTests;

class PropagationContextLinkingTest extends AbstractChangeTests {

    private void createPolicies(final UsageSpecification contextSet) {
        createPolicyEntity(contextSet, this.environment.getLinkingResources__ResourceEnvironment().get(0));
        createPolicyEntity(contextSet, this.assembly.getAssemblyContexts__ComposedStructure().get(0));
        createPolicyEntity(contextSet, this.assembly.getAssemblyContexts__ComposedStructure().get(1));
        createPolicyEntity(contextSet, this.assembly.getAssemblyContexts__ComposedStructure().get(2));
        createPolicyEntity(contextSet, this.environment.getResourceContainer_ResourceEnvironment().get(0));
        createPolicyEntity(contextSet, this.environment.getResourceContainer_ResourceEnvironment().get(1));
        createPolicyEntity(contextSet, this.environment.getResourceContainer_ResourceEnvironment().get(2));
    }

    private void isNoAssemblyChangeLinkingChange(final CredentialChange change) {
        assertTrue(change.getCompromisedassembly().isEmpty());
        assertTrue(change.getCompromisedlinkingresource().isEmpty());
    }

    private void isNoContextChangeNoAssemblyNoLinking(final CredentialChange change) {
        assertTrue(change.getContextchange().isEmpty());
        isNoAssemblyChangeLinkingChange(change);
    }

    private void runResourceToLinkingPropagation(final CredentialChange change) {
        generateXML();
        final var wrapper = getBlackboardWrapper();
        final var contextChange = new ResourceContainerPropagationContext(wrapper, change);
        contextChange.calculateResourceContainerToLinkingResourcePropagation();
        // final var contextChange = new
        // contextChange.calculateContextToLinkingPropagation(change);
    }

    private void runAssemblyToLinkingPropagation(final CredentialChange change) {
        generateXML();
        final var wrapper = getBlackboardWrapper();
        final var contextChange = new AssemblyContextPropagationContext(wrapper, change);
        contextChange.calculateAssemblyContextToLinkingResourcePropagation();
        // final var contextChange = new
        // contextChange.calculateContextToLinkingPropagation(change);
    }

    @Test
    void testContextToLinkingAssemblyStartpoint() {
        final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();

        final var context = createContext("Test");

        final var assemblyChange = this.createAssembly(change);
        final var assemblyComponent = assemblyChange.getAffectedElement();

        createContextChange(context, change);

        createPolicies(context);

        runAssemblyToLinkingPropagation(change);

        assertEquals(1, change.getContextchange().size());
        assertTrue(EcoreUtil.equals(change.getContextchange().get(0).getAffectedElement(), context));
        assertTrue(change.getCompromisedresource().isEmpty());
        assertEquals(1, change.getCompromisedlinkingresource().size());
        assertTrue(EcoreUtil.equals(change.getCompromisedlinkingresource().get(0).getAffectedElement(),
                this.environment.getLinkingResources__ResourceEnvironment().get(0)));
        assertEquals(1, change.getCompromisedassembly().size());
        assertTrue(EcoreUtil.equals(change.getCompromisedassembly().get(0).getAffectedElement(), assemblyComponent));
        assertTrue(change.isChanged());
    }

    @Test
    void testContextToLinkingPropagationNoContext() {
        final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();

        final var context = createContext("Test");

        final var resourceChange = this.createResourceChange(change);
        final var resource = resourceChange.getAffectedElement();

        createPolicyEntity(context, this.environment.getLinkingResources__ResourceEnvironment().get(0));

        runResourceToLinkingPropagation(change);

        isNoContextChangeNoAssemblyNoLinking(change);
        assertEquals(1, change.getCompromisedresource().size());
        assertTrue(EcoreUtil.equals(change.getCompromisedresource().get(0).getAffectedElement(), resource));
        assertFalse(change.isChanged());
    }

    @Test
    void testContextToLinkingPropagationNoContextNoStartResource() {
        final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();

        final var context = createContext("Test");
        createPolicyEntity(context, this.environment.getLinkingResources__ResourceEnvironment().get(0));

        runResourceToLinkingPropagation(change);

        isNoContextChangeNoAssemblyNoLinking(change);
        assertTrue(change.getCompromisedresource().isEmpty());
        assertFalse(change.isChanged());
    }

    @Test
    void testContextToLinkingPropagationResourceStartpoint() {
        final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();

        final var context = createContext("Test");

        final var resourceChange = this.createResourceChange(change);
        final var resource = resourceChange.getAffectedElement();

        createContextChange(context, change);

        createPolicies(context);

        runResourceToLinkingPropagation(change);

        assertEquals(1, change.getContextchange().size());
        assertTrue(EcoreUtil.equals(change.getContextchange().get(0).getAffectedElement(), context));
        assertTrue(change.getCompromisedassembly().isEmpty());
        assertEquals(1, change.getCompromisedlinkingresource().size());
        assertTrue(EcoreUtil.equals(change.getCompromisedlinkingresource().get(0).getAffectedElement(),
                this.environment.getLinkingResources__ResourceEnvironment().get(0)));
        assertEquals(1, change.getCompromisedresource().size());
        assertTrue(EcoreUtil.equals(change.getCompromisedresource().get(0).getAffectedElement(), resource));
        assertTrue(change.isChanged());
    }

    @Test
    void testContextToLinkingPropagationResourceStartpointDuplicate() {
        final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();

        final var context = createContext("Test");

        final var resourceChange = this.createResourceChange(change);
        final var resource = resourceChange.getAffectedElement();

        createContextChange(context, change);
        this.createLinkingChange(change);

        createPolicies(context);

        runResourceToLinkingPropagation(change);

        assertEquals(1, change.getContextchange().size());
        assertTrue(EcoreUtil.equals(change.getContextchange().get(0).getAffectedElement(), context));
        assertTrue(change.getCompromisedassembly().isEmpty());
        assertEquals(1, change.getCompromisedlinkingresource().size());
        assertTrue(EcoreUtil.equals(change.getCompromisedlinkingresource().get(0).getAffectedElement(),
                this.environment.getLinkingResources__ResourceEnvironment().get(0)));
        assertEquals(1, change.getCompromisedresource().size());
        assertTrue(EcoreUtil.equals(change.getCompromisedresource().get(0).getAffectedElement(), resource));
        assertFalse(change.isChanged());
    }

    @Test
    void testContextToLinkingPropagationWrongContext() {
        final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();

        final var ownedContext = createContext("Owned");

        final var context = createContext("Test");

        final var resourceChange = this.createResourceChange(change);
        final var resource = resourceChange.getAffectedElement();

        createContextChange(ownedContext, change);

        createPolicyEntity(context, this.environment.getLinkingResources__ResourceEnvironment().get(0));

        runResourceToLinkingPropagation(change);

        isNoAssemblyChangeLinkingChange(change);
        assertEquals(1, change.getContextchange().size());
        assertTrue(EcoreUtil.equals(change.getContextchange().get(0).getAffectedElement(), ownedContext));
        assertEquals(1, change.getCompromisedresource().size());
        assertTrue(EcoreUtil.equals(change.getCompromisedresource().get(0).getAffectedElement(), resource));
        assertFalse(change.isChanged());
    }

    @Test
    void testContextToLinkingPropagationWrongSpecification() {
        final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();

        final var context = createContext("Test");

        final var resourceChange = this.createResourceChange(change);
        final var resource = resourceChange.getAffectedElement();

        createContextChange(context, change);

        createPolicyEntity(context, this.environment.getLinkingResources__ResourceEnvironment().get(1));

        runResourceToLinkingPropagation(change);

        isNoAssemblyChangeLinkingChange(change);
        assertEquals(1, change.getContextchange().size());
        assertTrue(EcoreUtil.equals(change.getContextchange().get(0).getAffectedElement(), context));
        assertEquals(1, change.getCompromisedresource().size());
        assertTrue(EcoreUtil.equals(change.getCompromisedresource().get(0).getAffectedElement(), resource));
        assertFalse(change.isChanged());
    }

}
