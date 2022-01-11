package edu.kit.ipd.sdq.kamp4attack.tests.change.credentials;

import static org.junit.Assert.assertFalse;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.eclipse.emf.ecore.util.EcoreUtil;
import org.junit.jupiter.api.Test;

import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.ResourceContainerPropagationContext;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksFactory;
import edu.kit.ipd.sdq.kamp4attack.tests.change.AbstractChangeTests;

class PropagationContextResourceTest extends AbstractChangeTests {

    private void isNoAssemblyChangeLinkingChange(final CredentialChange change) {
        assertTrue(change.getCompromisedassembly().isEmpty());
        assertTrue(change.getCompromisedlinkingresource().isEmpty());
    }

    private void isNoContextChangeNoAssemblyNoLinking(final CredentialChange change) {
        assertTrue(change.getContextchange().isEmpty());
        isNoAssemblyChangeLinkingChange(change);
    }

    private void runContextToResourcePropagation(final CredentialChange change) {
        generateXML();
        final var wrapper = getBlackboardWrapper();
        //        final var resourceChange = new ContextChanges(wrapper);
        //        resourceChange.calculateContextToResourcePropagation(change);
        final var resourceChange = new ResourceContainerPropagationContext(wrapper, change);
        resourceChange.calculateResourceContainerToResourcePropagation();

    }

    @Test
    void testContextToResourcePropagation() {
        final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();
        final var context = createContext("Test");

        createContextChange(context, change);
        this.createResourceChange(change, this.environment.getResourceContainer_ResourceEnvironment().get(2));
        createPolicyEntity(context, this.environment.getResourceContainer_ResourceEnvironment().get(1));
        createPolicyEntity(context, this.environment.getResourceContainer_ResourceEnvironment().get(0));
        runContextToResourcePropagation(change);

        isNoAssemblyChangeLinkingChange(change);
        assertEquals(1, change.getContextchange().size());
        assertTrue(EcoreUtil.equals(change.getContextchange().get(0).getAffectedElement(), context));
        assertEquals(3, change.getCompromisedresource().size());
        assertTrue(change.getCompromisedresource().stream().anyMatch(e -> EcoreUtil.equals(e.getAffectedElement(),
                this.environment.getResourceContainer_ResourceEnvironment().get(2))));
        assertTrue(change.getCompromisedresource().stream().anyMatch(e -> EcoreUtil.equals(e.getAffectedElement(),
                this.environment.getResourceContainer_ResourceEnvironment().get(1))));
        assertTrue(change.getCompromisedresource().stream().anyMatch(e -> EcoreUtil.equals(e.getAffectedElement(),
                this.environment.getResourceContainer_ResourceEnvironment().get(0))));
        assertTrue(change.isChanged());
    }

    @Test
    void testContextToResourcePropagationDuplicate() {
        final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();
        final var context = createContext("Test");
        createContextChange(context, change);
        this.createResourceChange(change, this.environment.getResourceContainer_ResourceEnvironment().get(2));
        this.createResourceChange(change, this.environment.getResourceContainer_ResourceEnvironment().get(1));
        createPolicyEntity(context, this.environment.getResourceContainer_ResourceEnvironment().get(1));
        runContextToResourcePropagation(change);

        isNoAssemblyChangeLinkingChange(change);
        assertEquals(1, change.getContextchange().size());
        assertTrue(EcoreUtil.equals(change.getContextchange().get(0).getAffectedElement(), context));
        assertEquals(2, change.getCompromisedresource().size());
        assertTrue(change.getCompromisedresource().stream().anyMatch(e -> EcoreUtil.equals(e.getAffectedElement(),
                this.environment.getResourceContainer_ResourceEnvironment().get(2))));
        assertTrue(change.getCompromisedresource().stream().anyMatch(e -> EcoreUtil.equals(e.getAffectedElement(),
                this.environment.getResourceContainer_ResourceEnvironment().get(1))));
        assertFalse(change.isChanged());
    }

    @Test
    void testContextToResourcePropagationNoContextNoStartResource() {
        final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();
        runContextToResourcePropagation(change);
        isNoContextChangeNoAssemblyNoLinking(change);
        assertTrue(change.getCompromisedresource().isEmpty());
        assertFalse(change.isChanged());

    }

    @Test
    void testContextToResourcePropagationNoOwnedContextNoStartResource() {
        final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();
        final var context = createContext("Test");
        createPolicyEntity(context, this.environment.getResourceContainer_ResourceEnvironment().get(0));
        runContextToResourcePropagation(change);
        isNoContextChangeNoAssemblyNoLinking(change);
        assertTrue(change.getCompromisedresource().isEmpty());
        assertFalse(change.isChanged());
    }

    @Test
    void testContextToResourcePropagationNoStartResource() {
        final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();
        final var context = createContext("Test");
        createContextChange(context, change);
        createPolicyEntity(context, this.environment.getResourceContainer_ResourceEnvironment().get(0));
        runContextToResourcePropagation(change);

        isNoAssemblyChangeLinkingChange(change);
        assertEquals(1, change.getContextchange().size());
        assertTrue(EcoreUtil.equals(change.getContextchange().get(0).getAffectedElement(), context));
        assertTrue(change.getCompromisedresource().isEmpty());
        assertFalse(change.isChanged());
    }

    @Test
    void testContextToResourcePropagationOnlyOne() {
        final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();
        final var context = createContext("Test");
        createContextChange(context, change);
        this.createResourceChange(change, this.environment.getResourceContainer_ResourceEnvironment().get(2));
        createPolicyEntity(context, this.environment.getResourceContainer_ResourceEnvironment().get(1));
        runContextToResourcePropagation(change);

        isNoAssemblyChangeLinkingChange(change);
        assertEquals(1, change.getContextchange().size());
        assertTrue(EcoreUtil.equals(change.getContextchange().get(0).getAffectedElement(), context));
        assertEquals(2, change.getCompromisedresource().size());
        assertTrue(change.getCompromisedresource().stream().anyMatch(e -> EcoreUtil.equals(e.getAffectedElement(),
                this.environment.getResourceContainer_ResourceEnvironment().get(2))));
        assertTrue(change.getCompromisedresource().stream().anyMatch(e -> EcoreUtil.equals(e.getAffectedElement(),
                this.environment.getResourceContainer_ResourceEnvironment().get(1))));
        assertTrue(change.isChanged());
    }

}
