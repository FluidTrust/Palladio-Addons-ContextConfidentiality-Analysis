package edu.kit.ipd.sdq.kamp4attack.tests.change;

import static org.junit.Assert.assertFalse;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.eclipse.emf.ecore.util.EcoreUtil;
import org.junit.jupiter.api.Test;

import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.ContextChanges;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksFactory;

class PropagationContextResourceTest extends AbstractChangeTests {

    private void isNoAssemblyChangeLinkingChange(final CredentialChange change) {
        assertTrue(change.getCompromisedassembly().isEmpty());
        assertTrue(change.getCompromisedlinkingresource().isEmpty());
    }

    private void isNoContextChangeNoAssemblyNoLinking(final CredentialChange change) {
        assertTrue(change.getContextchange().isEmpty());
        this.isNoAssemblyChangeLinkingChange(change);
    }

    private void runContextToResourcePropagation(final CredentialChange change) {
        final var wrapper = this.getBlackboardWrapper();
        final var resourceChange = new ContextChanges(wrapper);
        resourceChange.calculateContextToResourcePropagation(change);
    }

    @Test
    void testContextToResourcePropagation() {
        final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();
        final var context = this.createContext("Test");
        final var contextSet = this.createContextSet(context);
        this.createContextChange(context, change);
        this.createResourceChange(change, this.environment.getResourceContainer_ResourceEnvironment().get(2));
        this.createPolicyResource(contextSet, this.environment.getResourceContainer_ResourceEnvironment().get(1));
        this.createPolicyResource(contextSet, this.environment.getResourceContainer_ResourceEnvironment().get(0));
        this.runContextToResourcePropagation(change);

        this.isNoAssemblyChangeLinkingChange(change);
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
        final var context = this.createContext("Test");
        final var contextSet = this.createContextSet(context);
        this.createContextChange(context, change);
        this.createResourceChange(change, this.environment.getResourceContainer_ResourceEnvironment().get(2));
        this.createResourceChange(change, this.environment.getResourceContainer_ResourceEnvironment().get(1));
        this.createPolicyResource(contextSet, this.environment.getResourceContainer_ResourceEnvironment().get(1));
        this.runContextToResourcePropagation(change);

        this.isNoAssemblyChangeLinkingChange(change);
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
        this.runContextToResourcePropagation(change);
        this.isNoContextChangeNoAssemblyNoLinking(change);
        assertTrue(change.getCompromisedresource().isEmpty());
        assertFalse(change.isChanged());

    }

    @Test
    void testContextToResourcePropagationNoOwnedContextNoStartResource() {
        final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();
        final var context = this.createContext("Test");
        final var contextSet = this.createContextSet(context);
        this.createPolicyResource(contextSet, this.environment.getResourceContainer_ResourceEnvironment().get(0));
        this.runContextToResourcePropagation(change);
        this.isNoContextChangeNoAssemblyNoLinking(change);
        assertTrue(change.getCompromisedresource().isEmpty());
        assertFalse(change.isChanged());
    }

    @Test
    void testContextToResourcePropagationNoStartResource() {
        final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();
        final var context = this.createContext("Test");
        final var contextSet = this.createContextSet(context);
        this.createContextChange(context, change);
        this.createPolicyResource(contextSet, this.environment.getResourceContainer_ResourceEnvironment().get(0));
        this.runContextToResourcePropagation(change);

        this.isNoAssemblyChangeLinkingChange(change);
        assertEquals(1, change.getContextchange().size());
        assertTrue(EcoreUtil.equals(change.getContextchange().get(0).getAffectedElement(), context));
        assertTrue(change.getCompromisedresource().isEmpty());
        assertFalse(change.isChanged());
    }

    @Test
    void testContextToResourcePropagationOnlyOne() {
        final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();
        final var context = this.createContext("Test");
        final var contextSet = this.createContextSet(context);
        this.createContextChange(context, change);
        this.createResourceChange(change, this.environment.getResourceContainer_ResourceEnvironment().get(2));
        this.createPolicyResource(contextSet, this.environment.getResourceContainer_ResourceEnvironment().get(1));
        this.runContextToResourcePropagation(change);

        this.isNoAssemblyChangeLinkingChange(change);
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
