package edu.kit.ipd.sdq.kamp4attack.tests.change.credentials;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.eclipse.emf.ecore.util.EcoreUtil;
import org.junit.jupiter.api.Test;

import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.LinkingPropagationContext;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksFactory;
import edu.kit.ipd.sdq.kamp4attack.tests.change.AbstractChangeTests;

class PropagationLinkingTest extends AbstractChangeTests {

    private void runLinkingToContextPropagation(final CredentialChange change) {
        generateXML();
        final var wrapper = getBlackboardWrapper();
        final var linkingChange = new LinkingPropagationContext(wrapper, change);
        linkingChange.calculateLinkingResourceToContextPropagation();
    }

    @Test
    void testLinkingToContextPropagation() {
        final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();

        final var linkingChange = this.createLinkingChange(change);
        final var context = createContext("Test");
        this.createAttributeProvider(context, linkingChange.getAffectedElement());

        runLinkingToContextPropagation(change);

        assertEquals(1, change.getCompromisedlinkingresource().size());
        assertTrue(EcoreUtil.equals(change.getCompromisedlinkingresource().get(0), linkingChange));
        assertEquals(1, change.getContextchange().size());
        assertTrue(EcoreUtil.equals(change.getContextchange().get(0).getAffectedElement(), context));
        assertTrue(change.getCompromisedassembly().isEmpty());
        assertTrue(change.getCompromisedresource().isEmpty());
        assertTrue(change.isChanged());

    }

    @Test
    void testLinkingToContextPropagationDuplicate() {
        final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();

        final var linkingChange = this.createLinkingChange(change);
        final var context = createContext("Test");
        this.createAttributeProvider(context, linkingChange.getAffectedElement());

        final var contextChange = KAMP4attackModificationmarksFactory.eINSTANCE.createContextChange();
        contextChange.setAffectedElement(context);
        change.getContextchange().add(contextChange);

        runLinkingToContextPropagation(change);

        assertEquals(1, change.getCompromisedlinkingresource().size());
        assertTrue(EcoreUtil.equals(change.getCompromisedlinkingresource().get(0), linkingChange));
        assertEquals(1, change.getContextchange().size());
        assertTrue(EcoreUtil.equals(change.getContextchange().get(0).getAffectedElement(), context));
        assertTrue(change.getCompromisedassembly().isEmpty());
        assertTrue(change.getCompromisedresource().isEmpty());
        assertFalse(change.isChanged());

    }

    @Test
    void testLinkingToContextPropagationKeep() {
        final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();

        final var linkingChange = this.createLinkingChange(change);
        final var contextOriginal = createContext("Own");
        final var context = createContext("Test");
        this.createAttributeProvider(context, linkingChange.getAffectedElement());

        final var contextChange = KAMP4attackModificationmarksFactory.eINSTANCE.createContextChange();
        contextChange.setAffectedElement(contextOriginal);
        change.getContextchange().add(contextChange);

        runLinkingToContextPropagation(change);

        assertEquals(1, change.getCompromisedlinkingresource().size());
        assertTrue(EcoreUtil.equals(change.getCompromisedlinkingresource().get(0), linkingChange));
        assertEquals(2, change.getContextchange().size());
        assertTrue(change.getContextchange().stream()
                .anyMatch(e -> EcoreUtil.equals(e.getAffectedElement(), contextOriginal)));
        assertTrue(change.getContextchange().stream().anyMatch(e -> EcoreUtil.equals(e.getAffectedElement(), context)));
        assertTrue(change.getCompromisedassembly().isEmpty());
        assertTrue(change.getCompromisedresource().isEmpty());
        assertTrue(change.isChanged());

    }

    @Test
    void testLinkingToContextPropagationNoContextProvider() {
        final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();

        final var linkingChange = this.createLinkingChange(change);

        runLinkingToContextPropagation(change);

        assertEquals(1, change.getCompromisedlinkingresource().size());
        assertTrue(EcoreUtil.equals(change.getCompromisedlinkingresource().get(0), linkingChange));
        assertTrue(change.getContextchange().isEmpty());
        assertTrue(change.getCompromisedassembly().isEmpty());
        assertTrue(change.getCompromisedresource().isEmpty());
        assertFalse(change.isChanged());

    }

    @Test
    void testLinkingToContextPropagationWrongProvider() {
        final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();

        final var linkingChange = this.createLinkingChange(change);
        final var context = createContext("Test");
        this.createAttributeProvider(context, this.environment.getLinkingResources__ResourceEnvironment().get(1));

        runLinkingToContextPropagation(change);

        assertEquals(1, change.getCompromisedlinkingresource().size());
        assertTrue(EcoreUtil.equals(change.getCompromisedlinkingresource().get(0), linkingChange));
        assertTrue(change.getContextchange().isEmpty());
        assertTrue(change.getCompromisedassembly().isEmpty());
        assertTrue(change.getCompromisedresource().isEmpty());
        assertFalse(change.isChanged());

    }

}
