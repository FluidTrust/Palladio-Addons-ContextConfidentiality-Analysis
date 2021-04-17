package edu.kit.ipd.sdq.kamp4attack.tests.change;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.eclipse.emf.ecore.util.EcoreUtil;
import org.junit.jupiter.api.Test;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.data.LinkingChange;

import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksFactory;

class PropagationLinkingTest extends AbstractChangeTests {

    private void runLinkingToContextPropagation(final CredentialChange change) {
        final var wrapper = this.getBlackboardWrapper();
        final var linkingChange = new LinkingChange(wrapper);
        linkingChange.calculateLinkingResourceToContextPropagation(change);
    }

    @Test
    void testLinkingToContextPropagation() {
        final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();

        final var linkingChange = this.createLinkingChange(change);
        final var context = this.createContext("Test");
        final var contextSet = this.createContextSet(context);
        this.createAttributeProvider(contextSet, linkingChange.getAffectedElement());

        this.runLinkingToContextPropagation(change);

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
        final var context = this.createContext("Test");
        final var contextSet = this.createContextSet(context);
        this.createAttributeProvider(contextSet, linkingChange.getAffectedElement());

        final var contextChange = KAMP4attackModificationmarksFactory.eINSTANCE.createContextChange();
        contextChange.setAffectedElement(context);
        change.getContextchange().add(contextChange);

        this.runLinkingToContextPropagation(change);

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
        final var contextOriginal = this.createContext("Own");
        final var context = this.createContext("Test");
        final var contextSet = this.createContextSet(context);
        this.createAttributeProvider(contextSet, linkingChange.getAffectedElement());

        final var contextChange = KAMP4attackModificationmarksFactory.eINSTANCE.createContextChange();
        contextChange.setAffectedElement(contextOriginal);
        change.getContextchange().add(contextChange);

        this.runLinkingToContextPropagation(change);

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
        final var context = this.createContext("Test");
        this.createContextSet(context);

        this.runLinkingToContextPropagation(change);

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
        final var context = this.createContext("Test");
        final var contextSet = this.createContextSet(context);
        this.createAttributeProvider(contextSet, this.environment.getLinkingResources__ResourceEnvironment().get(1));

        this.runLinkingToContextPropagation(change);

        assertEquals(1, change.getCompromisedlinkingresource().size());
        assertTrue(EcoreUtil.equals(change.getCompromisedlinkingresource().get(0), linkingChange));
        assertTrue(change.getContextchange().isEmpty());
        assertTrue(change.getCompromisedassembly().isEmpty());
        assertTrue(change.getCompromisedresource().isEmpty());
        assertFalse(change.isChanged());

    }

}
