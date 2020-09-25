package edu.kit.ipd.sdq.kamp4attack.tests.change;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.eclipse.emf.ecore.util.EcoreUtil;
import org.junit.jupiter.api.Test;

import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.ContextChanges;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksFactory;

class PropagationContextAssemblyTest extends AbstractChangeTests {

    private void isNoContextChangeNoResourceNoLinking(final CredentialChange change) {
        assertTrue(change.getContextchange().isEmpty());
        this.isNoResourceChangeLinkingChange(change);
    }

    private void isNoResourceChangeLinkingChange(final CredentialChange change) {
        assertTrue(change.getCompromisedresource().isEmpty());
        assertTrue(change.getCompromisedlinkingresource().isEmpty());
    }

    private void runContextToAssemblyPropagation(final CredentialChange change) {
        final var wrapper = this.getBlackboardWrapper();
        final var contextChange = new ContextChanges(wrapper);
        contextChange.calculateContextToAssemblyPropagation(change);
    }

    @Test
    void testContextToAssemblyContextNoSpecification() {
        final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();

        final var ownedContext = this.createContext("Owned");
        final var context = this.createContext("Test");
        final var contextSet = this.createContextSet(context);

        final var compromissedComponent = this.createAssembly(change);
        final var assemblyComponent = compromissedComponent.getAffectedElement();

        this.createContextChange(ownedContext, change);

        this.createPolicyAssembly(contextSet, this.assembly.getAssemblyContexts__ComposedStructure().get(0));

        this.createPolicyResource(contextSet, this.environment.getResourceContainer_ResourceEnvironment().get(0));

        this.createPolicyLinking(contextSet, this.environment.getLinkingResources__ResourceEnvironment().get(0));

        this.runContextToAssemblyPropagation(change);

        this.isNoResourceChangeLinkingChange(change);

        assertEquals(1, change.getContextchange().size());
        assertTrue(EcoreUtil.equals(ownedContext, change.getContextchange().get(0).getAffectedElement()));
        assertEquals(1, change.getCompromisedassembly().size());
        assertTrue(EcoreUtil.equals(assemblyComponent, change.getCompromisedassembly().get(0).getAffectedElement()));
        assertFalse(change.isChanged());

    }

    @Test
    void testContextToAssemblyPropagationDuplicate() {
        final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();

        final var context = this.createContext("Test");
        final var contextSet = this.createContextSet(context);

        this.createAssembly(change, this.assembly.getAssemblyContexts__ComposedStructure().get(0));

        this.createContextChange(context, change);

        this.createPolicyAssembly(contextSet, this.assembly.getAssemblyContexts__ComposedStructure().get(0));

        this.createPolicyResource(contextSet, this.environment.getResourceContainer_ResourceEnvironment().get(0));

        this.createPolicyLinking(contextSet, this.environment.getLinkingResources__ResourceEnvironment().get(0));

        this.runContextToAssemblyPropagation(change);

        this.isNoResourceChangeLinkingChange(change);

        assertEquals(1, change.getContextchange().size());
        assertTrue(EcoreUtil.equals(context, change.getContextchange().get(0).getAffectedElement()));
        assertEquals(1, change.getCompromisedassembly().size());
        assertTrue(change.getCompromisedassembly().stream().anyMatch(e -> EcoreUtil.equals(e.getAffectedElement(),
                this.assembly.getAssemblyContexts__ComposedStructure().get(0))));
        assertFalse(change.isChanged());

    }

    @Test
    void testContextToAssemblyPropagationNoAssemblyComponent() {
        final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();

        final var context = this.createContext("Test");
        final var contextSet = this.createContextSet(context);

        this.createPolicyAssembly(contextSet, this.assembly.getAssemblyContexts__ComposedStructure().get(0));

        this.createPolicyResource(contextSet, this.environment.getResourceContainer_ResourceEnvironment().get(0));

        this.createPolicyLinking(contextSet, this.environment.getLinkingResources__ResourceEnvironment().get(0));

        this.runContextToAssemblyPropagation(change);

        this.isNoContextChangeNoResourceNoLinking(change);
        assertTrue(change.getCompromisedassembly().isEmpty());
        assertFalse(change.isChanged());

    }

    @Test
    void testContextToAssemblyPropagationNoContextNoAssemblyComponent() {
        final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();

        this.runContextToAssemblyPropagation(change);
        this.isNoContextChangeNoResourceNoLinking(change);

        assertTrue(change.getCompromisedassembly().isEmpty());
        assertFalse(change.isChanged());

    }

    @Test
    void testContextToAssemblyPropagationNoSpecificationNoContext() {
        final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();

        final var compromissedComponent = this.createAssembly(change);
        final var assemblyComponent = compromissedComponent.getAffectedElement();
        this.runContextToAssemblyPropagation(change);

        this.isNoContextChangeNoResourceNoLinking(change);

        assertEquals(1, change.getCompromisedassembly().size());
        assertTrue(EcoreUtil.equals(assemblyComponent, change.getCompromisedassembly().get(0).getAffectedElement()));
        assertFalse(change.isChanged());

    }

    @Test
    void testContextToAssemblyPropagationProvided() {
        final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();

        final var context = this.createContext("Test");
        final var contextSet = this.createContextSet(context);

        this.createAssembly(change);

        this.createContextChange(context, change);

        this.createPolicyAssembly(contextSet, this.assembly.getAssemblyContexts__ComposedStructure().get(0));
        this.createPolicyAssembly(contextSet, this.assembly.getAssemblyContexts__ComposedStructure().get(1));
        this.createPolicyAssembly(contextSet, this.assembly.getAssemblyContexts__ComposedStructure().get(2));

        this.createPolicyResource(contextSet, this.environment.getResourceContainer_ResourceEnvironment().get(0));

        this.createPolicyLinking(contextSet, this.environment.getLinkingResources__ResourceEnvironment().get(0));

        this.runContextToAssemblyPropagation(change);

        this.isNoResourceChangeLinkingChange(change);

        assertEquals(1, change.getContextchange().size());
        assertTrue(EcoreUtil.equals(context, change.getContextchange().get(0).getAffectedElement()));
        assertEquals(2, change.getCompromisedassembly().size());
        assertTrue(change.getCompromisedassembly().stream().anyMatch(e -> EcoreUtil.equals(e.getAffectedElement(),
                this.assembly.getAssemblyContexts__ComposedStructure().get(0))));
        assertTrue(change.getCompromisedassembly().stream().anyMatch(e -> EcoreUtil.equals(e.getAffectedElement(),
                this.assembly.getAssemblyContexts__ComposedStructure().get(2))));
        assertTrue(change.isChanged());

    }

    @Test
    void testContextToAssemblyPropagationRequired() {
        final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();

        final var context = this.createContext("Test");
        final var contextSet = this.createContextSet(context);

        this.createAssembly(change, this.assembly.getAssemblyContexts__ComposedStructure().get(2));

        this.createContextChange(context, change);

        this.createPolicyAssembly(contextSet, this.assembly.getAssemblyContexts__ComposedStructure().get(0));
        this.createPolicyAssembly(contextSet, this.assembly.getAssemblyContexts__ComposedStructure().get(1));
        this.createPolicyAssembly(contextSet, this.assembly.getAssemblyContexts__ComposedStructure().get(2));

        this.createPolicyResource(contextSet, this.environment.getResourceContainer_ResourceEnvironment().get(0));

        this.createPolicyLinking(contextSet, this.environment.getLinkingResources__ResourceEnvironment().get(0));

        this.runContextToAssemblyPropagation(change);

        this.isNoResourceChangeLinkingChange(change);

        assertEquals(1, change.getContextchange().size());
        assertTrue(EcoreUtil.equals(context, change.getContextchange().get(0).getAffectedElement()));
        assertEquals(3, change.getCompromisedassembly().size());
        assertTrue(change.getCompromisedassembly().stream().anyMatch(e -> EcoreUtil.equals(e.getAffectedElement(),
                this.assembly.getAssemblyContexts__ComposedStructure().get(0))));
        assertTrue(change.getCompromisedassembly().stream().anyMatch(e -> EcoreUtil.equals(e.getAffectedElement(),
                this.assembly.getAssemblyContexts__ComposedStructure().get(2))));
        assertTrue(change.getCompromisedassembly().stream().anyMatch(e -> EcoreUtil.equals(e.getAffectedElement(),
                this.assembly.getAssemblyContexts__ComposedStructure().get(1))));
        assertTrue(change.isChanged());

    }

    @Test
    void testContextToAssemblyPropagationRequiredNoSpecificationThirdComponent() {
        final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();

        final var context = this.createContext("Test");
        final var contextSet = this.createContextSet(context);

        this.createAssembly(change, this.assembly.getAssemblyContexts__ComposedStructure().get(2));

        this.createContextChange(context, change);

        this.createPolicyAssembly(contextSet, this.assembly.getAssemblyContexts__ComposedStructure().get(0));
        this.createPolicyAssembly(contextSet, this.assembly.getAssemblyContexts__ComposedStructure().get(2));

        this.createPolicyResource(contextSet, this.environment.getResourceContainer_ResourceEnvironment().get(0));

        this.createPolicyLinking(contextSet, this.environment.getLinkingResources__ResourceEnvironment().get(0));

        this.runContextToAssemblyPropagation(change);

        this.isNoResourceChangeLinkingChange(change);

        assertEquals(1, change.getContextchange().size());
        assertTrue(EcoreUtil.equals(context, change.getContextchange().get(0).getAffectedElement()));
        assertEquals(2, change.getCompromisedassembly().size());
        assertTrue(change.getCompromisedassembly().stream().anyMatch(e -> EcoreUtil.equals(e.getAffectedElement(),
                this.assembly.getAssemblyContexts__ComposedStructure().get(0))));
        assertTrue(change.getCompromisedassembly().stream().anyMatch(e -> EcoreUtil.equals(e.getAffectedElement(),
                this.assembly.getAssemblyContexts__ComposedStructure().get(2))));
        assertTrue(change.isChanged());

    }

    @Test
    void testContextToAssemblyPropagationRequiredSpecificationThirdComponentWrongContext() {
        final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();

        final var context = this.createContext("Test");
        final var contextSet = this.createContextSet(context);

        final var differentContext = this.createContext("different");
        final var differentContextSet = this.createContextSet(differentContext);

        this.createAssembly(change, this.assembly.getAssemblyContexts__ComposedStructure().get(2));

        this.createContextChange(context, change);

        this.createPolicyAssembly(contextSet, this.assembly.getAssemblyContexts__ComposedStructure().get(0));
        this.createPolicyAssembly(differentContextSet, this.assembly.getAssemblyContexts__ComposedStructure().get(0));
        this.createPolicyAssembly(contextSet, this.assembly.getAssemblyContexts__ComposedStructure().get(2));

        this.createPolicyResource(contextSet, this.environment.getResourceContainer_ResourceEnvironment().get(0));

        this.createPolicyLinking(contextSet, this.environment.getLinkingResources__ResourceEnvironment().get(0));

        this.runContextToAssemblyPropagation(change);

        this.isNoResourceChangeLinkingChange(change);

        assertEquals(1, change.getContextchange().size());
        assertTrue(EcoreUtil.equals(context, change.getContextchange().get(0).getAffectedElement()));
        assertEquals(2, change.getCompromisedassembly().size());
        assertTrue(change.getCompromisedassembly().stream().anyMatch(e -> EcoreUtil.equals(e.getAffectedElement(),
                this.assembly.getAssemblyContexts__ComposedStructure().get(0))));
        assertTrue(change.getCompromisedassembly().stream().anyMatch(e -> EcoreUtil.equals(e.getAffectedElement(),
                this.assembly.getAssemblyContexts__ComposedStructure().get(2))));
        assertTrue(change.isChanged());

    }

    @Test
    void testContextToAssemblyPropagationWrongContext() {
        final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();

        final var ownedContext = this.createContext("Owned");
        final var context = this.createContext("Test");
        final var contextSet = this.createContextSet(context);

        final var compromissedComponent = this.createAssembly(change);
        final var assemblyComponent = compromissedComponent.getAffectedElement();

        this.createContextChange(ownedContext, change);

        this.createPolicyAssembly(contextSet, this.assembly.getAssemblyContexts__ComposedStructure().get(0));
        this.createPolicyAssembly(contextSet, this.assembly.getAssemblyContexts__ComposedStructure().get(1));
        this.createPolicyAssembly(contextSet, this.assembly.getAssemblyContexts__ComposedStructure().get(2));

        this.createPolicyResource(contextSet, this.environment.getResourceContainer_ResourceEnvironment().get(0));

        this.createPolicyLinking(contextSet, this.environment.getLinkingResources__ResourceEnvironment().get(0));

        this.runContextToAssemblyPropagation(change);

        this.isNoResourceChangeLinkingChange(change);

        assertEquals(1, change.getContextchange().size());
        assertTrue(EcoreUtil.equals(ownedContext, change.getContextchange().get(0).getAffectedElement()));
        assertEquals(1, change.getCompromisedassembly().size());
        assertTrue(EcoreUtil.equals(assemblyComponent, change.getCompromisedassembly().get(0).getAffectedElement()));
        assertFalse(change.isChanged());

    }
}
