package edu.kit.ipd.sdq.kamp4attack.tests.change.credentials;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.eclipse.emf.ecore.util.EcoreUtil;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.AssemblyContextPropagationContext;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksFactory;
import edu.kit.ipd.sdq.kamp4attack.tests.change.AbstractChangeTests;

class PropagationContextAssemblyTest extends AbstractChangeTests {

    private void isNoContextChangeNoResourceNoLinking(final CredentialChange change) {
        assertTrue(change.getContextchange().isEmpty());
        isNoResourceChangeLinkingChange(change);
    }

    private void isNoResourceChangeLinkingChange(final CredentialChange change) {
        assertTrue(change.getCompromisedresource().isEmpty());
        assertTrue(change.getCompromisedlinkingresource().isEmpty());
    }

    private void runContextToAssemblyPropagation(final CredentialChange change) {
        generateXML();
        final var wrapper = getBlackboardWrapper();
        final var contextChange = new AssemblyContextPropagationContext(wrapper);
        contextChange.calculateAssemblyContextToRemoteResourcePropagation(change);
    }

    @Test
    void testContextToAssemblyContextNoSpecification() {
        final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();

        final var ownedContext = createContext("Owned");
        final var context = createContext("Test");

        final var compromissedComponent = this.createAssembly(change);
        final var assemblyComponent = compromissedComponent.getAffectedElement();

        createContextChange(ownedContext, change);

        createPolicyEntity(context, this.assembly.getAssemblyContexts__ComposedStructure().get(0));

        createPolicyEntity(context, this.environment.getResourceContainer_ResourceEnvironment().get(0));

        createPolicyEntity(context, this.environment.getLinkingResources__ResourceEnvironment().get(0));

        runContextToAssemblyPropagation(change);

        isNoResourceChangeLinkingChange(change);

        assertEquals(1, change.getContextchange().size());
        assertTrue(EcoreUtil.equals(ownedContext, change.getContextchange().get(0).getAffectedElement()));
        assertEquals(1, change.getCompromisedassembly().size());
        assertTrue(EcoreUtil.equals(assemblyComponent, change.getCompromisedassembly().get(0).getAffectedElement()));
        assertFalse(change.isChanged());

    }

    @Disabled
    @Test
    void testContextToAssemblyPropagationDuplicate() {
        final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();

        final var context = createContext("Test");

        this.createAssembly(change, this.assembly.getAssemblyContexts__ComposedStructure().get(0));

        createContextChange(context, change);

        createPolicyEntity(context, this.assembly.getAssemblyContexts__ComposedStructure().get(0));

        createPolicyEntity(context, this.environment.getResourceContainer_ResourceEnvironment().get(0));

        createPolicyEntity(context, this.environment.getLinkingResources__ResourceEnvironment().get(0));

        runContextToAssemblyPropagation(change);

        isNoResourceChangeLinkingChange(change);

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

        final var context = createContext("Test");

        createPolicyEntity(context, this.assembly.getAssemblyContexts__ComposedStructure().get(0));

        createPolicyEntity(context, this.environment.getResourceContainer_ResourceEnvironment().get(0));

        createPolicyEntity(context, this.environment.getLinkingResources__ResourceEnvironment().get(0));

        runContextToAssemblyPropagation(change);

        isNoContextChangeNoResourceNoLinking(change);
        assertTrue(change.getCompromisedassembly().isEmpty());
        assertFalse(change.isChanged());

    }

    @Test
    void testContextToAssemblyPropagationNoContextNoAssemblyComponent() {
        final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();

        runContextToAssemblyPropagation(change);
        isNoContextChangeNoResourceNoLinking(change);

        assertTrue(change.getCompromisedassembly().isEmpty());
        assertFalse(change.isChanged());

    }

    @Test
    void testContextToAssemblyPropagationNoSpecificationNoContext() {
        final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();

        final var compromissedComponent = this.createAssembly(change);
        final var assemblyComponent = compromissedComponent.getAffectedElement();
        runContextToAssemblyPropagation(change);

        isNoContextChangeNoResourceNoLinking(change);

        assertEquals(1, change.getCompromisedassembly().size());
        assertTrue(EcoreUtil.equals(assemblyComponent, change.getCompromisedassembly().get(0).getAffectedElement()));
        assertFalse(change.isChanged());

    }

    @Disabled
    @Test
    void testContextToAssemblyPropagationProvided() {
        final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();

        final var context = createContext("Test");

        this.createAssembly(change);

        createContextChange(context, change);

        createPolicyEntity(context, this.assembly.getAssemblyContexts__ComposedStructure().get(0));
        createPolicyEntity(context, this.assembly.getAssemblyContexts__ComposedStructure().get(1));
        createPolicyEntity(context, this.assembly.getAssemblyContexts__ComposedStructure().get(2));

        createPolicyEntity(context, this.environment.getResourceContainer_ResourceEnvironment().get(0));

        createPolicyEntity(context, this.environment.getLinkingResources__ResourceEnvironment().get(0));

        runContextToAssemblyPropagation(change);

        isNoResourceChangeLinkingChange(change);

        assertEquals(1, change.getContextchange().size());
        assertTrue(EcoreUtil.equals(context, change.getContextchange().get(0).getAffectedElement()));
        assertEquals(2, change.getCompromisedassembly().size());
        assertTrue(change.getCompromisedassembly().stream().anyMatch(e -> EcoreUtil.equals(e.getAffectedElement(),
                this.assembly.getAssemblyContexts__ComposedStructure().get(0))));
        assertTrue(change.getCompromisedassembly().stream().anyMatch(e -> EcoreUtil.equals(e.getAffectedElement(),
                this.assembly.getAssemblyContexts__ComposedStructure().get(2))));
        assertTrue(change.isChanged());

    }

    @Disabled
    @Test
    void testContextToAssemblyPropagationRequired() {
        final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();

        final var context = createContext("Test");

        this.createAssembly(change, this.assembly.getAssemblyContexts__ComposedStructure().get(2));

        createContextChange(context, change);

        createPolicyEntity(context, this.assembly.getAssemblyContexts__ComposedStructure().get(0));
        createPolicyEntity(context, this.assembly.getAssemblyContexts__ComposedStructure().get(1));
        createPolicyEntity(context, this.assembly.getAssemblyContexts__ComposedStructure().get(2));

        createPolicyEntity(context, this.environment.getResourceContainer_ResourceEnvironment().get(0));

        createPolicyEntity(context, this.environment.getLinkingResources__ResourceEnvironment().get(0));

        runContextToAssemblyPropagation(change);

        isNoResourceChangeLinkingChange(change);

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

    @Disabled
    @Test
    void testContextToAssemblyPropagationRequiredNoSpecificationThirdComponent() {
        final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();

        final var context = createContext("Test");

        this.createAssembly(change, this.assembly.getAssemblyContexts__ComposedStructure().get(2));

        createContextChange(context, change);

        createPolicyEntity(context, this.assembly.getAssemblyContexts__ComposedStructure().get(0));
        createPolicyEntity(context, this.assembly.getAssemblyContexts__ComposedStructure().get(2));

        createPolicyEntity(context, this.environment.getResourceContainer_ResourceEnvironment().get(0));

        createPolicyEntity(context, this.environment.getLinkingResources__ResourceEnvironment().get(0));

        runContextToAssemblyPropagation(change);

        isNoResourceChangeLinkingChange(change);

        assertEquals(1, change.getContextchange().size());
        assertTrue(EcoreUtil.equals(context, change.getContextchange().get(0).getAffectedElement()));
        assertEquals(2, change.getCompromisedassembly().size());
        assertTrue(change.getCompromisedassembly().stream().anyMatch(e -> EcoreUtil.equals(e.getAffectedElement(),
                this.assembly.getAssemblyContexts__ComposedStructure().get(0))));
        assertTrue(change.getCompromisedassembly().stream().anyMatch(e -> EcoreUtil.equals(e.getAffectedElement(),
                this.assembly.getAssemblyContexts__ComposedStructure().get(2))));
        assertTrue(change.isChanged());

    }

    @Disabled
    @Test
    void testContextToAssemblyPropagationRequiredSpecificationThirdComponentWrongContext() {
        final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();

        final var context = createContext("Test");

        final var differentContext = createContext("different");

        this.createAssembly(change, this.assembly.getAssemblyContexts__ComposedStructure().get(2));

        createContextChange(context, change);

        createPolicyEntity(context, this.assembly.getAssemblyContexts__ComposedStructure().get(0));
        createPolicyEntity(differentContext, this.assembly.getAssemblyContexts__ComposedStructure().get(0));
        createPolicyEntity(context, this.assembly.getAssemblyContexts__ComposedStructure().get(2));

        createPolicyEntity(context, this.environment.getResourceContainer_ResourceEnvironment().get(0));

        createPolicyEntity(context, this.environment.getLinkingResources__ResourceEnvironment().get(0));

        runContextToAssemblyPropagation(change);

        isNoResourceChangeLinkingChange(change);

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

        final var ownedContext = createContext("Owned");
        final var context = createContext("Test");

        final var compromissedComponent = this.createAssembly(change);
        final var assemblyComponent = compromissedComponent.getAffectedElement();

        createContextChange(ownedContext, change);

        createPolicyEntity(context, this.assembly.getAssemblyContexts__ComposedStructure().get(0));
        createPolicyEntity(context, this.assembly.getAssemblyContexts__ComposedStructure().get(1));
        createPolicyEntity(context, this.assembly.getAssemblyContexts__ComposedStructure().get(2));

        createPolicyEntity(context, this.environment.getResourceContainer_ResourceEnvironment().get(0));

        createPolicyEntity(context, this.environment.getLinkingResources__ResourceEnvironment().get(0));

        runContextToAssemblyPropagation(change);

        isNoResourceChangeLinkingChange(change);

        assertEquals(1, change.getContextchange().size());
        assertTrue(EcoreUtil.equals(ownedContext, change.getContextchange().get(0).getAffectedElement()));
        assertEquals(1, change.getCompromisedassembly().size());
        assertTrue(EcoreUtil.equals(assemblyComponent, change.getCompromisedassembly().get(0).getAffectedElement()));
        assertFalse(change.isChanged());

    }
}
