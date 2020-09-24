package edu.kit.ipd.sdq.kamp4attack.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.eclipse.emf.ecore.util.EcoreUtil;
import org.junit.jupiter.api.Test;
import org.palladiosimulator.pcm.confidentiality.context.set.ContextSet;

import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.ContextChanges;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksFactory;

public class PropagationContextLinkingTest extends AbstractChangeTests {

    @Test
    void testContextToLinkingPropagationNoContextNoStartResource() {
        final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();

        var context = createContext("Test");
        var contextSet = createContextSet(context);
        createPolicyLinking(contextSet, this.environment.getLinkingResources__ResourceEnvironment().get(0));

        runContextToLinkingPropagation(change);

        isNoContextChangeNoAssemblyNoLinking(change);
        assertTrue(change.getCompromisedresource().isEmpty());
        assertFalse(change.isChanged());
    }

    @Test
    void testContextToLinkingPropagationNoContext() {
        final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();

        var context = createContext("Test");
        var contextSet = createContextSet(context);

        var resourceChange = this.createResourceChange(change);
        var resource = resourceChange.getAffectedElement();

        createPolicyLinking(contextSet, this.environment.getLinkingResources__ResourceEnvironment().get(0));

        runContextToLinkingPropagation(change);

        isNoContextChangeNoAssemblyNoLinking(change);
        assertEquals(1, change.getCompromisedresource().size());
        assertTrue(EcoreUtil.equals(change.getCompromisedresource().get(0).getAffectedElement(), resource));
        assertFalse(change.isChanged());
    }

    @Test
    void testContextToLinkingPropagationWrongContext() {
        final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();

        var ownedContext = createContext("Owned");
        createContextSet(ownedContext);

        var context = createContext("Test");
        var contextSet = createContextSet(context);

        var resourceChange = this.createResourceChange(change);
        var resource = resourceChange.getAffectedElement();

        this.createContextChange(ownedContext, change);

        createPolicyLinking(contextSet, this.environment.getLinkingResources__ResourceEnvironment().get(0));

        runContextToLinkingPropagation(change);

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

        var context = createContext("Test");
        var contextSet = createContextSet(context);

        var resourceChange = this.createResourceChange(change);
        var resource = resourceChange.getAffectedElement();

        this.createContextChange(context, change);

        createPolicyLinking(contextSet, this.environment.getLinkingResources__ResourceEnvironment().get(1));

        runContextToLinkingPropagation(change);

        isNoAssemblyChangeLinkingChange(change);
        assertEquals(1, change.getContextchange().size());
        assertTrue(EcoreUtil.equals(change.getContextchange().get(0).getAffectedElement(), context));
        assertEquals(1, change.getCompromisedresource().size());
        assertTrue(EcoreUtil.equals(change.getCompromisedresource().get(0).getAffectedElement(), resource));
        assertFalse(change.isChanged());
    }

    @Test
    void testContextToLinkingPropagationResourceStartpoint() {
        final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();

        var context = createContext("Test");
        var contextSet = createContextSet(context);

        var resourceChange = this.createResourceChange(change);
        var resource = resourceChange.getAffectedElement();

        this.createContextChange(context, change);

        createPolicies(contextSet);

        runContextToLinkingPropagation(change);

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

        var context = createContext("Test");
        var contextSet = createContextSet(context);

        var resourceChange = this.createResourceChange(change);
        var resource = resourceChange.getAffectedElement();

        this.createContextChange(context, change);
        this.createLinkingChange(change);

        createPolicies(contextSet);

        runContextToLinkingPropagation(change);

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
    void testContextToLinkingAssemblyStartpoint() {
        final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();

        var context = createContext("Test");
        var contextSet = createContextSet(context);

        var assemblyChange = this.createAssembly(change);
        var assemblyComponent = assemblyChange.getAffectedElement();

        this.createContextChange(context, change);

        createPolicies(contextSet);

        runContextToLinkingPropagation(change);

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
    
    private void createPolicies(ContextSet contextSet) {
        createPolicyLinking(contextSet, this.environment.getLinkingResources__ResourceEnvironment().get(0));
        createPolicyAssembly(contextSet, this.assembly.getAssemblyContexts__ComposedStructure().get(0));
        createPolicyAssembly(contextSet, this.assembly.getAssemblyContexts__ComposedStructure().get(1));
        createPolicyAssembly(contextSet, this.assembly.getAssemblyContexts__ComposedStructure().get(2));
        createPolicyResource(contextSet, this.environment.getResourceContainer_ResourceEnvironment().get(0));
        createPolicyResource(contextSet, this.environment.getResourceContainer_ResourceEnvironment().get(1));
        createPolicyResource(contextSet, this.environment.getResourceContainer_ResourceEnvironment().get(2));
    }

    private void isNoContextChangeNoAssemblyNoLinking(final CredentialChange change) {
        assertTrue(change.getContextchange().isEmpty());
        isNoAssemblyChangeLinkingChange(change);
    }

    private void isNoAssemblyChangeLinkingChange(final CredentialChange change) {
        assertTrue(change.getCompromisedassembly().isEmpty());
        assertTrue(change.getCompromisedlinkingresource().isEmpty());
    }

    private void runContextToLinkingPropagation(CredentialChange change) {
        final var wrapper = this.getBlackboardWrapper();
        final var contextChange = new ContextChanges(wrapper);
        contextChange.calculateContextToLinkingPropagation(change);
    }

}
