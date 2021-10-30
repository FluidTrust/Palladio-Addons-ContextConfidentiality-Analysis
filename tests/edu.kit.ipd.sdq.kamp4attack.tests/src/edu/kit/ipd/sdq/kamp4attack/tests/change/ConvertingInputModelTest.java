package edu.kit.ipd.sdq.kamp4attack.tests.change;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.eclipse.emf.ecore.util.EcoreUtil;
import org.junit.jupiter.api.Test;

import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;

class ConvertingInputModelTest extends AbstractChangeTests {

    @Test
    void testTransformationAssembly() {

        this.attacker.getAttackers().getAttacker().get(0).getCompromisedComponents()
        .add(this.assembly.getAssemblyContexts__ComposedStructure().get(0));

        runAnalysis();

        assertEquals(1, this.modification.getChangePropagationSteps().size());
        assertTrue(this.modification.getChangePropagationSteps().get(0) instanceof CredentialChange);
        final var change = (CredentialChange) this.modification.getChangePropagationSteps().get(0);

        assertTrue(change.getContextchange().isEmpty());
        assertTrue(change.getCompromisedresource().isEmpty());
        assertTrue(change.getCompromisedlinkingresource().isEmpty());
        assertEquals(1, change.getCompromisedassembly().size());
        assertTrue(EcoreUtil.equals(change.getCompromisedassembly().get(0).getAffectedElement(),
                this.assembly.getAssemblyContexts__ComposedStructure().get(0)));

    }

    @Test
    void testTransformationResource() {

        this.attacker.getAttackers().getAttacker().get(0).getCompromisedResources()
        .add(this.environment.getResourceContainer_ResourceEnvironment().get(0));
        this.allocation.getAllocationContexts_Allocation().clear();

        runAnalysis();

        assertEquals(1, this.modification.getChangePropagationSteps().size());
        assertTrue(this.modification.getChangePropagationSteps().get(0) instanceof CredentialChange);
        final var change = (CredentialChange) this.modification.getChangePropagationSteps().get(0);

        assertTrue(change.getContextchange().isEmpty());
        assertTrue(change.getCompromisedassembly().isEmpty());
        assertTrue(change.getCompromisedlinkingresource().isEmpty());
        assertEquals(1, change.getCompromisedresource().size());
        assertTrue(EcoreUtil.equals(change.getCompromisedresource().get(0).getAffectedElement(),
                this.environment.getResourceContainer_ResourceEnvironment().get(0)));

    }

    @Test
    void testTransformationLinking() {

        this.attacker.getAttackers().getAttacker().get(0).getCompromisedLinkingResources()
        .add(this.environment.getLinkingResources__ResourceEnvironment().get(0));

        runAnalysis();
        assertEquals(1, this.modification.getChangePropagationSteps().size());
        assertTrue(this.modification.getChangePropagationSteps().get(0) instanceof CredentialChange);
        final var change = (CredentialChange) this.modification.getChangePropagationSteps().get(0);

        assertTrue(change.getContextchange().isEmpty());
        assertTrue(change.getCompromisedassembly().isEmpty());
        assertTrue(change.getCompromisedresource().isEmpty());
        assertEquals(1, change.getCompromisedlinkingresource().size());
        assertTrue(EcoreUtil.equals(change.getCompromisedlinkingresource().get(0).getAffectedElement(),
                this.environment.getLinkingResources__ResourceEnvironment().get(0)));

    }

    @Test
    void testTransformationContext() {

        final var context = createContext("Test");
        this.attacker.getAttackers().getAttacker().get(0).getCredentials().add(context);

        runAnalysis();

        assertEquals(1, this.modification.getChangePropagationSteps().size());
        assertTrue(this.modification.getChangePropagationSteps().get(0) instanceof CredentialChange);
        final var change = (CredentialChange) this.modification.getChangePropagationSteps().get(0);

        assertTrue(change.getCompromisedlinkingresource().isEmpty());
        assertTrue(change.getCompromisedassembly().isEmpty());
        assertTrue(change.getCompromisedresource().isEmpty());
        assertEquals(1, change.getContextchange().size());
        assertTrue(EcoreUtil.equals(change.getContextchange().get(0).getAffectedElement(), context));

    }

    @Test
    void testAllTransfomations() {
        this.attacker.getAttackers().getAttacker().get(0).getCompromisedComponents()
        .add(this.assembly.getAssemblyContexts__ComposedStructure().get(0));
        final var context = createContext("Test");
        this.attacker.getAttackers().getAttacker().get(0).getCredentials().add(context);
        this.attacker.getAttackers().getAttacker().get(0).getCompromisedResources()
        .add(this.environment.getResourceContainer_ResourceEnvironment().get(0));
        this.attacker.getAttackers().getAttacker().get(0).getCompromisedLinkingResources()
        .add(this.environment.getLinkingResources__ResourceEnvironment().get(0));

        runAnalysis();

        assertTrue(this.modification.getChangePropagationSteps().get(0) instanceof CredentialChange);
        final var change = (CredentialChange) this.modification.getChangePropagationSteps().get(0);

        assertEquals(1, change.getContextchange().size());
        assertTrue(EcoreUtil.equals(change.getContextchange().get(0).getAffectedElement(), context));
        assertEquals(1, change.getCompromisedlinkingresource().size());
        assertTrue(EcoreUtil.equals(change.getCompromisedlinkingresource().get(0).getAffectedElement(),
                this.environment.getLinkingResources__ResourceEnvironment().get(0)));
        assertEquals(1, change.getCompromisedresource().size());
        assertTrue(EcoreUtil.equals(change.getCompromisedresource().get(0).getAffectedElement(),
                this.environment.getResourceContainer_ResourceEnvironment().get(0)));
        assertEquals(1, change.getCompromisedassembly().size());
        assertTrue(EcoreUtil.equals(change.getCompromisedassembly().get(0).getAffectedElement(),
                this.assembly.getAssemblyContexts__ComposedStructure().get(0)));

    }


}
