package edu.kit.ipd.sdq.kamp4attack.tests.change;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.eclipse.emf.ecore.util.EcoreUtil;
import org.junit.jupiter.api.Test;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.PcmIntegrationFactory;

import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;

class ConvertingInputModelTest extends AbstractChangeTests {

    @Test
    void testTransformationAssembly() {
        var start = PcmIntegrationFactory.eINSTANCE.createSystemComponent();
        start.getAssemblycontext().add(this.assembly.getAssemblyContexts__ComposedStructure().get(0));
        this.attacker.getAttackers().getAttacker().get(0).getCompromisedComponents().add(start);

        runAnalysis();

        assertEquals(1, this.modification.getChangePropagationSteps().size());
        assertTrue(this.modification.getChangePropagationSteps().get(0) instanceof CredentialChange);
        final var change = this.modification.getChangePropagationSteps().get(0);

        assertTrue(change.getContextchange().isEmpty());
        assertTrue(change.getCompromisedresource().isEmpty());
        assertTrue(change.getCompromisedlinkingresource().isEmpty());
        assertEquals(1, change.getCompromisedassembly().size());
        assertTrue(EcoreUtil.equals(change.getCompromisedassembly().get(0).getAffectedElement(),
                this.assembly.getAssemblyContexts__ComposedStructure().get(0)));

    }

    @Test
    void testTransformationResource() {

        var resource = PcmIntegrationFactory.eINSTANCE.createResourceEnvironmentElement();
        resource.setResourcecontainer(this.environment.getResourceContainer_ResourceEnvironment().get(0));

        this.attacker.getAttackers().getAttacker().get(0).getCompromisedResourceElements().add(resource);
        this.allocation.getAllocationContexts_Allocation().clear();

        runAnalysis();

        assertEquals(1, this.modification.getChangePropagationSteps().size());
        assertTrue(this.modification.getChangePropagationSteps().get(0) instanceof CredentialChange);
        final var change = this.modification.getChangePropagationSteps().get(0);

        assertTrue(change.getContextchange().isEmpty());
        assertTrue(change.getCompromisedassembly().isEmpty());
        assertTrue(change.getCompromisedlinkingresource().isEmpty());
        assertEquals(1, change.getCompromisedresource().size());
        assertTrue(EcoreUtil.equals(change.getCompromisedresource().get(0).getAffectedElement(),
                this.environment.getResourceContainer_ResourceEnvironment().get(0)));

    }

    @Test
    void testTransformationLinking() {
        var resource = PcmIntegrationFactory.eINSTANCE.createResourceEnvironmentElement();
        resource.setLinkingresource(this.environment.getLinkingResources__ResourceEnvironment().get(0));

        this.attacker.getAttackers().getAttacker().get(0).getCompromisedResourceElements().add(resource);

        runAnalysis();
        assertEquals(1, this.modification.getChangePropagationSteps().size());
        assertTrue(this.modification.getChangePropagationSteps().get(0) instanceof CredentialChange);
        final var change = this.modification.getChangePropagationSteps().get(0);

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
        final var change = this.modification.getChangePropagationSteps().get(0);

        assertTrue(change.getCompromisedlinkingresource().isEmpty());
        assertTrue(change.getCompromisedassembly().isEmpty());
        assertTrue(change.getCompromisedresource().isEmpty());
        assertEquals(1, change.getContextchange().size());
        assertTrue(EcoreUtil.equals(change.getContextchange().get(0).getAffectedElement(), context));

    }

    @Test
    void testAllTransfomations() {
        var start = PcmIntegrationFactory.eINSTANCE.createSystemComponent();
        start.getAssemblycontext().add(this.assembly.getAssemblyContexts__ComposedStructure().get(0));

        var resource = PcmIntegrationFactory.eINSTANCE.createResourceEnvironmentElement();
        resource.setResourcecontainer(this.environment.getResourceContainer_ResourceEnvironment().get(0));

        var linking = PcmIntegrationFactory.eINSTANCE.createResourceEnvironmentElement();
        linking.setLinkingresource(this.environment.getLinkingResources__ResourceEnvironment().get(0));

        this.attacker.getAttackers().getAttacker().get(0).getCompromisedComponents().add(start);
        final var context = createContext("Test");
        this.attacker.getAttackers().getAttacker().get(0).getCredentials().add(context);
        this.attacker.getAttackers().getAttacker().get(0).getCompromisedResourceElements().add(resource);
        this.attacker.getAttackers().getAttacker().get(0).getCompromisedResourceElements().add(linking);

        runAnalysis();

        assertTrue(this.modification.getChangePropagationSteps().get(0) instanceof CredentialChange);
        final var change = this.modification.getChangePropagationSteps().get(0);

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
