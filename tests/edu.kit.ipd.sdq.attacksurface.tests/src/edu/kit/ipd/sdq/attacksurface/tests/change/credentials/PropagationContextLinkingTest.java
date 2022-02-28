package edu.kit.ipd.sdq.attacksurface.tests.change.credentials;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.eclipse.emf.ecore.util.EcoreUtil;
import org.junit.jupiter.api.Test;
import org.palladiosimulator.pcm.confidentiality.context.system.UsageSpecification;

import edu.kit.ipd.sdq.attacksurface.tests.change.AbstractChangeTests;
//TODO
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.AssemblyContextPropagationContext;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.ResourceContainerPropagationContext;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksFactory;


class PropagationContextLinkingTest extends AbstractChangeTests {
  //TODO

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
        //        final var contextChange = new
        //        contextChange.calculateContextToLinkingPropagation(change);
    }

    private void runAssemblyToLinkingPropagation(final CredentialChange change) {
        generateXML();
        final var wrapper = getBlackboardWrapper();
        final var contextChange = new AssemblyContextPropagationContext(wrapper, change);
        contextChange.calculateAssemblyContextToLinkingResourcePropagation();
        //        final var contextChange = new
        //        contextChange.calculateContextToLinkingPropagation(change);
    }

    // TODO tests

}
