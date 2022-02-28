package edu.kit.ipd.sdq.attacksurface.tests.change.credentials;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.jupiter.api.Assertions.assertEquals;

import org.eclipse.emf.ecore.util.EcoreUtil;
import org.junit.jupiter.api.Test;
import org.palladiosimulator.pcm.resourceenvironment.ResourceContainer;

import edu.kit.ipd.sdq.attacksurface.tests.change.AbstractChangeTests;
//TODO
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.ResourceContainerPropagationContext;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksFactory;

class PropagationResourceTest extends AbstractChangeTests {
  //TODO

    private void isNoAssemblyResourceLinkingPropagation(final CredentialChange change,
            final ResourceContainer resource) {
        isNoResourceLinkingPropagation(change, resource);
        assertTrue(change.getCompromisedassembly().isEmpty());

    }

    private void isNoResourceLinkingPropagation(final CredentialChange change, final ResourceContainer resource) {
        assertTrue(change.getCompromisedlinkingresource().isEmpty());
        assertEquals(1, change.getCompromisedresource().size());
        assertTrue(EcoreUtil.equals(change.getCompromisedresource().get(0).getAffectedElement(), resource));
    }

    private void runResourceAssemblyPropagation(final CredentialChange change) {
        generateXML();
        final var wrapper = getBlackboardWrapper();
        final var resourceChange = new ResourceContainerPropagationContext(wrapper, change);
        resourceChange.calculateResourceContainerToLocalAssemblyContextPropagation();
    }

    private void runResourceContextPropagation(final CredentialChange change) {
        generateXML();
        final var wrapper = getBlackboardWrapper();
        final var resourceChange = new ResourceContainerPropagationContext(wrapper, change);
        resourceChange.calculateResourceContainerToContextPropagation();
    }

    // TODO tests

}
