package edu.kit.ipd.sdq.attacksurface.tests.change.credentials;

import static org.junit.Assert.assertFalse;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.eclipse.emf.ecore.util.EcoreUtil;
import org.junit.jupiter.api.Test;

import edu.kit.ipd.sdq.attacksurface.tests.change.AbstractChangeTests;
//TODO
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.ResourceContainerPropagationContext;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksFactory;

class PropagationContextResourceTest extends AbstractChangeTests {

  //TODO
    
    private void isNoAssemblyChangeLinkingChange(final CredentialChange change) {
        assertTrue(change.getCompromisedassembly().isEmpty());
        assertTrue(change.getCompromisedlinkingresource().isEmpty());
    }

    private void isNoContextChangeNoAssemblyNoLinking(final CredentialChange change) {
        assertTrue(change.getContextchange().isEmpty());
        isNoAssemblyChangeLinkingChange(change);
    }

    private void runContextToResourcePropagation(final CredentialChange change) {
        generateXML();
        final var wrapper = getBlackboardWrapper();
        //        final var resourceChange = new ContextChanges(wrapper);
        //        resourceChange.calculateContextToResourcePropagation(change);
        final var resourceChange = new ResourceContainerPropagationContext(wrapper, change);
        resourceChange.calculateResourceContainerToResourcePropagation();

    }

    // TODO tests

}
