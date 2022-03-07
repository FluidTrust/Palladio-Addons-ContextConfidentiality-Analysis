package edu.kit.ipd.sdq.attacksurface.tests.change.credentials;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.eclipse.emf.ecore.util.EcoreUtil;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import edu.kit.ipd.sdq.attacksurface.tests.change.AbstractChangeTests;
//TODO
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.AssemblyContextPropagationContext;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksFactory;

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
        final var contextChange = new AssemblyContextPropagationContext(wrapper, change);
        contextChange.calculateAssemblyContextToRemoteResourcePropagation();
    }

    //TODO tests from context changes to assemblies (incl. getting credentials with vulnerabilities)
}
