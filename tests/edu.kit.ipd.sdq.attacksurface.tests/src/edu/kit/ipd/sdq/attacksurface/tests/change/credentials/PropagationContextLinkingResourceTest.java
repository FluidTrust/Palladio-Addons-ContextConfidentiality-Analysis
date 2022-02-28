package edu.kit.ipd.sdq.attacksurface.tests.change.credentials;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.eclipse.emf.ecore.util.EcoreUtil;
import org.junit.jupiter.api.Test;
import org.palladiosimulator.pcm.confidentiality.context.system.UsageSpecification;

import edu.kit.ipd.sdq.attacksurface.tests.change.AbstractChangeTests;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.LinkingPropagationContext;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksFactory;

class PropagationContextLinkingResourceTest extends AbstractChangeTests {
    
    private void createPolicies(final UsageSpecification contextSet) {
        createPolicyEntity(contextSet, this.environment.getResourceContainer_ResourceEnvironment().get(0));
        createPolicyEntity(contextSet, this.environment.getResourceContainer_ResourceEnvironment().get(1));
        createPolicyEntity(contextSet, this.environment.getResourceContainer_ResourceEnvironment().get(2));

    }

    private void isNoAssemblyResourceChange(final CredentialChange change) {
        assertTrue(change.getCompromisedassembly().isEmpty());
        assertTrue(change.getCompromisedresource().isEmpty());
    }

    private void isNoContextChangeNoAssemblyNoResource(final CredentialChange change) {
        assertTrue(change.getContextchange().isEmpty());
        isNoAssemblyResourceChange(change);
    }

    private void runContextLinkingToResourcePropagation(final CredentialChange change) {
        generateXML();
        final var contextChange = new LinkingPropagationContext(getBlackboardWrapper(), change);
        contextChange.calculateLinkingResourceToResourcePropagation();
    }

    // TODO tests

}
