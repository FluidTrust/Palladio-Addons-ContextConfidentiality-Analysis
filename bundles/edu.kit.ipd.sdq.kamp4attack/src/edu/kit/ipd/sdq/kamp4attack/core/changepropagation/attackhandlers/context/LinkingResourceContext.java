package edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.context;

import java.util.Optional;

import org.eclipse.emf.ecore.EObject;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.data.DataHandlerAttacker;
import org.palladiosimulator.pcm.confidentiality.context.helper.PolicyHelper;
import org.palladiosimulator.pcm.resourceenvironment.LinkingResource;

import edu.kit.ipd.sdq.kamp4attack.core.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.HelperCreationCompromisedElements;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.LinkingResourceHandler;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedLinkingResource;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;

public class LinkingResourceContext extends LinkingResourceHandler {

    public LinkingResourceContext(final BlackboardWrapper modelStorage, final DataHandlerAttacker dataHandler) {
        super(modelStorage, dataHandler);
    }

    @Override
    protected Optional<CompromisedLinkingResource> attackLinkingResource(final LinkingResource linking,
            final CredentialChange change, final EObject source) {
        final var credentials = this.getCredentials(change);
        final var policies = PolicyHelper.getPolicy(this.getModelStorage().getSpecification(), linking);

        if (policies.stream().anyMatch(policy -> policy.checkAccessRight(credentials))) {
            final var sourceList = this.createSource(source, credentials);
            final var compromised = HelperCreationCompromisedElements.createCompromisedLinking(linking, sourceList);
            return Optional.of(compromised);
        }
        return Optional.empty();
    }

}
