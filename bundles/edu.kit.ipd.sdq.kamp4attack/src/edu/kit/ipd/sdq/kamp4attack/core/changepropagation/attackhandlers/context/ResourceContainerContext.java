package edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.context;

import java.util.List;
import java.util.Optional;

import org.eclipse.emf.ecore.EObject;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.data.DataHandlerAttacker;
import org.palladiosimulator.pcm.confidentiality.context.helper.PolicyHelper;
import org.palladiosimulator.pcm.resourceenvironment.ResourceContainer;

import edu.kit.ipd.sdq.kamp4attack.core.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.HelperCreationCompromisedElements;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.ResourceContainerHandler;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedResource;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;

public class ResourceContainerContext extends ResourceContainerHandler {

    public ResourceContainerContext(BlackboardWrapper modelStorage, DataHandlerAttacker dataHandler) {
        super(modelStorage, dataHandler);
    }

    @Override
    protected Optional<CompromisedResource> attackResourceContainer(ResourceContainer container,
            CredentialChange change, EObject source) {
        var credentials = this.getCredentials(change);
        var policies = PolicyHelper.getPolicy(this.getModelStorage().getSpecification(), container);

        if (policies.stream().anyMatch(policy -> policy.checkAccessRight(credentials))) {
            var compromised = HelperCreationCompromisedElements.createCompromisedResource(container, List.of(source, credentials));
            return Optional.of(compromised);
        }
        return Optional.empty();

    }

}
