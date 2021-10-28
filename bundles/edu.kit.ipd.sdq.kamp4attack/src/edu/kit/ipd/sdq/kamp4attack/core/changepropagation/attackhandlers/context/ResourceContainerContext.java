package edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.context;

import java.util.List;
import java.util.Optional;

import org.eclipse.emf.ecore.EObject;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.HelperCreationCompromisedElements;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.data.DataHandlerAttacker;
import org.palladiosimulator.pcm.confidentiality.context.system.UsageSpecification;
import org.palladiosimulator.pcm.confidentiality.context.xacml.pdp.result.DecisionType;
import org.palladiosimulator.pcm.resourceenvironment.ResourceContainer;

import com.google.common.base.Objects;

import edu.kit.ipd.sdq.kamp4attack.core.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.ResourceContainerHandler;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedResource;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;

public class ResourceContainerContext extends ResourceContainerHandler {

    public ResourceContainerContext(final BlackboardWrapper modelStorage, final DataHandlerAttacker dataHandler) {
        super(modelStorage, dataHandler);
    }

    @Override
    protected Optional<CompromisedResource> attackResourceContainer(final ResourceContainer container,
            final CredentialChange change, final EObject source) {
        final List<? extends UsageSpecification> credentials = this.getCredentials(change);

        final var result = this.queryAccessForEntity(container, credentials);

        if (result.isPresent() && Objects.equal(result.get().getDecision(), DecisionType.PERMIT)) {
            final var sourceList = this.createSource(source, credentials);
            final var compromised = HelperCreationCompromisedElements.createCompromisedResource(container, sourceList);
            return Optional.of(compromised);
        }
        return Optional.empty();

    }

}
