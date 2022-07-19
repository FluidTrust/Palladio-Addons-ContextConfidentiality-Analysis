package edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes;

import java.util.List;
import java.util.stream.Stream;

import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.PCMConnectionHelper;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.Attacker;
import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.PCMAttributeProvider;
import org.palladiosimulator.pcm.resourceenvironment.LinkingResource;
import org.palladiosimulator.pcm.resourceenvironment.ResourceContainer;

import edu.kit.ipd.sdq.kamp4attack.core.api.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;

public abstract class Change<T> {

    protected BlackboardWrapper modelStorage;

    protected CredentialChange changes;

    public Change(final BlackboardWrapper v, CredentialChange change) {
        this.modelStorage = v;
        this.changes = change;

    }

    protected void updateFromContextProviderStream(final CredentialChange changes,
            final Stream<? extends PCMAttributeProvider> streamAttributeProvider) {
        final var streamContextChange = streamAttributeProvider.map(e -> {
            if (e.getAssemblycontext() != null) {
                return HelperUpdateCredentialChange.createContextChange(e.getAttribute(),
                        List.of(e.getAssemblycontext()));
            }
            if (e.getLinkingresource() != null) {
                return HelperUpdateCredentialChange.createContextChange(e.getAttribute(),
                        List.of(e.getLinkingresource()));
            }
            if (e.getResourcecontainer() != null) {
                return HelperUpdateCredentialChange.createContextChange(e.getAttribute(),
                        List.of(e.getResourcecontainer()));
            }
            return HelperUpdateCredentialChange.createContextChange(e.getAttribute(), null);
        });

        HelperUpdateCredentialChange.updateCredentials(changes, streamContextChange);
    }

    protected Attacker getAttacker() {
        if (this.modelStorage.getModificationMarkRepository().getSeedModifications().getAttackcomponent().isEmpty()) {
            throw new IllegalStateException("No attacker selected");
        }
        if (this.modelStorage.getModificationMarkRepository().getSeedModifications().getAttackcomponent().size() > 2) {
            throw new IllegalStateException("More than one attacker");
        }
        return this.modelStorage.getModificationMarkRepository().getSeedModifications().getAttackcomponent().get(0)
                .getAffectedElement();
    }

    protected List<LinkingResource> getLinkingResource(final ResourceContainer container) {
        return PCMConnectionHelper.getLinkingResource(container, this.modelStorage.getResourceEnvironment());
    }

    protected List<ResourceContainer> getConnectedResourceContainers(final ResourceContainer resource) {
        return PCMConnectionHelper.getConnectedResourceContainers(resource, this.modelStorage.getResourceEnvironment());
    }
}
