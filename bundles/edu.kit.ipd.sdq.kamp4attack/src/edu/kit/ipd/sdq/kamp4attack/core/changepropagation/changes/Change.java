package edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.eclipse.emf.ecore.util.EcoreUtil;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.Attacker;
import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.PCMAttributeProvider;
import org.palladiosimulator.pcm.resourceenvironment.LinkingResource;
import org.palladiosimulator.pcm.resourceenvironment.ResourceContainer;

import edu.kit.ipd.sdq.kamp4attack.core.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;

public abstract class Change<T> {

    protected Collection<T> initialMarkedItems;

    protected BlackboardWrapper modelStorage;

    protected CredentialChange changes;

    public Change(final BlackboardWrapper v, CredentialChange change) {
        this.modelStorage = v;
        this.initialMarkedItems = this.loadInitialMarkedItems();
        this.changes = change;

    }

    protected abstract Collection<T> loadInitialMarkedItems();

    protected void updateFromContextProviderStream(final CredentialChange changes,
            final Stream<? extends PCMAttributeProvider> streamAttributeProvider) {
        final var streamContextChange = streamAttributeProvider
                .map(e -> {
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
        final var resourceEnvironment = this.modelStorage.getResourceEnvironment();
        return resourceEnvironment.getLinkingResources__ResourceEnvironment().stream()
                .filter(e -> e.getConnectedResourceContainers_LinkingResource().stream()
                        .anyMatch(f -> EcoreUtil.equals(f, container)))
                .collect(Collectors.toList());
    }

    protected List<ResourceContainer> getConnectedResourceContainers(final ResourceContainer resource) {
        final var resources = this.getLinkingResource(resource).stream()
                .flatMap(e -> e.getConnectedResourceContainers_LinkingResource().stream()).distinct()
                .filter(e -> !EcoreUtil.equals(e, resource)).collect(Collectors.toList());
        return resources;
    }
}
