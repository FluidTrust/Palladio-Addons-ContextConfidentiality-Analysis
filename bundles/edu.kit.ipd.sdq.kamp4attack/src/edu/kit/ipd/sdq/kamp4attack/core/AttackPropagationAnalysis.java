package edu.kit.ipd.sdq.kamp4attack.core;

import java.util.ArrayList;
import java.util.Optional;

import org.eclipse.emf.ecore.EObject;
import org.osgi.service.component.annotations.Component;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.changeStorages.AssemblyContextChangeAssemblyContextsStorage;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.changeStorages.AssemblyContextChangeIsGlobalStorage;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.changeStorages.AssemblyContextChangeResourceContainerStorage;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.changeStorages.AssemblyContextChangeTargetedConnectorsStorage;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.changeStorages.ChangeLinkingResourcesStorage;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.changeStorages.ResourceContainerChangeAssemblyContextsStorage;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.data.DataHandlerAttacker;
import org.palladiosimulator.pcm.confidentiality.attacker.helper.VulnerabilityHelper;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.ResourceEnvironmentElement;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.SystemComponent;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;

import edu.kit.ipd.sdq.kamp4attack.core.api.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.core.api.IAttackPropagationAnalysis;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.AssemblyContextHandler;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.AssemblyContextPropagationContext;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.AssemblyContextPropagationVulnerability;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.LinkingPropagationContext;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.LinkingPropagationVulnerability;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.ResourceContainerPropagationContext;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.ResourceContainerPropagationVulnerability;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.propagationsteps.AssemblyContextPropagationWithContext;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.propagationsteps.LinkingPropagationWithContext;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.propagationsteps.ResourceContainerPropagationWithContext;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedAssembly;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksFactory;

/**
 * Entry point for attack propagation
 *
 * @author majuwa
 *
 */

@Component(service = IAttackPropagationAnalysis.class)
public class AttackPropagationAnalysis implements IAttackPropagationAnalysis {

    private CredentialChange changePropagationDueToCredential;

    @Override
    public void runChangePropagationAnalysis(final BlackboardWrapper board) {

        // Setup
        this.changePropagationDueToCredential = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();
        CachePDP.instance()
            .clearCache();
        CacheCompromised.instance()
            .reset();
        CacheVulnerability.instance()
            .reset();
        CacheCompromised.instance()
            .register(this.changePropagationDueToCredential);

        this.resetHashMaps();
        // prepare

        this.createInitialStructure(board);
        VulnerabilityHelper.initializeVulnerabilityStorage(board.getVulnerabilitySpecification());

        // Calculate
        do {
            this.changePropagationDueToCredential.setChanged(false);
            this.calculateAndMarkLinkingPropagation(board);
            this.calculateAndMarkResourcePropagation(board);
            this.calculateAndMarkAssemblyPropagation(board);

        } while (this.changePropagationDueToCredential.isChanged());

        // Clear caches
        CachePDP.instance()
            .clearCache();
        CacheCompromised.instance()
            .reset();
        CacheVulnerability.instance()
            .reset();

        VulnerabilityHelper.resetMap();
        this.resetHashMaps();
    }

    private void resetHashMaps() {
        ChangeLinkingResourcesStorage.getInstance()
            .reset();
        AssemblyContextChangeIsGlobalStorage.getInstance()
            .reset();
        AssemblyContextChangeTargetedConnectorsStorage.getInstance()
            .reset();
        AssemblyContextChangeResourceContainerStorage.getInstance()
            .reset();
        AssemblyContextChangeAssemblyContextsStorage.getInstance()
            .reset();
        ResourceContainerChangeAssemblyContextsStorage.getInstance()
            .reset();
    }

    private void calculateAndMarkAssemblyPropagation(final BlackboardWrapper board) {
        final var list = new ArrayList<AssemblyContextPropagationWithContext>();
        list.add(new AssemblyContextPropagationContext(board, this.changePropagationDueToCredential));
        list.add(new AssemblyContextPropagationVulnerability(board, this.changePropagationDueToCredential));
        for (final var analysis : list) {
            analysis.calculateAssemblyContextToContextPropagation();
            analysis.calculateAssemblyContextToAssemblyContextPropagation();
            analysis.calculateAssemblyContextToGlobalAssemblyContextPropagation();
            analysis.calculateAssemblyContextToLinkingResourcePropagation();
            analysis.calculateAssemblyContextToLocalResourcePropagation();
            analysis.calculateAssemblyContextToRemoteResourcePropagation();
        }
    }

    private void calculateAndMarkResourcePropagation(final BlackboardWrapper board) {
        final var list = new ArrayList<ResourceContainerPropagationWithContext>();
        list.add(new ResourceContainerPropagationContext(board, this.changePropagationDueToCredential));
        list.add(new ResourceContainerPropagationVulnerability(board, this.changePropagationDueToCredential));
        for (final var analysis : list) {
            analysis.calculateResourceContainerToContextPropagation();
            analysis.calculateResourceContainerToLinkingResourcePropagation();
            analysis.calculateResourceContainerToLocalAssemblyContextPropagation();
            analysis.calculateResourceContainerToRemoteAssemblyContextPropagation();
            analysis.calculateResourceContainerToResourcePropagation();
        }
    }

    private void calculateAndMarkLinkingPropagation(final BlackboardWrapper board) {
        final var list = new ArrayList<LinkingPropagationWithContext>();
        list.add(new LinkingPropagationContext(board, this.changePropagationDueToCredential));
        list.add(new LinkingPropagationVulnerability(board, this.changePropagationDueToCredential));
        for (final var analysis : list) {
            analysis.calculateLinkingResourceToContextPropagation();
            analysis.calculateLinkingResourceToAssemblyContextPropagation();
            analysis.calculateLinkingResourceToResourcePropagation();
        }
    }

    /**
     * Creates the initial propagation steps from the seed modification
     *
     * @param board
     */
    private void createInitialStructure(final BlackboardWrapper board) {
        final var repository = board.getModificationMarkRepository();
        final var seedModification = repository.getSeedModifications();
        final var attackers = seedModification.getAttackcomponent();
        if (attackers == null) {
            throw new IllegalStateException("No seed modification found");
        }

        repository.getChangePropagationSteps()
            .clear();

        for (final var attacker : attackers) {
            final var localAttacker = attacker.getAffectedElement();

            final var listCredentialChanges = localAttacker.getCredentials()
                .stream()
                .map(context -> {
                    final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createContextChange();
                    change.setAffectedElement(context);
                    return change;
                })
                .toList();

            this.changePropagationDueToCredential.getContextchange()
                .addAll(listCredentialChanges);

            // convert affectedResources to changes
            final var affectedRessourcesList = localAttacker.getCompromisedResourceElements()
                .stream()
                .filter(e -> e.getResourcecontainer() != null)
                .map(ResourceEnvironmentElement::getResourcecontainer)
                .map(resource -> {
                    final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCompromisedResource();
                    change.setAffectedElement(resource);
                    return change;
                })
                .toList();
            this.changePropagationDueToCredential.getCompromisedresource()
                .addAll(affectedRessourcesList);

            // convert affectedAssemblyContexts to changes
            final var assemblyHandler = new AssemblyContextHandler(board,
                    new DataHandlerAttacker(this.changePropagationDueToCredential)) {
                @Override
                protected Optional<CompromisedAssembly> attackComponent(final AssemblyContext component,
                        final CredentialChange change, final EObject source) {
                    final var compromisedComponent = KAMP4attackModificationmarksFactory.eINSTANCE
                        .createCompromisedAssembly();
                    compromisedComponent.setAffectedElement(component);
                    return Optional.of(compromisedComponent);
                }
            };

            assemblyHandler.attackAssemblyContext(localAttacker.getCompromisedComponents()
                .stream()
                .map(SystemComponent::getAssemblycontext)
                .map(e -> e.get(0))
                .toList(), this.changePropagationDueToCredential, null);

            // convert affectedLinkingResources to changes
            final var affectedLinkingList = localAttacker.getCompromisedResourceElements()
                .stream()
                .filter(e -> e.getLinkingresource() != null)
                .map(ResourceEnvironmentElement::getLinkingresource)
                .map(linkingResource -> {
                    final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCompromisedLinkingResource();
                    change.setAffectedElement(linkingResource);
                    return change;
                })
                .toList();
            this.changePropagationDueToCredential.getCompromisedlinkingresource()
                .addAll(affectedLinkingList);

        }
        board.getModificationMarkRepository()
            .getChangePropagationSteps()
            .add(this.changePropagationDueToCredential);
    }

}
