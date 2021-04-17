package edu.kit.ipd.sdq.kamp4attack.core.changepropagation;

import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.stream.Collectors;

import org.eclipse.emf.ecore.util.EcoreUtil;
import org.palladiosimulator.pcm.allocation.AllocationContext;
import org.palladiosimulator.pcm.confidentiality.attacker.helper.VulnerabilityHelper;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.AttackVector;
import org.palladiosimulator.pcm.confidentiality.context.helper.PolicyHelper;
import org.palladiosimulator.pcm.resourceenvironment.LinkingResource;
import org.palladiosimulator.pcm.resourceenvironment.ResourceContainer;

import edu.kit.ipd.sdq.kamp.architecture.ArchitectureModelLookup;
import edu.kit.ipd.sdq.kamp4attack.core.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedLinkingResource;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedResource;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksFactory;

public class ResourceChange extends Change<ResourceContainer> {

    public ResourceChange(BlackboardWrapper v) {
        super(v);
    }

    @Override
    protected Collection<ResourceContainer> loadInitialMarkedItems() {
        return ArchitectureModelLookup.lookUpMarkedObjectsOfAType(modelStorage, ResourceContainer.class);
    }

    public void calculateResourceToContextPropagation(CredentialChange changes) {
        var listInfectedContainer = getInfectedResourceContainers(changes);

        var streamAttributeProvider = this.modelStorage.getSpecification().getAttributeprovider().stream().filter(
                e -> listInfectedContainer.stream().anyMatch(f -> EcoreUtil.equals(e.getResourcecontainer(), f)));

        updateFromContextProviderStream(changes, streamAttributeProvider);

    }

    public void calculateResourceToAssemblyPropagation(CredentialChange changes) {
        var listInfectedContainer = getInfectedResourceContainers(changes);

        var streamTargetAllocations = this.modelStorage.getAllocation().getAllocationContexts_Allocation().stream()
                .filter(e -> listInfectedContainer.stream()
                        .anyMatch(f -> EcoreUtil.equals(f, e.getResourceContainer_AllocationContext())));

        var streamAssembly = streamTargetAllocations.map(AllocationContext::getAssemblyContext_AllocationContext);

        var streamChanges = streamAssembly.map(e -> {
            var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCompromisedAssembly();
            change.setToolderived(true);
            change.setAffectedElement(e);
            return change;
        });

        var listChanges = streamChanges
                .filter(e -> changes.getCompromisedassembly().stream()
                        .noneMatch(f -> EcoreUtil.equals(f.getAffectedElement(), e.getAffectedElement())))
                .collect(Collectors.toList());

        changes.getCompromisedassembly().addAll(listChanges);
        if (!listChanges.isEmpty())
            changes.setChanged(true);
    }

    public void calculateResourceToLinkingPropagation(CredentialChange changes) {
        var listInfectedContainer = getInfectedResourceContainers(changes);

        var compromisedLinkingResources = new HashSet<CompromisedLinkingResource>();
        var attacks = getAttacks();
        for (var resource : listInfectedContainer) {
            var listReachableLinkingResources = findReachableLinkingResources(changes, resource);

            var credentials = getCredentials(changes);
            
            for (var linkingResource : listReachableLinkingResources) {
                var vulnerabilityList = VulnerabilityHelper
                        .getVulnerabilities(this.modelStorage.getVulnerabilitySpecification(), linkingResource);
                var policies = PolicyHelper.getPolicy(this.modelStorage.getSpecification(), linkingResource);
                var vulnerability = VulnerabilityHelper.checkAttack(credentials, policies, vulnerabilityList, attacks,
                        AttackVector.ADJACENT_NETWORK);
                if (vulnerability != null && vulnerability.isTakeOver()) {
                    var compromisedLinkingResource = KAMP4attackModificationmarksFactory.eINSTANCE.createCompromisedLinkingResource();
                    compromisedLinkingResource.setAffectedElement(linkingResource);
                    compromisedLinkingResource.getCausingElements().addAll(List.of(resource, vulnerability));
                    compromisedLinkingResource.setToolderived(true);
                    compromisedLinkingResources.add(compromisedLinkingResource);
                }
            }
        }
        if(!compromisedLinkingResources.isEmpty()) {
            changes.setChanged(true);
            changes.getCompromisedlinkingresource().addAll(compromisedLinkingResources);
        }
    }

    private List<ResourceContainer> getInfectedResourceContainers(CredentialChange changes) {
        return changes.getCompromisedresource().stream().map(CompromisedResource::getAffectedElement)
                .collect(Collectors.toList());
    }

    private List<LinkingResource> findReachableLinkingResources(CredentialChange changes, ResourceContainer resource) {
        return this.modelStorage.getResourceEnvironment().getLinkingResources__ResourceEnvironment().stream() // filter
                                                                                                              // for
                                                                                                              // connected
                                                                                                              // LinkingResources
                .filter(targetResource -> targetResource.getConnectedResourceContainers_LinkingResource().stream()
                        .anyMatch(container -> EcoreUtil.equals(resource, container)))
                .filter(targetLinking -> changes.getCompromisedlinkingresource().stream() // remove
                                                                                          // compromised
                                                                                          // linking
                        .noneMatch(test -> EcoreUtil.equals(test.getAffectedElement(), targetLinking))).distinct() //remove duplicates
                .collect(Collectors.toList());
    }

}
