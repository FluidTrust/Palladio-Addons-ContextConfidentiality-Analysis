package edu.kit.ipd.sdq.kamp4attack.core.changepropagation;

import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.eclipse.emf.common.util.EList;
import org.eclipse.emf.ecore.util.EcoreUtil;
import org.palladiosimulator.pcm.allocation.Allocation;
import org.palladiosimulator.pcm.allocation.AllocationContext;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.data.CollectionHelper;
import org.palladiosimulator.pcm.confidentiality.attacker.helper.VulnerabilityHelper;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.AttackVector;
import org.palladiosimulator.pcm.confidentiality.context.helper.PolicyHelper;
import org.palladiosimulator.pcm.confidentiality.context.set.ContextSet;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;
import org.palladiosimulator.pcm.resourceenvironment.LinkingResource;
import org.palladiosimulator.pcm.resourceenvironment.ResourceContainer;

import edu.kit.ipd.sdq.kamp.architecture.ArchitectureModelLookup;
import edu.kit.ipd.sdq.kamp4attack.core.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedAssembly;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedLinkingResource;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedResource;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksFactory;

public class LinkingChange extends Change<LinkingResource> {

    public LinkingChange(BlackboardWrapper v) {
        super(v);
    }

    @Override
    protected Collection<LinkingResource> loadInitialMarkedItems() {
        return ArchitectureModelLookup.lookUpMarkedObjectsOfAType(modelStorage, LinkingResource.class);
    }

    public void calculateLinkingResourceToContextPropagation(CredentialChange changes) {
        var listCompromisedLinkingResources = changes.getCompromisedlinkingresource().stream()
                .map(CompromisedLinkingResource::getAffectedElement).collect(Collectors.toList());

        var streamAttributeProvider = this.modelStorage.getSpecification().getAttributeprovider().stream()
                .filter(e -> listCompromisedLinkingResources.stream()
                        .anyMatch(f -> EcoreUtil.equals(e.getLinkingresource(), f)));

        updateFromContextProviderStream(changes, streamAttributeProvider);

    }

    public void calculateLinkingResourceToResourcePropagation(CredentialChange changes) {
        var credentials = this.getCredentials(changes);
        var compromidesLinkingResources = this.getCompromisedLinkingResources(changes);
        
        
        var compromisedResources = propagateByContextToResource(compromidesLinkingResources, credentials);
        var attackedResources = propagateByAttackToResource(compromidesLinkingResources,credentials);
        
        compromisedResources = (Set<CompromisedResource>) CollectionHelper.removeAlreadyAffectedElements(compromisedResources, attackedResources);
        
        if(!compromisedResources.isEmpty()) {
            changes.setChanged(true);
            changes.getCompromisedresource().addAll(compromisedResources);
        }
        
    }

    private Set<CompromisedAssembly> propagateByContextToAssembly(List<LinkingResource> compromisedLinkingResources,
            ContextSet credentials) {
        var compromisedAssemblies = new HashSet<CompromisedAssembly>();
        for (var linking : compromisedLinkingResources) {
            var reachableResources = linking.getConnectedResourceContainers_LinkingResource();
            var reachableAssemblies = CollectionHelper.getAssemblyContext(reachableResources, this.modelStorage.getAllocation());
            var accessibleAssemblies = reachableAssemblies.stream().filter(e -> {
                var policies = PolicyHelper.getPolicy(this.modelStorage.getSpecification(), e);
                return policies.stream().anyMatch(policy -> policy.checkAccessRight(credentials));
            }).map(e -> {
                var compromisedAssembly = KAMP4attackModificationmarksFactory.eINSTANCE.createCompromisedAssembly();
                compromisedAssembly.setToolderived(true);
                compromisedAssembly.setAffectedElement(e);
                compromisedAssembly.getCausingElements().addAll(List.of(linking, credentials));
                return compromisedAssembly;
            }).collect(Collectors.toSet());
            var cleanedCollection = CollectionHelper.removeAlreadyAffectedElements(compromisedAssemblies,accessibleAssemblies);
            compromisedAssemblies.addAll((Collection<? extends CompromisedAssembly>) cleanedCollection);
        }
        return compromisedAssemblies;
    }


    private Set<CompromisedResource> propagateByContextToResource(List<LinkingResource> compromisedLinkingResources,
            ContextSet credentials) {
        var compromisedResources = new HashSet<CompromisedResource>();
        for (var linking : compromisedLinkingResources) {
            var reachableResources = linking.getConnectedResourceContainers_LinkingResource();
            var accessibleResources = reachableResources.stream().filter(e -> {
                var policies = PolicyHelper.getPolicy(this.modelStorage.getSpecification(), e);
                return policies.stream().anyMatch(policy -> policy.checkAccessRight(credentials));
            }).map(e -> {
                var compromisedAssembly = KAMP4attackModificationmarksFactory.eINSTANCE.createCompromisedResource();
                compromisedAssembly.setToolderived(true);
                compromisedAssembly.setAffectedElement(e);
                compromisedAssembly.getCausingElements().addAll(List.of(linking, credentials));
                return compromisedAssembly;
            }).collect(Collectors.toSet());
            var cleanedCollection = CollectionHelper.removeAlreadyAffectedElements(compromisedResources,accessibleResources);
            compromisedResources.addAll((Collection<? extends CompromisedResource>) cleanedCollection);
        }
        return compromisedResources;
    }
    private Set<CompromisedResource> propagateByAttackToResource(List<LinkingResource> compromisedLinkingResources,
            ContextSet credentials) {
        var compromisedResources = new HashSet<CompromisedResource>();
        var attacks = getAttacks();
        for (var linking : compromisedLinkingResources) {
            var reachableResources = linking.getConnectedResourceContainers_LinkingResource();
            for(var resource : reachableResources) {
                var vulnerabilityList = VulnerabilityHelper
                        .getVulnerabilities(this.modelStorage.getVulnerabilitySpecification(), resource);
                var policies = PolicyHelper.getPolicy(this.modelStorage.getSpecification(), resource);
                var vulnerability = VulnerabilityHelper.checkAttack(credentials, policies, vulnerabilityList, attacks,
                        AttackVector.ADJACENT_NETWORK);
                if (vulnerability != null && vulnerability.isTakeOver()) {
                    var compromisedLinkingResource = KAMP4attackModificationmarksFactory.eINSTANCE.createCompromisedResource();
                    compromisedLinkingResource.setAffectedElement(resource);
                    compromisedLinkingResource.getCausingElements().addAll(List.of(resource, vulnerability));
                    compromisedLinkingResource.setToolderived(true);
                    compromisedResources.add(compromisedLinkingResource);
                }
            }
        }
        return compromisedResources;
    }




    // TODO
    public void calculateLinkingResourceToAssemblyContext(CredentialChange changes) {
        var credentials = this.getCredentials(changes);
        var compromidesLinkingResources = this.getCompromisedLinkingResources(changes);
        
        var compromisedAssemblies = propagateByContextToAssembly(compromidesLinkingResources, credentials);
    }

    private List<LinkingResource> getCompromisedLinkingResources(CredentialChange changes) {
        return changes.getCompromisedlinkingresource().stream().map(CompromisedLinkingResource::getAffectedElement)
                .collect(Collectors.toList());
    }

}
