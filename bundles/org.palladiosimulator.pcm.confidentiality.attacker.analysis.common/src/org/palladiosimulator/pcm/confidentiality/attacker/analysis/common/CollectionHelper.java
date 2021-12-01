package org.palladiosimulator.pcm.confidentiality.attacker.analysis.common;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

import org.eclipse.emf.ecore.EObject;
import org.eclipse.emf.ecore.util.EcoreUtil;
import org.palladiosimulator.pcm.allocation.Allocation;
import org.palladiosimulator.pcm.allocation.AllocationContext;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.AttackerSystemSpecificationContainer;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.PCMElement;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.VulnerabilitySystemIntegration;
import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.ServiceRestriction;
import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.StructureFactory;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;
import org.palladiosimulator.pcm.repository.BasicComponent;
import org.palladiosimulator.pcm.resourceenvironment.ResourceContainer;
import org.palladiosimulator.pcm.seff.ResourceDemandingSEFF;

import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedAssembly;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedService;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksFactory;

public class CollectionHelper {
    private CollectionHelper() {

    }

    public static List<AssemblyContext> getAssemblyContext(final List<ResourceContainer> reachableResources,
            final Allocation allocation) {
        return allocation.getAllocationContexts_Allocation().stream()
                .filter(container -> searchResource(container.getResourceContainer_AllocationContext(),
                        reachableResources))
                .map(AllocationContext::getAssemblyContext_AllocationContext).distinct().collect(Collectors.toList());

    }

    public static List<ServiceRestriction> getProvidedRestrictions(final List<AssemblyContext> components) {

        return components.stream().flatMap(component -> CollectionHelper.getProvidedRestrictions(component).stream())
                .collect(Collectors.toList());
    }

    public static List<ServiceRestriction> getProvidedRestrictions(AssemblyContext component) {
        var listRestriction = new ArrayList<ServiceRestriction>();

        var repoComponent = component.getEncapsulatedComponent__AssemblyContext();
        if (repoComponent instanceof BasicComponent) {
            for (var seff : ((BasicComponent) repoComponent).getServiceEffectSpecifications__BasicComponent()) {
                if (seff instanceof ResourceDemandingSEFF) {
                    var specification = StructureFactory.eINSTANCE.createServiceRestriction();
                    specification.setAssemblycontext(component);
                    specification.setService((ResourceDemandingSEFF) seff);
                    specification.setSignature(seff.getDescribedService__SEFF());
                    listRestriction.add(specification);
                }
            }
        }

        return listRestriction;

    }

    public static List<CompromisedService> filterExistingService(final List<CompromisedService> services,
            final CredentialChange change) {
        return services.stream().filter(service -> !containsService(service, change)).collect(Collectors.toList());

    }

    public static ServiceRestriction findOrCreateServiceRestriction(ServiceRestriction service,
            AttackerSystemSpecificationContainer attackerSpecification, CredentialChange change) {
        var listMethodSpecification = attackerSpecification.getVulnerabilities().stream()
                .filter(VulnerabilitySystemIntegration.class::isInstance)
                .map(VulnerabilitySystemIntegration.class::cast)
                .filter(e -> e.getPcmelement().getMethodspecification() != null)
                .map(VulnerabilitySystemIntegration::getPcmelement).map(PCMElement::getMethodspecification)
                .filter(ServiceRestriction.class::isInstance).map(ServiceRestriction.class::cast)
                .filter(e -> EcoreUtil.equals(e.getService(), service.getService())
                        && EcoreUtil.equals(e.getAssemblycontext(), service.getAssemblycontext()))
                .findAny();

        if (listMethodSpecification.isPresent()) {
            return listMethodSpecification.get();
        }

        if (change.getServicerestrictioncontainer() == null) {
            change.setServicerestrictioncontainer(
                    KAMP4attackModificationmarksFactory.eINSTANCE.createServiceRestrictionContainer());
        }

        listMethodSpecification = change.getServicerestrictioncontainer().getServicerestriction().stream()
                .filter(e -> EcoreUtil.equals(e.getService(), service.getService())
                        && EcoreUtil.equals(e.getAssemblycontext(), service.getAssemblycontext()))
                .findAny();

        if (listMethodSpecification.isPresent()) {
            return listMethodSpecification.get();
        } else {
            change.getServicerestrictioncontainer().getServicerestriction().add(service);
            return service;
        }

    }

    public static void addService(final Collection<CompromisedAssembly> compromisedAssemblies,
            AttackerSystemSpecificationContainer container, final CredentialChange change) {

        for (final var component : compromisedAssemblies) {
            final var serviceRestrictions = CollectionHelper.getProvidedRestrictions(component.getAffectedElement());

            final var causingElement = new ArrayList<AssemblyContext>();
            causingElement.add(component.getAffectedElement());

            var serviceRestrictionsCompromised = serviceRestrictions.stream().map(service -> {
                var serviceModel = CollectionHelper.findOrCreateServiceRestriction(service, container, change);
                return HelperCreationCompromisedElements.createCompromisedService(serviceModel, causingElement);
            }).collect(Collectors.toList());

            serviceRestrictionsCompromised = CollectionHelper.filterExistingService(serviceRestrictionsCompromised,
                    change);
            change.getCompromisedservice().addAll(serviceRestrictionsCompromised);
        }

    }

    private static boolean containsService(final CompromisedService service, final CredentialChange change) {
        return change.getCompromisedservice().stream().anyMatch(referenceComponent -> EcoreUtil
                .equals(referenceComponent.getAffectedElement(), service.getAffectedElement()));
    }

    @SuppressWarnings("unchecked")
    public static <T extends EObject> List<T> removeDuplicates(final Collection<T> collection) {
        return (List<T>) EcoreUtil.filterDescendants(collection); // checked by incoming values
    }

    private static boolean searchResource(final ResourceContainer targetContainer,
            final List<ResourceContainer> listContainer) {
        return listContainer.stream().anyMatch(container -> EcoreUtil.equals(container, targetContainer));
    }

}
