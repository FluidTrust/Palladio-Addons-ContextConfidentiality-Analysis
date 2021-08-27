package org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.data;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

import org.eclipse.emf.ecore.EObject;
import org.eclipse.emf.ecore.util.EcoreUtil;
import org.palladiosimulator.pcm.allocation.Allocation;
import org.palladiosimulator.pcm.allocation.AllocationContext;
import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.ServiceRestriction;
import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.StructureFactory;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;
import org.palladiosimulator.pcm.repository.BasicComponent;
import org.palladiosimulator.pcm.resourceenvironment.ResourceContainer;
import org.palladiosimulator.pcm.seff.ResourceDemandingSEFF;

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
        var listRestriction = new ArrayList<ServiceRestriction>();

        for (var component : components) {
            var repoComponent = component.getEncapsulatedComponent__AssemblyContext();
            if (repoComponent instanceof BasicComponent) {
                for (var seff : ((BasicComponent) repoComponent).getServiceEffectSpecifications__BasicComponent()) {
                    if (seff instanceof ResourceDemandingSEFF) {
                        var specification = StructureFactory.eINSTANCE.createServiceRestriction();
                        specification.setAssemblycontext(component);
                        specification.setService((ResourceDemandingSEFF) seff);
                        listRestriction.add(specification);
                    }
                }
            }
        }

        return listRestriction;
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
