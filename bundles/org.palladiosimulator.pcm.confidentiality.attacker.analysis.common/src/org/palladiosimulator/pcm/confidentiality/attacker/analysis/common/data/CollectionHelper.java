package org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.data;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

import org.eclipse.emf.ecore.EObject;
import org.eclipse.emf.ecore.util.EcoreUtil;
import org.palladiosimulator.pcm.allocation.Allocation;
import org.palladiosimulator.pcm.allocation.AllocationContext;
import org.palladiosimulator.pcm.confidentiality.context.specification.assembly.AssemblyFactory;
import org.palladiosimulator.pcm.confidentiality.context.specification.assembly.ProvidedRestriction;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;
import org.palladiosimulator.pcm.resourceenvironment.ResourceContainer;

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

    public static List<ProvidedRestriction> getProvidedRestrictions(final List<AssemblyContext> components) {
        var listRestriction = new ArrayList<ProvidedRestriction>();

        for (var component : components) {
            for (var role : component.getEncapsulatedComponent__AssemblyContext()
                    .getProvidedRoles_InterfaceProvidingEntity()) {
                var specification = AssemblyFactory.eINSTANCE.createProvidedRestriction();
                specification.setAssemblycontext(component);
                specification.setProvidedrole(role);
                listRestriction.add(specification);
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
