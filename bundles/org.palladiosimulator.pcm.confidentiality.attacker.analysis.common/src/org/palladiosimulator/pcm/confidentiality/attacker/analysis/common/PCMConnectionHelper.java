package org.palladiosimulator.pcm.confidentiality.attacker.analysis.common;

import java.util.List;
import java.util.stream.Collectors;

import org.eclipse.emf.ecore.util.EcoreUtil;
import org.palladiosimulator.pcm.core.composition.AssemblyConnector;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;
import org.palladiosimulator.pcm.system.System;

public class PCMConnectionHelper {

    private PCMConnectionHelper() {
        assert false;
    }

    public static List<AssemblyContext> getConnectectedAssemblies(System system, AssemblyContext component) {
        final var targetConnectors = getConnectedConnectors(component, system);

        final var targetComponents = targetConnectors.stream()
                .map(AssemblyConnector::getProvidingAssemblyContext_AssemblyConnector)
                .filter(e -> !EcoreUtil.equals(e, component)).collect(Collectors.toList());
        // not possible to change to toList() since this list needs to be mutable

        targetComponents
                .addAll(targetConnectors.stream().map(AssemblyConnector::getRequiringAssemblyContext_AssemblyConnector)
                        .filter(e -> !EcoreUtil.equals(e, component)).toList());
        return CollectionHelper.removeDuplicates(targetComponents);
    }

    public static List<AssemblyConnector> getConnectedConnectors(final AssemblyContext component, final System system) {
        return system.getConnectors__ComposedStructure().stream().filter(AssemblyConnector.class::isInstance)
                .map(AssemblyConnector.class::cast)
                .filter(e -> EcoreUtil.equals(e.getRequiringAssemblyContext_AssemblyConnector(), component)
                        || EcoreUtil.equals(e.getProvidingAssemblyContext_AssemblyConnector(), component))
                .toList();
    }

}
