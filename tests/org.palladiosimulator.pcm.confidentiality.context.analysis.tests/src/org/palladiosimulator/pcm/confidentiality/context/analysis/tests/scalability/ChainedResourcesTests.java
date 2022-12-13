package org.palladiosimulator.pcm.confidentiality.context.analysis.tests.scalability;

import org.palladiosimulator.pcm.core.composition.AssemblyContext;
import org.palladiosimulator.pcm.core.composition.CompositionFactory;
import org.palladiosimulator.pcm.core.composition.RequiredDelegationConnector;
import org.palladiosimulator.pcm.repository.OperationProvidedRole;
import org.palladiosimulator.pcm.repository.OperationRequiredRole;
import org.palladiosimulator.pcm.system.System;

public class ChainedResourcesTests extends ScalabilityTests {

    @Override
    protected String getFilename() {
        return "chain.csv";
    }

    @Override
    protected AssemblyContext resourceAddOperation(final System system, final AssemblyContext context) {
        final var newComponent = CompositionFactory.eINSTANCE.createAssemblyContext();

        newComponent.setEncapsulatedComponent__AssemblyContext(context.getEncapsulatedComponent__AssemblyContext());

        final var delegationConnector = system.getConnectors__ComposedStructure()
            .stream()
            .filter(RequiredDelegationConnector.class::isInstance)
            .map(RequiredDelegationConnector.class::cast)
            .findAny();
        delegationConnector.get()
            .setAssemblyContext_RequiredDelegationConnector(newComponent);

        final var connector = CompositionFactory.eINSTANCE.createAssemblyConnector();

        connector.setParentStructure__Connector(system);
        connector.setProvidingAssemblyContext_AssemblyConnector(newComponent);
        connector.setRequiringAssemblyContext_AssemblyConnector(context);
        connector.setProvidedRole_AssemblyConnector(
                (OperationProvidedRole) context.getEncapsulatedComponent__AssemblyContext()
                    .getProvidedRoles_InterfaceProvidingEntity()
                    .get(0));
        connector.setRequiredRole_AssemblyConnector(
                (OperationRequiredRole) context.getEncapsulatedComponent__AssemblyContext()
                    .getRequiredRoles_InterfaceRequiringEntity()
                    .get(0));

        system.getConnectors__ComposedStructure()
            .add(connector);
        system.getAssemblyContexts__ComposedStructure()
            .add(newComponent);

        return newComponent;
    }
}
