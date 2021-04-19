package org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.data;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.palladiosimulator.pcm.allocation.Allocation;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.AttackerFactory;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.CompromisedData;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;
import org.palladiosimulator.pcm.repository.OperationProvidedRole;
import org.palladiosimulator.pcm.repository.OperationRequiredRole;
import org.palladiosimulator.pcm.repository.OperationSignature;
import org.palladiosimulator.pcm.repository.Parameter;
import org.palladiosimulator.pcm.repository.RepositoryComponent;
import org.palladiosimulator.pcm.resourceenvironment.ResourceContainer;
import org.palladiosimulator.pcm.seff.ExternalCallAction;
import org.palladiosimulator.pcm.seff.ResourceDemandingSEFF;

public class Datahandler {

    public static List<CompromisedData> getData(RepositoryComponent component) {
        var interfacesList = component.getProvidedRoles_InterfaceProvidingEntity().stream()
                .filter(OperationProvidedRole.class::isInstance).map(OperationProvidedRole.class::cast)
                .map(OperationProvidedRole::getProvidedInterface__OperationProvidedRole)
                .collect(Collectors.toUnmodifiableList());
        var parameters = interfacesList.stream().flatMap(e -> e.getSignatures__OperationInterface().stream())
                .flatMap(e -> e.getParameters__OperationSignature().stream());
        var listDataParameter = createDataFromParameter(component, parameters);

        var interfacesRequired = component.getRequiredRoles_InterfaceRequiringEntity().stream()
                .filter(OperationRequiredRole.class::isInstance).map(OperationRequiredRole.class::cast)
                .map(OperationRequiredRole::getRequiredInterface__OperationRequiredRole);

        interfacesRequired = Stream.concat(interfacesList.stream(), interfacesRequired);
        var listDataReturnTypes = interfacesRequired.flatMap(e -> e.getSignatures__OperationInterface().stream())
                .map(returnType -> {
                    return createDataReturnValue(returnType);
                });

        return Stream.concat(listDataReturnTypes, listDataParameter).collect(Collectors.toUnmodifiableList());

    }

    private static CompromisedData createDataReturnValue(OperationSignature returnType) {
        var data = AttackerFactory.eINSTANCE.createCompromisedData();
        data.setDataType(returnType.getReturnType__OperationSignature());
        return data;
    }

    private static Stream<CompromisedData> createDataFromParameter(RepositoryComponent component,
            Stream<Parameter> parameters) {
        var listDataParameter = parameters.map(parameter -> {
            var data = AttackerFactory.eINSTANCE.createCompromisedData();
            data.setDataType(parameter.getDataType__Parameter());
            data.setReferenceName(parameter.getParameterName());
            data.setSource(component);
            return data;
        });
        return listDataParameter;
    }

    public static List<CompromisedData> getData(ResourceContainer resource, Allocation allocation) {
        var assemblyContexts = CollectionHelper.getAssemblyContext(List.of(resource), allocation);
        return assemblyContexts.stream().map(AssemblyContext::getEncapsulatedComponent__AssemblyContext)
                .flatMap(e -> getData(e).stream()).collect(Collectors.toList());
    }

    public static List<CompromisedData> getData(ResourceDemandingSEFF seff) {
        var component = seff.getBasicComponent_ServiceEffectSpecification();
        var parameterStream = ((OperationSignature) seff.getDescribedService__SEFF())
                .getParameters__OperationSignature().stream();

        var dataSignatureStream = Datahandler.createDataFromParameter(component, parameterStream);

        var seffStream = seff.getSteps_Behaviour().stream().filter(ExternalCallAction.class::isInstance)
                .map(ExternalCallAction.class::cast).map(ExternalCallAction::getCalledService_ExternalService)
                .map(Datahandler::createDataReturnValue);

        return Stream.concat(dataSignatureStream, seffStream).collect(Collectors.toUnmodifiableList());

    }

}
