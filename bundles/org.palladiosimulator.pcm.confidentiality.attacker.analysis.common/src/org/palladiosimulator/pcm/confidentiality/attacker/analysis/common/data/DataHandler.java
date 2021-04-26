package org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.data;

import java.util.Collection;
import java.util.List;
import java.util.Optional;
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

public class DataHandler {
    
    private DataHandler() {
        
    }
    
    public static Collection<CompromisedData> getData(RepositoryComponent component) {
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
                }).flatMap(Optional::stream).collect(Collectors.toList());

        listDataParameter.addAll(listDataReturnTypes);
        return listDataParameter;

    }

    private static Optional<CompromisedData> createDataReturnValue(OperationSignature signature) {
        if(signature.getReturnType__OperationSignature() == null)
            return Optional.empty();
        var data = AttackerFactory.eINSTANCE.createCompromisedData();
        data.setDataType(signature.getReturnType__OperationSignature());
        data.setSource(signature);
        return Optional.of(data);
    }

    private static Collection<CompromisedData> createDataFromParameter(RepositoryComponent component,
            Stream<Parameter> parameters) {
        return parameters.map(parameter -> {
            var data = AttackerFactory.eINSTANCE.createCompromisedData();
            data.setDataType(parameter.getDataType__Parameter());
            data.setReferenceName(parameter.getParameterName());
            data.setSource(component);
            return data;
        }).collect(Collectors.toList());
    }

    public static List<CompromisedData> getData(ResourceContainer resource, Allocation allocation) {
        var assemblyContexts = CollectionHelper.getAssemblyContext(List.of(resource), allocation);
        return assemblyContexts.stream().map(AssemblyContext::getEncapsulatedComponent__AssemblyContext)
                .flatMap(e -> getData(e).stream()).collect(Collectors.toList());
    }

    public static Collection<CompromisedData> getData(ResourceDemandingSEFF seff) {
        var component = seff.getBasicComponent_ServiceEffectSpecification();
        var parameterStream = ((OperationSignature) seff.getDescribedService__SEFF())
                .getParameters__OperationSignature().stream();

        var dataSignatureList = DataHandler.createDataFromParameter(component, parameterStream);

        var seffList = seff.getSteps_Behaviour().stream().filter(ExternalCallAction.class::isInstance)
                .map(ExternalCallAction.class::cast).map(ExternalCallAction::getCalledService_ExternalService)
                .map(DataHandler::createDataReturnValue).flatMap(Optional::stream).collect(Collectors.toUnmodifiableList());
        
        var returnData = createDataReturnValue((OperationSignature) seff.getDescribedService__SEFF());
        if(returnData.isPresent()) {
            dataSignatureList.add(returnData.get());
        }
        
        
        dataSignatureList.addAll(seffList);
        return dataSignatureList;

    }

}
