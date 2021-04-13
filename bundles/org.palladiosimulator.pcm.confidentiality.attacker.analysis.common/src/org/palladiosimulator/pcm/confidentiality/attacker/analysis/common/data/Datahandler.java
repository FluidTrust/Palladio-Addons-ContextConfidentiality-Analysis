package org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.data;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.palladiosimulator.pcm.confidentiality.attackerSpecification.AttackerFactory;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.CompromisedData;
import org.palladiosimulator.pcm.repository.OperationProvidedRole;
import org.palladiosimulator.pcm.repository.OperationRequiredRole;
import org.palladiosimulator.pcm.repository.RepositoryComponent;

public class Datahandler {
    
    public List<CompromisedData> getData(RepositoryComponent component) {
        var interfacesList = component.getProvidedRoles_InterfaceProvidingEntity().stream()
                .filter(OperationProvidedRole.class::isInstance).map(OperationProvidedRole.class::cast)
                .map(OperationProvidedRole::getProvidedInterface__OperationProvidedRole)
                .collect(Collectors.toUnmodifiableList());
        var parameters = interfacesList.stream().flatMap(e -> e.getSignatures__OperationInterface().stream())
                .flatMap(e -> e.getParameters__OperationSignature().stream());
        var listDataParameter = parameters.map(parameter -> {
            var data = AttackerFactory.eINSTANCE.createCompromisedData();
            data.setDataType(parameter.getDataType__Parameter());
            data.setReferenceName(parameter.getParameterName());
            return data;
        });

        var interfacesRequired = component.getRequiredRoles_InterfaceRequiringEntity().stream()
                .filter(OperationRequiredRole.class::isInstance).map(OperationRequiredRole.class::cast)
                .map(OperationRequiredRole::getRequiredInterface__OperationRequiredRole);

        interfacesRequired = Stream.concat(interfacesList.stream(), interfacesRequired);
        var listDataReturnTypes = interfacesRequired.flatMap(e -> e.getSignatures__OperationInterface().stream())
                .map(returnType -> {
                    var data = AttackerFactory.eINSTANCE.createCompromisedData();
                    data.setDataType(returnType.getReturnType__OperationSignature());
                    return data;
                });

        return Stream.concat(listDataReturnTypes, listDataParameter).collect(Collectors.toUnmodifiableList());

    }

}
