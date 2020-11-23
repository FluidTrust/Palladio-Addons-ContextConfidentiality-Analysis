package org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.visitors;

import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import org.eclipse.emf.ecore.util.EcoreUtil;
import org.palladiosimulator.pcm.confidentiality.context.ConfidentialAccessSpecification;
import org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.api.PCMBlackBoard;
import org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.output.creation.ScenarioResultStorage;
import org.palladiosimulator.pcm.confidentiality.context.set.ContextSet;
import org.palladiosimulator.pcm.confidentiality.context.specification.assembly.SystemPolicySpecification;
import org.palladiosimulator.pcm.core.composition.AssemblyConnector;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;
import org.palladiosimulator.pcm.core.composition.Connector;
import org.palladiosimulator.pcm.core.composition.DelegationConnector;
import org.palladiosimulator.pcm.core.composition.ProvidedDelegationConnector;
import org.palladiosimulator.pcm.repository.OperationSignature;
import org.palladiosimulator.pcm.repository.Signature;
import org.palladiosimulator.pcm.seff.ExternalCallAction;
import org.palladiosimulator.pcm.system.System;
import org.palladiosimulator.pcm.usagemodel.EntryLevelSystemCall;
import org.palladiosimulator.pcm.usagemodel.UsageScenario;

public class CheckOperation {
    private List<SystemPolicySpecification> policies;
    private ContextSet requestorContext;
    private ScenarioResultStorage storage;
    private System system;
    private UsageScenario scenario;

    public CheckOperation(PCMBlackBoard pcm, ConfidentialAccessSpecification accessSpecificatoin,
            ContextSet requestorContext, ScenarioResultStorage storage, UsageScenario scenario) {
        // non null checks
        Objects.requireNonNull(pcm);
        Objects.requireNonNull(accessSpecificatoin);
        Objects.requireNonNull(requestorContext);
        Objects.requireNonNull(storage);
        Objects.requireNonNull(scenario);

        this.policies = accessSpecificatoin.getPcmspecificationcontainer().getPolicyspecification().stream()
                .filter(SystemPolicySpecification.class::isInstance).map(SystemPolicySpecification.class::cast)
                .collect(Collectors.toList());
        this.requestorContext = requestorContext;
        this.storage = storage;
        this.system = pcm.getSystem();
        this.scenario = scenario;
    }

    public void performCheck(ExternalCallAction externalAction, AssemblyContext encapsulatedContext) {
        var connector = getAssemblyConnector(externalAction, encapsulatedContext);

        performCheck(externalAction.getCalledService_ExternalService(), connector);

    }
    
    public void performCheck(EntryLevelSystemCall systemCall, AssemblyContext encapsulatedContext) {
        var connector = getDelegationConnector(systemCall, encapsulatedContext);
        performCheck(systemCall.getOperationSignature__EntryLevelSystemCall(), connector);
    }

    private void performCheck(OperationSignature signature, Connector connector) {
        var setContexts = getContextSets(signature, connector, policies);
        if (!checkContextSet(requestorContext, setContexts)) {
            storage.storeNegativeResult(scenario, signature.getInterface__OperationSignature(), signature, connector,
                    requestorContext, setContexts);
        }
    }



    private ProvidedDelegationConnector getDelegationConnector(EntryLevelSystemCall systemCall,
            AssemblyContext assemblyContext) {

        var connector = system.getConnectors__ComposedStructure().stream()
                .filter(ProvidedDelegationConnector.class::isInstance).map(ProvidedDelegationConnector.class::cast)
                .filter(e -> EcoreUtil.equals(e.getAssemblyContext_ProvidedDelegationConnector(), assemblyContext))
                .filter(e -> EcoreUtil.equals(e.getOuterProvidedRole_ProvidedDelegationConnector(),
                        systemCall.getProvidedRole_EntryLevelSystemCall()))
                .findAny();
        if (connector.isEmpty())
            throw new IllegalStateException(
                    "Connector entry level system call not found: " + systemCall.getEntityName());
        return connector.get();
    }

    private boolean checkContextSet(ContextSet contextRequestor, List<ContextSet> policies) {
        return policies.stream().anyMatch(policy -> policy.checkAccessRight(contextRequestor));
    }

    private List<ContextSet> getContextSets(Signature signature, Connector connector,
            List<SystemPolicySpecification> policies) {
        return policies.stream().filter(e -> e.getMethodspecification() != null)
                .filter(e -> EcoreUtil.equals(e.getMethodspecification().getSignature(), signature)
                        && EcoreUtil.equals(e.getMethodspecification().getConnector(), connector))
                .flatMap(e -> e.getPolicy().stream()).collect(Collectors.toList());
    }

    private AssemblyConnector getAssemblyConnector(ExternalCallAction action, AssemblyContext assemblyContext) {
        var signatureExternalCall = action.getCalledService_ExternalService();

        var optConnector = system.getConnectors__ComposedStructure().stream()
                .filter(AssemblyConnector.class::isInstance).map(AssemblyConnector.class::cast)
                .filter(e -> EcoreUtil.equals(
                        e.getProvidedRole_AssemblyConnector().getProvidedInterface__OperationProvidedRole(),
                        signatureExternalCall.getInterface__OperationSignature()))
                .filter(e -> EcoreUtil.equals(e.getRequiringAssemblyContext_AssemblyConnector(), assemblyContext))
                .findAny();
        if (optConnector.isEmpty())
            throw new IllegalArgumentException(
                    "Connector for external call not found. Please verify model: " + action.getEntityName());

        return optConnector.get();
    }

}
