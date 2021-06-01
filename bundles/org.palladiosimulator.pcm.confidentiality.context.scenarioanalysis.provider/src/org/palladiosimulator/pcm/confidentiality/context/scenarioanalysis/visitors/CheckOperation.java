package org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.visitors;

import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

import org.eclipse.emf.ecore.util.EcoreUtil;
import org.palladiosimulator.pcm.confidentiality.context.ConfidentialAccessSpecification;
import org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.api.PCMBlackBoard;
import org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.output.creation.ScenarioResultStorage;
import org.palladiosimulator.pcm.confidentiality.context.set.ContextSet;
import org.palladiosimulator.pcm.confidentiality.context.specification.assembly.AttributeProvider;
import org.palladiosimulator.pcm.confidentiality.context.specification.assembly.MethodSpecification;
import org.palladiosimulator.pcm.confidentiality.context.specification.assembly.SystemPolicySpecification;
import org.palladiosimulator.pcm.core.composition.AssemblyConnector;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;
import org.palladiosimulator.pcm.core.composition.Connector;
import org.palladiosimulator.pcm.core.composition.ProvidedDelegationConnector;
import org.palladiosimulator.pcm.repository.OperationSignature;
import org.palladiosimulator.pcm.repository.Signature;
import org.palladiosimulator.pcm.seff.ExternalCallAction;
import org.palladiosimulator.pcm.system.System;
import org.palladiosimulator.pcm.usagemodel.EntryLevelSystemCall;
import org.palladiosimulator.pcm.usagemodel.UsageScenario;

public class CheckOperation {
    private final List<SystemPolicySpecification> policies;
    private final List<AttributeProvider> attributeProviders;
    private final ScenarioResultStorage storage;
    private final System system;
    private final UsageScenario scenario;

    public CheckOperation(final PCMBlackBoard pcm, final ConfidentialAccessSpecification accessSpecificatoin,
            final ScenarioResultStorage storage, final UsageScenario scenario) {
        // non null checks
        Objects.requireNonNull(pcm);
        Objects.requireNonNull(accessSpecificatoin);
        Objects.requireNonNull(storage);
        Objects.requireNonNull(scenario);

        this.policies = accessSpecificatoin.getPcmspecificationcontainer().getPolicyspecification().stream()
                .filter(SystemPolicySpecification.class::isInstance).map(SystemPolicySpecification.class::cast)
                .collect(Collectors.toList());
        this.attributeProviders = accessSpecificatoin.getPcmspecificationcontainer().getAttributeprovider();
        this.storage = storage;
        this.system = pcm.getSystem();
        this.scenario = scenario;
    }

    public Optional<ContextSet> performCheck(final ExternalCallAction externalAction,
            final AssemblyContext encapsulatedContext, final ContextSet requestorContext) {
        final var connector = this.getAssemblyConnector(externalAction, encapsulatedContext);

        return this.performCheck(externalAction.getCalledService_ExternalService(), connector, requestorContext);

    }

    public Optional<ContextSet> performCheck(final EntryLevelSystemCall systemCall,
            final AssemblyContext encapsulatedContext, final ContextSet requestorContext) {
        final var connector = this.getDelegationConnector(systemCall, encapsulatedContext);
        return this.performCheck(systemCall.getOperationSignature__EntryLevelSystemCall(), connector, requestorContext);
    }

    public Optional<ContextSet> performCheck(final OperationSignature signature, final Connector connector,
            final ContextSet requestorContext) {
        final var setContexts = this.getContextSets(signature, connector, this.policies);
        final var listAttributeProvider = this.getAttributeProvider(signature, connector);
        if (!this.checkContextSet(requestorContext, setContexts)) {
            this.storage.storeNegativeResult(this.scenario, signature.getInterface__OperationSignature(), signature,
                    connector, requestorContext, setContexts);
        }
        if (listAttributeProvider.isEmpty()) {
            return Optional.empty();
        }
        if (listAttributeProvider.size() != 1) {
            throw new IllegalStateException(
                    "There exists more than one attribute provider for one method specification. Please recheck your model");
        } else {
            return Optional.of(listAttributeProvider.get(0));
        }
    }

    private ProvidedDelegationConnector getDelegationConnector(final EntryLevelSystemCall systemCall,
            final AssemblyContext assemblyContext) {

        final var connector = this.system.getConnectors__ComposedStructure().stream()
                .filter(ProvidedDelegationConnector.class::isInstance).map(ProvidedDelegationConnector.class::cast)
                .filter(e -> EcoreUtil.equals(e.getAssemblyContext_ProvidedDelegationConnector(), assemblyContext))
                .filter(e -> EcoreUtil.equals(e.getOuterProvidedRole_ProvidedDelegationConnector(),
                        systemCall.getProvidedRole_EntryLevelSystemCall()))
                .findAny();
        if (connector.isEmpty()) {
            throw new IllegalStateException(
                    "Connector entry level system call not found: " + systemCall.getEntityName());
        }
        return connector.get();
    }

    private boolean checkContextSet(final ContextSet contextRequestor, final List<ContextSet> policies) {
        return policies.stream().anyMatch(policy -> policy.checkAccessRight(contextRequestor));
    }

    private List<ContextSet> getContextSets(final Signature signature, final Connector connector,
            final List<SystemPolicySpecification> policies) {
        return policies.stream().filter(e -> e.getMethodspecification() != null)
                .filter(e -> this.filterMethodspecification(signature, connector, e.getMethodspecification()))
                .flatMap(e -> e.getPolicy().stream()).collect(Collectors.toList());
    }

    private boolean filterMethodspecification(final Signature signature, final Connector connector,
            final MethodSpecification methodSpecification) {
        return EcoreUtil.equals(methodSpecification.getSignature(), signature)
                && EcoreUtil.equals(methodSpecification.getConnector(), connector);
    }

    private List<ContextSet> getAttributeProvider(final Signature signature, final Connector connector) {
        return this.attributeProviders.stream().filter(e -> e.getMethodspecification() != null)
                .filter(e -> this.filterMethodspecification(signature, connector, e.getMethodspecification()))
                .map(AttributeProvider::getContextset).collect(Collectors.toList());
    }

    private AssemblyConnector getAssemblyConnector(final ExternalCallAction action,
            final AssemblyContext assemblyContext) {
        final var signatureExternalCall = action.getCalledService_ExternalService();

        final var optConnector = this.system.getConnectors__ComposedStructure().stream()
                .filter(AssemblyConnector.class::isInstance).map(AssemblyConnector.class::cast)
                .filter(e -> EcoreUtil.equals(
                        e.getProvidedRole_AssemblyConnector().getProvidedInterface__OperationProvidedRole(),
                        signatureExternalCall.getInterface__OperationSignature()))
                .filter(e -> EcoreUtil.equals(e.getRequiringAssemblyContext_AssemblyConnector(), assemblyContext))
                .findAny();
        if (optConnector.isEmpty()) {
            throw new IllegalArgumentException(
                    "Connector for external call not found. Please verify model: " + action.getEntityName());
        }

        return optConnector.get();
    }

}
