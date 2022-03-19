package org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.visitors;

import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Objects;

import org.palladiosimulator.pcm.confidentiality.context.ConfidentialAccessSpecification;
import org.palladiosimulator.pcm.confidentiality.context.helper.PolicyHelper;
import org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.api.Configuration;
import org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.api.PCMBlackBoard;
import org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.output.creation.ScenarioResultStorage;
import org.palladiosimulator.pcm.confidentiality.context.system.UsageSpecification;
import org.palladiosimulator.pcm.confidentiality.context.xacml.pdp.Evaluate;
import org.palladiosimulator.pcm.confidentiality.context.xacml.pdp.result.DecisionType;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;
import org.palladiosimulator.pcm.core.composition.Connector;
import org.palladiosimulator.pcm.repository.Signature;
import org.palladiosimulator.pcm.seff.ResourceDemandingSEFF;
import org.palladiosimulator.pcm.usagemodel.UsageScenario;

import de.uka.ipd.sdq.identifier.Identifier;

public class CheckOperation {
//    private final List<AttributeProvider> attributeProviders;
    private final ScenarioResultStorage storage;
//    private final System system;
    private final UsageScenario scenario;
//    private final Configuration configuration;
    private final Evaluate eval;

    public CheckOperation(final PCMBlackBoard pcm, final ConfidentialAccessSpecification accessSpecification,
            final ScenarioResultStorage storage, final UsageScenario scenario, Configuration configuration,
            Evaluate eval) {
        // non null checks
        Objects.requireNonNull(pcm);
        Objects.requireNonNull(accessSpecification);
        Objects.requireNonNull(storage);
        Objects.requireNonNull(scenario);
        Objects.requireNonNull(configuration);
        Objects.requireNonNull(eval);

//        this.attributeProviders = accessSpecification.getPcmspecificationcontainer().getAttributeprovider();
        this.storage = storage;
//        this.system = pcm.getSystem();
        this.scenario = scenario;
//        this.configuration = configuration;
        this.eval = eval;
    }

//    public Optional<ContextSet> performCheck(final ExternalCallAction externalAction,
//            final AssemblyContext encapsulatedContext, final List<? extends UsageSpecification> requestorContext) {
//        final var connector = getAssemblyConnector(externalAction, encapsulatedContext);
//
//        var listComponent = PCMInstanceHelper.getHandlingAssemblyContexts(externalAction, List.of(encapsulatedContext));
//        if (listComponent.isEmpty()) {
//            throw new IllegalStateException("Component for external call " + externalAction + " not found");
//        }
//        var component = listComponent.get(listComponent.size() - 1);
//
//        var switchConnector = new CompositionSwitch<ProvidedRole>() {
//
//            @Override
//            public ProvidedRole caseProvidedDelegationConnector(ProvidedDelegationConnector object) {
//                return object.getOuterProvidedRole_ProvidedDelegationConnector();
//            }
//
//            @Override
//            public ProvidedRole caseAssemblyConnector(AssemblyConnector object) {
//                return object.getProvidedRole_AssemblyConnector();
//            }
//
//        };
//        var role = switchConnector.doSwitch(connector);
//        performCheck(externalAction.getCalledService_ExternalService(), component, connector, role, requestorContext);
//
//        return this.performCheck(externalAction.getCalledService_ExternalService(), connector, requestorContext);
//
//    }
//
//    public Optional<ContextSet> performCheck(final EntryLevelSystemCall systemCall,
//            final List<AssemblyContext> encapsulatedContext,
//            final List<? extends UsageSpecification> requestorContext) {
//        final var connector = getDelegationConnector(systemCall, encapsulatedContext);
//        this.performCheck(systemCall.getOperationSignature__EntryLevelSystemCall(), encapsulatedContext, connector,
//                connector.getInnerProvidedRole_ProvidedDelegationConnector(), requestorContext);
//        return this.performCheck(systemCall.getOperationSignature__EntryLevelSystemCall(), connector, requestorContext);
//    }
//
//    public Optional<ContextSet> performCheck(final OperationSignature signature, final Connector connector,
//            final List<? extends UsageSpecification> requestorContext) {
//        final var setContexts = getContextSets(signature, connector, this.policies);
//        if (!setContexts.isEmpty() && !checkContextSet(requestorContext, setContexts)) {
//            this.storage.storeNegativeResult(this.scenario, signature.getInterface__OperationSignature(), signature,
//                    connector, requestorContext, setContexts);
//        }
//        if (!this.configuration.isAttributeProviders()) {
//            return Optional.empty();
//        }
//
//        final var listAttributeProvider = getAttributeProvider(signature, connector);
//        if (listAttributeProvider.isEmpty()) {
//            return Optional.empty();
//        }
//        if (listAttributeProvider.size() != 1) {
//            throw new IllegalStateException(
//                    "There exists more than one attribute provider for one method specification. Please recheck your model");
//        } else {
//            return Optional.of(listAttributeProvider.get(0));
//        }
//    }

    public void performCheck(Signature signature, Deque<AssemblyContext> component, ResourceDemandingSEFF seff,
            List<? extends UsageSpecification> requestorContext) {

        performCheckEntity(signature, component, seff, requestorContext);
    }

    public void performCheck(Signature signature, Deque<AssemblyContext> component, Connector connector,
            List<? extends UsageSpecification> requestorContext) {

        performCheckEntity(signature, component, connector, requestorContext);
    }

    public void performCheckEntity(Signature signature, Deque<AssemblyContext> component, Identifier role,
            List<? extends UsageSpecification> requestorContext) {
        var listSubject = new ArrayList<UsageSpecification>();
        var listEnvironment = new ArrayList<UsageSpecification>();
        var listResource = new ArrayList<UsageSpecification>();
        var listAction = new ArrayList<UsageSpecification>();
        var listXML = new ArrayList<UsageSpecification>();

        PolicyHelper.createRequestAttributes(signature, component, requestorContext, listSubject, listEnvironment,
                listResource, listAction, listXML);

        var resultOpt = this.eval.evaluate(listSubject, listEnvironment, listResource, listAction, listXML);

        if (resultOpt.isEmpty()) {
            throw new IllegalStateException("Empty PDP-Results");
        }
        var result = resultOpt.get();
        if (!result.getDecision().equals(DecisionType.PERMIT)) {
            this.storage.storeNegativeResult(this.scenario, null, signature, role, result);
        }
    }

//    private ProvidedDelegationConnector getDelegationConnector(final EntryLevelSystemCall systemCall,
//            final AssemblyContext assemblyContext) {
//
//        final var connector = this.system.getConnectors__ComposedStructure().stream()
//                .filter(ProvidedDelegationConnector.class::isInstance).map(ProvidedDelegationConnector.class::cast)
//                .filter(e -> EcoreUtil.equals(e.getAssemblyContext_ProvidedDelegationConnector(), assemblyContext))
//                .filter(e -> EcoreUtil.equals(e.getOuterProvidedRole_ProvidedDelegationConnector(),
//                        systemCall.getProvidedRole_EntryLevelSystemCall()))
//                .findAny();
//        if (connector.isEmpty()) {
//            throw new IllegalStateException(
//                    "Connector entry level system call not found: " + systemCall.getEntityName());
//        }
//        return connector.get();
//    }

//    private List<ContextSet> getContextSets(final Signature signature, final Connector connector,
//            final List<SystemPolicySpecification> policies) {
//        return policies.stream().filter(e -> e.getMethodspecification() != null)
//                .filter(e -> e.getMethodspecification() instanceof ConnectionRestriction)
//                .filter(e -> filterMethodspecification(signature, connector,
//                        (ConnectionRestriction) e.getMethodspecification()))
//                .flatMap(e -> e.getPolicy().stream()).collect(Collectors.toList());
//    }
//
//    private boolean filterMethodspecification(final Signature signature, final Connector connector,
//            final ConnectionRestriction methodSpecification) {
//        return EcoreUtil.equals(methodSpecification.getSignature(), signature)
//                && EcoreUtil.equals(methodSpecification.getConnector(), connector);
//    }
//
//    private List<ContextSet> getAttributeProvider(final Signature signature, final Connector connector) {
//        return this.attributeProviders.stream().filter(e -> e.getMethodspecification() != null)
//                .filter(e -> filterMethodspecification(signature, connector, e.getMethodspecification()))
//                .map(AttributeProvider::getContextset).collect(Collectors.toList());
//    }
//
//    private List<ContextSet> getContextSets(OperationSignature signature, ProvidedRole role, AssemblyContext component,
//            List<SystemPolicySpecification> policies) {
//        return policies.stream().filter(e -> e.getMethodspecification() != null)
//                .filter(e -> e.getMethodspecification() instanceof ServiceRestriction).filter(e -> {
//                    var restriction = (ServiceRestriction) e.getMethodspecification();
//                    return EcoreUtil.equals(restriction.getSignature(), signature)
//                            && EcoreUtil.equals(restriction.getProvidedrole(), role)
//                            && EcoreUtil.equals(restriction.getAssemblycontext(), component);
//                }).flatMap(e -> e.getPolicy().stream()).collect(Collectors.toList());
//
//    }
//
//    private AssemblyConnector getAssemblyConnector(final ExternalCallAction action,
//            final AssemblyContext assemblyContext) {
//        final var signatureExternalCall = action.getCalledService_ExternalService();
//
//        final var optConnector = this.system.getConnectors__ComposedStructure().stream()
//                .filter(AssemblyConnector.class::isInstance).map(AssemblyConnector.class::cast)
//                .filter(e -> EcoreUtil.equals(
//                        e.getProvidedRole_AssemblyConnector().getProvidedInterface__OperationProvidedRole(),
//                        signatureExternalCall.getInterface__OperationSignature()))
//                .filter(e -> EcoreUtil.equals(e.getRequiringAssemblyContext_AssemblyConnector(), assemblyContext))
//                .findAny();
//        if (optConnector.isEmpty()) {
//            throw new IllegalArgumentException(
//                    "Connector for external call not found. Please verify model: " + action.getEntityName());
//        }
//
//        return optConnector.get();
//    }

}
