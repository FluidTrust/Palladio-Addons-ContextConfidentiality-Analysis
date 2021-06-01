package org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.provider;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.eclipse.emf.ecore.util.EcoreUtil;
import org.osgi.service.component.annotations.Component;
import org.palladiosimulator.pcm.confidentiality.context.ConfidentialAccessSpecification;
import org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.AnalysisResults;
import org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.OutputmodelFactory;
import org.palladiosimulator.pcm.confidentiality.context.model.ContextAttribute;
import org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.api.PCMBlackBoard;
import org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.api.ScenarioAnalysis;
import org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.visitors.UsageModelVisitorScenarioRepository;
import org.palladiosimulator.pcm.confidentiality.context.set.ContextSet;
import org.palladiosimulator.pcm.confidentiality.context.specification.ContextSpecification;
import org.palladiosimulator.pcm.confidentiality.context.specification.PolicySpecification;
import org.palladiosimulator.pcm.confidentiality.context.specification.assembly.SystemPolicySpecification;
import org.palladiosimulator.pcm.seff.ResourceDemandingBehaviour;
import org.palladiosimulator.pcm.usagemodel.UsageScenario;

@Component
public class ScenarioAnalysisImpl implements ScenarioAnalysis {

    @Override
    public AnalysisResults runScenarioAnalysis(final PCMBlackBoard pcm, final ConfidentialAccessSpecification context) {

        final var usage = pcm.getUsageModel();
        if (context.getPcmspecificationcontainer().getPolicyspecification().stream()
                .anyMatch(SystemPolicySpecification.class::isInstance)) {
            return new ScenarioAnalysisSystemImpl().runScenarioAnalysis(pcm, context);
        }

        final var result = OutputmodelFactory.eINSTANCE.createAnalysisResults();
        for (final var scenario : usage.getUsageScenario_UsageModel()) {
            final var visitor = new UsageModelVisitorScenarioRepository();
            final var seffs = visitor.doSwitch(scenario.getScenarioBehaviour_UsageScenario());

            final var output = OutputmodelFactory.eINSTANCE.createScenarioOutput();
            output.setResult(this.analysisScenario(scenario, seffs, context));
            output.setScenario(scenario);
            result.getScenariooutput().add(output);
        }

        return result;
    }

    private boolean analysisScenario(final UsageScenario scenario, final Set<ResourceDemandingBehaviour> behaviour,
            final ConfidentialAccessSpecification context) {

        final var contextSet = this.getContextSet(context.getPcmspecificationcontainer().getContextspecification(),
                scenario);
        final var policyList = this
                .getContextSetsPolicy(context.getPcmspecificationcontainer().getPolicyspecification(), behaviour);

        for (final var policySeff : policyList) {
            if (!this.checkContext(contextSet, policySeff)) {
                return false;
            }
        }

        return true;
    }

    private boolean checkContext(final ContextSet request, final List<ContextSet> contextListPolicy) {
        if (contextListPolicy.isEmpty()) {
            return false;
        }
        if (request.getContexts().isEmpty()) {
            return false;
        }
        for (final var policy : contextListPolicy) {
            if (this.checkContextSet(policy, request)) {
                return true;
            }
        }
        return false;
    }

    private boolean checkContextSet(final ContextSet policy, final ContextSet request) {
        for (final var policyItem : policy.getContexts()) {
            if (!this.checkContextAttribute(policyItem, request)) {
                return false;
            }
        }
        return true;
    }

    private boolean checkContextAttribute(final ContextAttribute policy, final ContextSet request) {
        return request.getContexts().stream().anyMatch(e -> !policy.checkAccessRight(e));

    }

    private List<List<ContextSet>> getContextSetsPolicy(final List<PolicySpecification> policySpecification,
            final Set<ResourceDemandingBehaviour> behaviour) {
        return policySpecification.stream().filter(policy -> this.contains(policy, behaviour))
                .map(PolicySpecification::getPolicy).collect(Collectors.toList());
    }

    private boolean contains(final PolicySpecification policy, final Set<ResourceDemandingBehaviour> behaviours) {
        for (final ResourceDemandingBehaviour behaviour : behaviours) {
            if (EcoreUtil.equals(policy.getResourcedemandingbehaviour(), behaviour)) {
                return true;
            }
        }
        return false;
    }

    private ContextSet getContextSet(final List<ContextSpecification> contextSpecification,
            final UsageScenario scenario) {
        return contextSpecification.stream().filter(usage -> EcoreUtil.equals(scenario, usage.getUsagescenario()))
                .map(ContextSpecification::getContextset).findFirst().get();
    }
}
