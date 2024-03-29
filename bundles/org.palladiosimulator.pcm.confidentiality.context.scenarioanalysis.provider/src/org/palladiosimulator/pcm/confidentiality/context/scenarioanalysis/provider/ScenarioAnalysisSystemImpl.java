package org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.provider;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.eclipse.emf.ecore.EObject;
import org.eclipse.emf.ecore.util.EcoreUtil;
import org.osgi.service.component.annotations.Component;
import org.palladiosimulator.pcm.confidentiality.context.ConfidentialAccessSpecification;
import org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.AnalysisResults;
import org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.api.Configuration;
import org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.api.PCMBlackBoard;
import org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.api.ScenarioAnalysis;
import org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.helpers.AttributeProviderHandler;
import org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.output.creation.ResultEMFModelStorage;
import org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.visitors.CheckOperation;
import org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.visitors.SystemWalker;
import org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.visitors.UsageModelVisitorScenarioSystem;
import org.palladiosimulator.pcm.confidentiality.context.system.UsageSpecification;
import org.palladiosimulator.pcm.confidentiality.context.system.pcm.usage.PCMUsageSpecification;
import org.palladiosimulator.pcm.usagemodel.EntryLevelSystemCall;
import org.palladiosimulator.pcm.usagemodel.UsageScenario;

@Component
public class ScenarioAnalysisSystemImpl implements ScenarioAnalysis {

    @Override
    public AnalysisResults runScenarioAnalysis(final PCMBlackBoard pcm, final ConfidentialAccessSpecification context,
            final Configuration configuration) {

        final var eval = configuration.getEvaluate();

        final var usage = pcm.getUsageModel();
        final var result = new ResultEMFModelStorage();
        final var attributeHandler = new AttributeProviderHandler(context.getPcmspecificationcontainer()
            .getAttributeprovider());

        for (final var scenario : usage.getUsageScenario_UsageModel()) {
            result.addScenario(scenario, this.isMisusage(context, scenario));

            final var requestor = this.getRequestorContexts(context, scenario);

            final var visitor = new UsageModelVisitorScenarioSystem();
            final var systemCalls = visitor.doSwitch(scenario.getScenarioBehaviour_UsageScenario());

            for (final var systemCall : systemCalls) {
                final var tmpRequestor = this.getRequestorContexts(context, systemCall, requestor);
                final var checkOperation = new CheckOperation(pcm, context, result, scenario, configuration, eval);
                final var walker = new SystemWalker(checkOperation, attributeHandler);
                walker.propagationBySeff(systemCall, pcm.getSystem(), tmpRequestor);
            }

        }

        return result.getResultModel();

    }

    private List<? extends UsageSpecification> getRequestorContexts(final ConfidentialAccessSpecification access,
            final UsageScenario scenario) {
        return this.getSpecificationScenario(access, scenario)
            .toList();
    }

    private boolean isMisusage(final ConfidentialAccessSpecification access, final UsageScenario scenario) {
        return access.getPcmspecificationcontainer()
            .getMisusagescenario()
            .stream()
            .anyMatch(misusageDeclaration -> misusageDeclaration.getUsagescenario()
                .getId()
                .equals(scenario.getId()));
    }

    private Stream<? extends UsageSpecification> getSpecificationScenario(final ConfidentialAccessSpecification access,
            final EObject scenario) {
        return this.createPCMUsageSpecificationStream(access)
            .filter(e -> EcoreUtil.equals(e.getUsagescenario(), scenario));
    }

    private Stream<PCMUsageSpecification> createPCMUsageSpecificationStream(
            final ConfidentialAccessSpecification access) {
        return access.getPcmspecificationcontainer()
            .getUsagespecification()
            .stream()
            .filter(PCMUsageSpecification.class::isInstance)
            .map(PCMUsageSpecification.class::cast);

    }

    private List<? extends UsageSpecification> getRequestorContexts(final ConfidentialAccessSpecification access,
            final EntryLevelSystemCall systemCall, final List<? extends UsageSpecification> oldList) {

        final var usageList = this.createPCMUsageSpecificationStream(access)
            .filter(e -> EcoreUtil.equals(e.getEntrylevelsystemcall(), systemCall))
            .collect(Collectors.toList());
        return usageList.isEmpty() ? oldList : usageList;
    }

}
