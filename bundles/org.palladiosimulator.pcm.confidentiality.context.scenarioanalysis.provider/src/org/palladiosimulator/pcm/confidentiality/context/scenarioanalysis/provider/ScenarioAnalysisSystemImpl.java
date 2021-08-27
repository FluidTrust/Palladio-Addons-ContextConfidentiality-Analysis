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
            Configuration configuration) {

        var eval = configuration.getEvaluate();

        final var usage = pcm.getUsageModel();
        final var result = new ResultEMFModelStorage();

        for (final var scenario : usage.getUsageScenario_UsageModel()) {
            final var requestor = getRequestorContexts(context, scenario);

            final var visitor = new UsageModelVisitorScenarioSystem();
            final var systemCalls = visitor.doSwitch(scenario.getScenarioBehaviour_UsageScenario());

            for (final var systemCall : systemCalls) {
                final var tmpRequestor = getRequestorContexts(context, systemCall, requestor);
                final var checkOperation = new CheckOperation(pcm, context, result, scenario, configuration, eval);
                final var walker = new SystemWalker(checkOperation);
                walker.propagationBySeff(systemCall, pcm.getSystem(), tmpRequestor);
            }

            // set positiv return value if no error happened
            if (result.getResultModel().getScenariooutput().stream()
                    .noneMatch(e -> EcoreUtil.equals(e.getScenario(), scenario))) {
                result.storePositiveResult(scenario);
            }
            //            if (isMisusage(context, scenario)) {
            //                result.flip(scenario);
            //            }

        }

        return result.getResultModel();

    }

    private List<? extends UsageSpecification> getRequestorContexts(final ConfidentialAccessSpecification access,
            final UsageScenario scenario) {
        return getSpecificationScenario(access, scenario).collect(Collectors.toList());
    }

    //    private boolean isMisusage(final ConfidentialAccessSpecification access, final UsageScenario scenario) {
    //        final var scenarioSpecification = getSpecificationScenario(access, scenario).findAny();
    //        if (scenarioSpecification.isPresent()) {
    //            return scenarioSpecification.get().isMissageUse();
    //        }
    //        return false;
    //    }

    private Stream<? extends UsageSpecification> getSpecificationScenario(final ConfidentialAccessSpecification access,
            final EObject scenario) {
        return createPCMUsageSpecificationStream(access).filter(e -> EcoreUtil.equals(e.getUsagescenario(), scenario));
    }

    private Stream<PCMUsageSpecification> createPCMUsageSpecificationStream(
            final ConfidentialAccessSpecification access) {
        return access.getPcmspecificationcontainer().getUsagespecification().stream()
                .filter(PCMUsageSpecification.class::isInstance).map(PCMUsageSpecification.class::cast);

    }

    private List<? extends UsageSpecification> getRequestorContexts(final ConfidentialAccessSpecification access,
            final EntryLevelSystemCall systemCall, List<? extends UsageSpecification> oldList) {

        var usageList = createPCMUsageSpecificationStream(access)
                .filter(e -> EcoreUtil.equals(e.getEntrylevelsystemcall(), systemCall)).collect(Collectors.toList());
        return usageList.isEmpty() ? oldList : usageList;
    }

}
