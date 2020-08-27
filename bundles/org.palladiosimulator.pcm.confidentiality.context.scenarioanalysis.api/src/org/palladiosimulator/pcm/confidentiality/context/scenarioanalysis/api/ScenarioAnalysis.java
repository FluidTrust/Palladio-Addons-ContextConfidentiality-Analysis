package org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.api;

import org.palladiosimulator.pcm.confidentiality.context.ConfidentialAccessSpecification;
import org.palladiosimulator.pcm.confidentiality.context.analysis.api.ContextAnalysis;
import org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.AnalysisResults;
import org.palladiosimulator.pcm.repository.Repository;
import org.palladiosimulator.pcm.usagemodel.UsageModel;
public interface ScenarioAnalysis extends ContextAnalysis {
    AnalysisResults runScenarioAnalysis(Repository pcm, ConfidentialAccessSpecification context, UsageModel usage);

}
