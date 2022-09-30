package edu.kit.ipd.sdq.attacksurface.tests.evaluation.scalability;

import static org.junit.jupiter.api.Assertions.fail;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import org.eclipse.emf.ecore.util.EcoreUtil;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.palladiosimulator.pcm.confidentiality.attacker.helper.VulnerabilityHelper;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.AttackerFactory;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.AttackerSystemSpecificationContainer;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.PcmIntegrationFactory;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.VulnerabilitySystemIntegration;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;
import org.palladiosimulator.pcm.core.entity.Entity;
import org.palladiosimulator.pcm.resourceenvironment.ResourceContainer;
import org.palladiosimulator.pcm.resourceenvironment.ResourceEnvironment;

import edu.kit.ipd.sdq.attacksurface.core.AttackHandlingHelper;
import edu.kit.ipd.sdq.attacksurface.core.AttackPathCreation;
import edu.kit.ipd.sdq.attacksurface.graph.AttackGraphCreation;
import edu.kit.ipd.sdq.attacksurface.graph.PCMElementType;
import edu.kit.ipd.sdq.attacksurface.tests.evaluation.EvaluationTest;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksFactory;

public abstract class ScalabilityTests extends EvaluationTest {
    public static final int WARMUP = 0;
    public static final int REPEAT = 5;// 10;
    protected static final boolean RUN_ONLY_GRAPH_ANALYSIS = true; // TODO adapt to false for only
                                                                    // element prop. analysis
    protected static final int MAX_NUMBER_COMPLETE = 10;

    public ScalabilityTests() {
        this.PATH_REPOSITORY = "Scalability/scalability.repository";
        this.PATH_RESOURCES = "Scalability/scalability.resourceenvironment";
        this.PATH_ASSEMBLY = "Scalability/scalability.system";
        this.PATH_ALLOCATION = "Scalability/scalability.allocation";
        this.PATH_ATTACKER = "Scalability/scalability.attacker";
        this.PATH_CONTEXT = "Scalability/scalability.context";
        this.PATH_MODIFICATION = "Scalability/scalability.kamp4attackmodificationmarks";
    }

    @Disabled
    @Test
    void run() {

        for (var i = 0; i < WARMUP; i++) {
            analysisTime(null);
        }
        VulnerabilityHelper.initializeVulnerabilityStorage(getBlackboardWrapper().getVulnerabilitySpecification());
        final var attacks = this.attacker.getSystemintegration();
        moveVulnerabilitiesIfNecessary(attacks);
        final var maximumNumberOfAdditions = RUN_ONLY_GRAPH_ANALYSIS ? getMaximumNumberOfAdditionsForFullAnalysis()
                : getMaximumNumberOfAdditions();
        for (var i = 10; i <= maximumNumberOfAdditions; i *= 10) {
            perform(this.environment, i, attacks);
            writeResults(i);
        }
        VulnerabilityHelper.resetMap();
    }

    // TODO enable for scalability test for maximum

    @Disabled
    @Test
    void runMax() { // runs the test for aof the scalability evaluation
        for (var i = 0; i < WARMUP; i++) {
            analysisTime(null);
        }

        VulnerabilityHelper.initializeVulnerabilityStorage(getBlackboardWrapper().getVulnerabilitySpecification());
        final var attacks = this.attacker.getSystemintegration();
        moveVulnerabilitiesIfNecessary(attacks);
        perform(this.environment, 100000, attacks);
        writeResults();
        VulnerabilityHelper.resetMap();

    }

    protected abstract int getMaximumRunValue();

    protected abstract int getMaximumNumberOfAdditions();

    protected int getMaximumNumberOfAdditionsForFullAnalysis() {
        return MAX_NUMBER_COMPLETE;
    }

    private void writeResults() {
        writeResults(0);
    }

    private void writeResults(int i) {
        var timeList = new ArrayList<Long>();

        for (var j = 0; j < REPEAT; j++) {
            analysisTime(timeList);
        }

        var path = Paths.get(System.getProperty("java.io.tmpdir"), getFilename());
        if (!Files.exists(path)) {
            try {
                path = Files.createFile(path);
            } catch (IOException e) {
                fail(e.getMessage());
            }
        }

        try (var output = Files.newBufferedWriter(path, StandardOpenOption.APPEND);) {
            var changes = !RUN_ONLY_GRAPH_ANALYSIS
                    ? (CredentialChange) getBlackboardWrapper().getModificationMarkRepository()
                            .getChangePropagationSteps().get(0)
                    : getChanges();
            if (RUN_ONLY_GRAPH_ANALYSIS) {
                output.append(String.format(Locale.US, "%d,%d\n", i,
                        Math.round(timeList.stream().mapToLong(Long::longValue).average().getAsDouble())
//                    Math.round(changes.getAttackpaths().stream().mapToInt(p -> p.getAttackpathelement().size())
//                            .average()
//                            .getAsDouble())

                /*
                 * , toString(changes.getAttackpaths())
                 */)); // TODO remove actual path output
            } else {
                output.append(
                        String.format(Locale.US, "%d,%d,%d,%d\n", i,
                                Math.round(timeList.stream().mapToLong(Long::longValue).average().getAsDouble()),
                                getBlackboardWrapper().getResourceEnvironment()
                                        .getResourceContainer_ResourceEnvironment().size(),
                                changes.getAttackpaths().get(0).getAttackpathelement().size()));
            }

        } catch (IOException e) {
            fail(e.getMessage());
        }
    }

    void analysisTime(List<Long> list) {
//        resetAttackGraphAndChanges();
//        setPathLengthFilter(getMaximumPathLength());
        for (var i = 0; i < REPEAT; i++) {
            var startTime = 0L;
            var endTime = 0L;
            if (RUN_ONLY_GRAPH_ANALYSIS) {
                startTime = java.lang.System.currentTimeMillis();
                endTime = runGraphCreation();
            } else {
                var graph = createGraph();
                startTime = System.currentTimeMillis();

                endTime = runFullAnalysis(graph);
            }
            VulnerabilityHelper.resetMap();
            resetHashMaps();
            if (list != null) {
                list.add(endTime - startTime);
            }
        }
    }

    protected long runGraphCreation() {
        createGraph();
        VulnerabilityHelper.resetMap();
        return System.currentTimeMillis();

    }

    private AttackGraphCreation createGraph() {
        VulnerabilityHelper.initializeVulnerabilityStorage(getBlackboardWrapper().getVulnerabilitySpecification());
        var graph = new AttackGraphCreation(getBlackboardWrapper());
        graph.createGraph();
        return graph;
    }

    protected long runFullAnalysis(AttackGraphCreation graph) {
        getSurfaceAttacker().getFiltercriteria().clear();
        var startFilter = AttackerFactory.eINSTANCE.createStartElementFilterCriterion();
        var pcmElement = PcmIntegrationFactory.eINSTANCE.createResourceEnvironmentElement();
        pcmElement.setResourcecontainer(getBlackboardWrapper().getResourceEnvironment()
                .getResourceContainer_ResourceEnvironment()
                .get(getBlackboardWrapper().getResourceEnvironment().getResourceContainer_ResourceEnvironment().size()
                        - 1));
        startFilter.getStartResources().add(pcmElement);

        getSurfaceAttacker().getFiltercriteria().add(startFilter);


        var target = prepareAnalysis();
        (new AttackPathCreation(target,
                getBlackboardWrapper().getModificationMarkRepository().getChangePropagationSteps().get(0)))
                        .createAttackPaths(getBlackboardWrapper(), graph.getGraph());

        return System.currentTimeMillis();
    }

    private Entity prepareAnalysis() {
        var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();
        getBlackboardWrapper().getModificationMarkRepository().getChangePropagationSteps().clear();
        getBlackboardWrapper().getModificationMarkRepository().getChangePropagationSteps().add(change);
        final var localAttacker = AttackHandlingHelper.getSurfaceAttacker(getBlackboardWrapper());
        final var criticalPCMElement = localAttacker.getTargetedElement();
        return PCMElementType.typeOf(criticalPCMElement).getEntity(criticalPCMElement);
    }

    private void perform(ResourceEnvironment environment, int numberAddition,
            AttackerSystemSpecificationContainer attacks) {
        final var sizeMinOne = environment.getResourceContainer_ResourceEnvironment().size() - 1;
        final var origin = environment.getResourceContainer_ResourceEnvironment().get(sizeMinOne);
        var vulnerability = this.attacker.getVulnerabilites().getVulnerability().get(0);
        var newOrigin = origin;
        for (var i = getBlackboardWrapper().getResourceEnvironment().getResourceContainer_ResourceEnvironment()
                .size(); i < numberAddition; i++) {
            var integration = PcmIntegrationFactory.eINSTANCE.createVulnerabilitySystemIntegration();
            integration.setVulnerability(vulnerability);

            newOrigin = resourceAddOperation(environment, newOrigin, integration);
            attacks.getVulnerabilities().add(integration);

        }

    }

    protected abstract void moveVulnerabilitiesIfNecessary(AttackerSystemSpecificationContainer attacks);

    protected void moveVulnerabilities(final AttackerSystemSpecificationContainer attacks,
            final AssemblyContext assemblyInOrigin, final ResourceContainer origin) {
        var vulnerability = VulnerabilityHelper.getVulnerabilities(attacks, assemblyInOrigin).get(0);
        final var sysInteg = attacks.getVulnerabilities().stream()
                .filter(s -> PCMElementType.typeOf(s.getPcmelement()).getEntity(s.getPcmelement()).getId()
                        .equals(assemblyInOrigin.getId()))
                .filter(s -> EcoreUtil.equals(vulnerability, s.getIdOfContent())).findFirst().orElse(null);
        sysInteg.getPcmelement().getAssemblycontext().clear();
        sysInteg.getPcmelement().setResourcecontainer(origin);

        // set resource container as critical element and move vulnerability there too
        final var root = getSurfaceAttacker().getTargetedElement().getAssemblycontext();
        final var sysIntegRoot = attacks.getVulnerabilities().stream()
                .filter(s -> PCMElementType.typeOf(s.getPcmelement()).getEntity(s.getPcmelement()).getId()
                        .equals(root.get(0).getId()))
                .filter(s -> EcoreUtil.equals(vulnerability, s.getIdOfContent())).findFirst().orElse(null);
        sysIntegRoot.getPcmelement().getAssemblycontext().clear();
        sysIntegRoot.getPcmelement().setResourcecontainer(getResource(root));

        setCriticalResourceContainer(getResource(root).getEntityName());
    }

    protected abstract ResourceContainer resourceAddOperation(ResourceEnvironment environment, ResourceContainer origin,
            VulnerabilitySystemIntegration integration);

    protected abstract String getFilename();

    protected abstract int getMaximumPathLength();

}
