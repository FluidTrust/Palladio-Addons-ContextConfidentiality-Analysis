package edu.kit.ipd.sdq.attacksurface.tests.evaluation.scalability;

import static org.junit.jupiter.api.Assertions.fail;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Locale;

import org.eclipse.emf.ecore.util.EcoreUtil;
import org.junit.jupiter.api.Test;
import org.palladiosimulator.pcm.confidentiality.attacker.helper.VulnerabilityHelper;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.AttackerFactory;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.AttackerSystemSpecificationContainer;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.PcmIntegrationFactory;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.VulnerabilitySystemIntegration;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;
import org.palladiosimulator.pcm.resourceenvironment.ResourceContainer;
import org.palladiosimulator.pcm.resourceenvironment.ResourceEnvironment;

import edu.kit.ipd.sdq.attacksurface.graph.PCMElementType;
import edu.kit.ipd.sdq.attacksurface.tests.evaluation.EvaluationTest;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;

public abstract class ScalabilityTests extends EvaluationTest {
    public static final int WARMUP = 0;
    public static final int REPEAT = 2;// 10;
    protected static final boolean RUN_COMPLETE_ANALYSIS = true; // TODO adapt to false for only
                                                                 // element prop. analysis
    protected static final int MAX_NUMBER_COMPLETE = 100;

    public ScalabilityTests() {
        this.PATH_REPOSITORY = "Scalability/scalability.repository";
        this.PATH_RESOURCES = "Scalability/scalability.resourceenvironment";
        this.PATH_ASSEMBLY = "Scalability/scalability.system";
        this.PATH_ALLOCATION = "Scalability/scalability.allocation";
        this.PATH_ATTACKER = "Scalability/scalability.attacker";
        this.PATH_CONTEXT = "Scalability/scalability.context";
        this.PATH_MODIFICATION = "Scalability/scalability.kamp4attackmodificationmarks";
    }

    @Test
    void run() {

        for (var i = 0; i < WARMUP; i++) {
            analysisTime();
        }
        VulnerabilityHelper.initializeVulnerabilityStorage(getBlackboardWrapper().getVulnerabilitySpecification());
        final var attacks = this.attacker.getSystemintegration();
        moveVulnerabilitiesIfNecessary(attacks);
        final var maximumNumberOfAdditions = RUN_COMPLETE_ANALYSIS ? getMaximumNumberOfAdditionsForFullAnalysis()
                : getMaximumNumberOfAdditions();
        for (var i = 10; i <= maximumNumberOfAdditions; i *= 10) {
            perform(this.environment, i, attacks);
            writeResults();
        }
        VulnerabilityHelper.resetMap();
    }

    // TODO enable for scalability test for maximum
    @Test
    void runMax() { // runs the test for aof the scalability evaluation
        for (var i = 0; i < WARMUP; i++) {
            analysisTime();
        }

        final var attacks = this.attacker.getSystemintegration();
        moveVulnerabilitiesIfNecessary(attacks);
        perform(this.environment, getMaximumRunValue(), attacks);
        writeResults();
    }

    protected abstract int getMaximumRunValue();

    protected abstract int getMaximumNumberOfAdditions();

    protected int getMaximumNumberOfAdditionsForFullAnalysis() {
        return MAX_NUMBER_COMPLETE;
    }

    private void writeResults() {
        var timeList = new ArrayList<Long>();

        for (var j = 0; j < REPEAT; j++) {
            timeList.add(analysisTime());
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
            var changes = RUN_COMPLETE_ANALYSIS
                    ? (CredentialChange) getBlackboardWrapper().getModificationMarkRepository()
                            .getChangePropagationSteps().get(0)
                    : getChanges();
            if(RUN_COMPLETE_ANALYSIS) {
            output.append(String.format(Locale.US, "%d,%d,%d\n", changes.getAttackpaths().size(),
                    Math.round(timeList.stream().mapToLong(Long::longValue).average().getAsDouble()),changes.getAttackpaths().size()
//                    Math.round(changes.getAttackpaths().stream().mapToInt(p -> p.getAttackpathelement().size())
//                            .average()
//                            .getAsDouble())
            /*
             * , toString(changes.getAttackpaths())
             */)); // TODO remove actual path output
            }
            else {
            output.append(String.format(Locale.US, "%d\n",
                    Math.round(timeList.stream().mapToLong(Long::longValue).average().getAsDouble())));
            }

        } catch (IOException e) {
            fail(e.getMessage());
        }
    }

    long analysisTime() {
//        resetAttackGraphAndChanges();
        setPathLengthFilter(getMaximumPathLength());
        var startTime = java.lang.System.currentTimeMillis();
        if (RUN_COMPLETE_ANALYSIS) {
            runAnalysis();
        } else {
            runEvaluationAnalysis();
        }
        return java.lang.System.currentTimeMillis() - startTime;
    }

    protected abstract void runEvaluationAnalysis();

    private void perform(ResourceEnvironment environment, int numberAddition,
            AttackerSystemSpecificationContainer attacks) {
        final var sizeMinOne = environment.getResourceContainer_ResourceEnvironment().size() - 1;
        final var origin = environment.getResourceContainer_ResourceEnvironment().get(sizeMinOne);
        var vulnerability = this.attacker.getVulnerabilites().getVulnerability().get(0);
        var newOrigin = origin;
        for (var i = 0; i < numberAddition; i++) {
            var integration = PcmIntegrationFactory.eINSTANCE.createVulnerabilitySystemIntegration();
            integration.setVulnerability(vulnerability);

            newOrigin = resourceAddOperation(environment, newOrigin, integration);
            attacks.getVulnerabilities().add(integration);

            getSurfaceAttacker().getFiltercriteria().clear();

            var startFilter = AttackerFactory.eINSTANCE.createStartElementFilterCriterion();
            var pcmElement = PcmIntegrationFactory.eINSTANCE.createResourceEnvironmentElement();
            pcmElement.setResourcecontainer(newOrigin);
            startFilter.getStartResources().add(pcmElement);

            getSurfaceAttacker().getFiltercriteria().add(startFilter);

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
