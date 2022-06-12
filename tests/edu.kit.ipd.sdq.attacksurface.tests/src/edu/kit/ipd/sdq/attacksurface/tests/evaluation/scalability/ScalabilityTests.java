package edu.kit.ipd.sdq.attacksurface.tests.evaluation.scalability;

import static org.junit.Assert.fail;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Locale;

import org.eclipse.emf.ecore.util.EcoreUtil;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.palladiosimulator.pcm.confidentiality.attacker.helper.VulnerabilityHelper;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.AttackerSystemSpecificationContainer;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.PcmIntegrationFactory;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.VulnerabilitySystemIntegration;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;
import org.palladiosimulator.pcm.resourceenvironment.ResourceContainer;
import org.palladiosimulator.pcm.resourceenvironment.ResourceEnvironment;

import edu.kit.ipd.sdq.attacksurface.graph.PCMElementType;
import edu.kit.ipd.sdq.attacksurface.tests.evaluation.EvaluationTest;
//TODO
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;

public abstract class ScalabilityTests extends EvaluationTest {
    public static final int WARMUP = 2;
    public static final int REPEAT = 2;//10;
    protected static final boolean RUN_COMPLETE_ANALYSIS = true; //TODO adapt to false for only element prop. analysis
    protected static final int MAX_NUMBER_COMPLETE = 7;

    public ScalabilityTests() {
        this.PATH_REPOSITORY = "Scalability/scalability.repository";
        this.PATH_RESOURCES = "Scalability/scalability.resourceenvironment";
        this.PATH_ASSEMBLY = "Scalability/scalability.system";
        this.PATH_ALLOCATION = "Scalability/scalability.allocation";
        this.PATH_ATTACKER = "Scalability/scalability.attacker";
        this.PATH_CONTEXT = "Scalability/scalability.context";
        this.PATH_MODIFICATION = "Scalability/scalability.kamp4attackmodificationmarks";
    }

    @Disabled //TODO enable for scalability tests
    @Test
    void run() {
        for (var i = 0; i < WARMUP; i++) {
            analysisTime();
        }

        final var attacks = this.attacker.getSystemintegration();
        moveVulnerabilitiesIfNecessary(attacks);
        final var maximumNumberOfAdditions = RUN_COMPLETE_ANALYSIS ?
                getMaximumNumberOfAdditionsForFullAnalysis() : getMaximumNumberOfAdditions();
        for (var i = 0; i < maximumNumberOfAdditions; i++) {
            perform(this.environment, 1, attacks);
            writeResults();
        }
    }

    @Disabled //TODO enable for scalability test for maximum
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
                    ? (CredentialChange) getBlackboardWrapper().getModificationMarkRepository().getChangePropagationSteps().get(0)
                    : getChanges();
            output.append(String.format(Locale.US, "%d,%d,%d\n", changes.getAttackpaths().size(),
                    Math.round(timeList.stream().mapToLong(Long::longValue).average().getAsDouble()),
                    Math.round(changes.getAttackpaths()
                        .stream()
                        .mapToInt(p -> p.getPath().size())
                        .average().getAsDouble())/*,
                    toString(changes.getAttackpaths())*/)); //TODO remove actual path output

        } catch (IOException e) {
            fail(e.getMessage());
        }
    }

    long analysisTime() {
        resetAttackGraphAndChanges();
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
        }
    }

    protected abstract void moveVulnerabilitiesIfNecessary(AttackerSystemSpecificationContainer attacks);

    protected void moveVulnerabilities(final AttackerSystemSpecificationContainer attacks,
            final AssemblyContext assemblyInOrigin,
            final ResourceContainer origin) {
        var vulnerability = VulnerabilityHelper.getVulnerabilities(attacks, assemblyInOrigin).get(0);
        final var sysInteg = attacks.getVulnerabilities()
                .stream()
                .filter(s -> PCMElementType.typeOf(s.getPcmelement()).getEntity(s.getPcmelement()).getId().equals(assemblyInOrigin.getId()))
                .filter(s -> EcoreUtil.equals(vulnerability, s.getIdOfContent()))
                .findFirst().orElse(null);
        sysInteg.getPcmelement().getAssemblycontext().clear();
        sysInteg.getPcmelement().setResourcecontainer(origin);

        //set resource container as critical element and move vulnerability there too
        final var root = getAttackGraph().getRootNodeContent().getContainedElementAsPCMElement().getAssemblycontext();
        final var sysIntegRoot = attacks.getVulnerabilities()
                .stream()
                .filter(s -> PCMElementType.typeOf(s.getPcmelement()).getEntity(s.getPcmelement()).getId()
                        .equals(root.get(0).getId()))
                .filter(s -> EcoreUtil.equals(vulnerability, s.getIdOfContent()))
                .findFirst().orElse(null);
        sysIntegRoot.getPcmelement().getAssemblycontext().clear();
        sysIntegRoot.getPcmelement().setResourcecontainer(getResource(root));

        setCriticalResourceContainer(getResource(root).getEntityName());
    }

    protected abstract ResourceContainer resourceAddOperation(ResourceEnvironment environment, ResourceContainer origin,
            VulnerabilitySystemIntegration integration);

    protected abstract String getFilename();

    protected abstract int getMaximumPathLength();

}
