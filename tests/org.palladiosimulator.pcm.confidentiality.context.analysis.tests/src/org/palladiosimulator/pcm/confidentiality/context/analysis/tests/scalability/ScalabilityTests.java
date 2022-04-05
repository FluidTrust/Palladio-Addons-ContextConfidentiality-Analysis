package org.palladiosimulator.pcm.confidentiality.context.analysis.tests.scalability;

import static org.junit.Assert.fail;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.palladiosimulator.pcm.confidentiality.context.analysis.tests.base.casestudies.ScalabilityBaseTest;
import org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.api.Configuration;
import org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.api.PCMBlackBoard;
import org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.provider.ScenarioAnalysisSystemImpl;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;

public abstract class ScalabilityTests extends ScalabilityBaseTest {
    public static final int WARMUP = 0;
    public static final int REPEAT = 1;

    @BeforeEach
    void initLocal() {
        this.blackBoard = new PCMBlackBoard(this.assembly, this.repo, this.usage);
        this.analysis = new ScenarioAnalysisSystemImpl();
        this.configuration = new Configuration(false, this.eval);
    }

    @Disabled
    @Test
    void warmup() {
        runAnalysis();
    }

    @Disabled
    @Test
    void run() {
        generateXML();
        for (var i = 0; i < WARMUP; i++) {
            runAnalysis();
        }

//        for (var i = 0; i < 1; i++) {
//            perform(this.environment, 1000, this.attacker.getSystemintegration());
//
//            var timeList = new ArrayList<Long>();
//
//            for (var j = 0; j < REPEAT; j++) {
//                timeList.add(analysisTime());
//            }
//
//            try (var output = Files.newBufferedWriter(Paths.get(System.getProperty("java.io.tmpdir"), getFilename()),
//                    StandardOpenOption.APPEND);) {
//                var credential = (CredentialChange) getBlackboardWrapper().getModificationMarkRepository()
//                        .getChangePropagationSteps().get(0);
//                output.append(String.format("%d,%d\n", credential.getCompromisedresource().size(),
//                        Math.round(timeList.stream().mapToLong(Long::longValue).average().getAsDouble())));
//
//            } catch (IOException e) {
//                fail(e.getMessage());
//            }
//
//        }
        perform(10);
        writeResults();
        perform(90);
        writeResults();
        perform(900);
        writeResults();
        perform(9000);
        writeResults();
        perform(90000);
        writeResults();
    }

    private void writeResults() {
        var timeList = new ArrayList<Long>();

        for (var j = 0; j < REPEAT; j++) {
            timeList.add(analysisTime());
        }

        try (var output = Files.newBufferedWriter(Paths.get(System.getProperty("java.io.tmpdir"), getFilename()),
                StandardOpenOption.APPEND);) {
            output.append(String.format("%d,%d\n",
                    this.blackBoard.getSystem().getAssemblyContexts__ComposedStructure().size(),
                    Math.round(timeList.stream().mapToLong(Long::longValue).average().getAsDouble())));

        } catch (IOException e) {
            fail(e.getMessage());
        }
    }

    long analysisTime() {
        var startTime = java.lang.System.currentTimeMillis();
        runAnalysis();
        return java.lang.System.currentTimeMillis() - startTime;
    }

    private void perform(int numberAddition) {
        var origin = this.blackBoard.getSystem().getAssemblyContexts__ComposedStructure()
                .get(this.blackBoard.getSystem().getAssemblyContexts__ComposedStructure().size() - 1);
        for (var i = 0; i < numberAddition; i++) {
            origin = resourceAddOperation(this.blackBoard.getSystem(), origin);
        }
    }

    protected abstract AssemblyContext resourceAddOperation(org.palladiosimulator.pcm.system.System system,
            AssemblyContext context);

    protected abstract String getFilename();

    private void runAnalysis() {

        final var output = this.analysis.runScenarioAnalysis(this.blackBoard, this.context, this.configuration);
    }

}
