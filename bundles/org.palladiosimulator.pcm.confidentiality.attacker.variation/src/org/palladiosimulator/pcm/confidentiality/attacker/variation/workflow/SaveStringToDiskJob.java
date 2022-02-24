package org.palladiosimulator.pcm.confidentiality.attacker.variation.workflow;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.util.Objects;

import org.eclipse.core.runtime.IProgressMonitor;
import org.palladiosimulator.dataflow.confidentiality.transformation.workflow.blackboards.KeyValueMDSDBlackboard;

import de.uka.ipd.sdq.workflow.jobs.AbstractBlackboardInteractingJob;
import de.uka.ipd.sdq.workflow.jobs.CleanupFailedException;
import de.uka.ipd.sdq.workflow.jobs.JobFailedException;
import de.uka.ipd.sdq.workflow.jobs.UserCanceledException;

public class SaveStringToDiskJob extends AbstractBlackboardInteractingJob<KeyValueMDSDBlackboard> {
    private final File file;
    private final String ID;

    public SaveStringToDiskJob(final File file, final String ID) {
        Objects.requireNonNull(file);
        Objects.requireNonNull(ID);
        this.file = file;
        this.ID = ID;
    }

    @Override
    public void execute(final IProgressMonitor monitor) throws JobFailedException, UserCanceledException {
        monitor.beginTask("Saving to Disk", 1);
        if (!this.getBlackboard().get(this.ID).isPresent()) {
            throw new JobFailedException("No string value to save present");
        }
        if (!(this.getBlackboard().get(this.ID).get() instanceof String)) {
            throw new JobFailedException("Value is not of expected type String");
        }
        final var stringValue = (String) this.getBlackboard().get(this.ID).get();
        try {
            Files.writeString(this.file.toPath(), stringValue, StandardOpenOption.CREATE);
        } catch (final IOException e) {
            throw new JobFailedException("Saving value as file failed", e);
        }
        monitor.worked(1);

    }

    @Override
    public void cleanup(final IProgressMonitor monitor) throws CleanupFailedException {
        // TODO Auto-generated method stub

    }

    @Override
    public String getName() {
        // TODO Auto-generated method stub
        return "Save String to disk";
    }

}
