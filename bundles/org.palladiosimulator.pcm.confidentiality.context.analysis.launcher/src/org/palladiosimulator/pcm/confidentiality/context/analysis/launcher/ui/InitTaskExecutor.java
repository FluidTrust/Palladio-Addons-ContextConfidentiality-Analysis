package org.palladiosimulator.pcm.confidentiality.context.analysis.launcher.ui;

import java.util.concurrent.atomic.AtomicBoolean;

public class InitTaskExecutor {

    private final AtomicBoolean initTaskRunning = new AtomicBoolean(false);

    public void runInitTask(final Runnable task) {
        synchronized (this.initTaskRunning) {
            this.initTaskRunning.set(true);
            try {
                task.run();
            } finally {
                this.initTaskRunning.set(false);
            }
        }
    }

    public boolean isInitTaskRunning() {
        synchronized (this.initTaskRunning) {
            return this.initTaskRunning.get();
        }
    }

}
