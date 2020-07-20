package org.palladiosimulator.pcm.confidentiality.context.analysis.ui.handlers;



import org.eclipse.core.commands.AbstractHandler;
import org.eclipse.core.commands.ExecutionEvent;
import org.eclipse.core.commands.ExecutionException;
import org.eclipse.core.runtime.Platform;
import org.eclipse.e4.core.services.log.Logger;
import org.eclipse.emf.common.util.URI;
import org.eclipse.ui.PlatformUI;
import org.palladiosimulator.pcm.confidentiality.context.analysis.ui.Activator;


/**
 * 
 * 
 * @author Maximilian Walter
 * @version 1.0
 */
public class MainHandler extends AbstractHandler {
    public static final boolean IS_ECLIPSE_RUNNING = Platform.isRunning();
    
    public static final Logger LOGGER = PlatformUI.getWorkbench().getService(Logger.class);
    @Override
    public Object execute(ExecutionEvent event) throws ExecutionException {
        //URI.createFileURI(path)
        var analysis = Activator.getInstance().getAnalysis();
        var usagePath = new URI[1];
        usagePath[0] = URI.createFileURI("/home/majuwa/workspaces/control_running/Example/newUsageModel.usagemodel");
        var contextPath = URI.createFileURI("/home/majuwa/workspaces/control_running/Example/My.context");
        analysis.testArchitecture(contextPath, usagePath);
        LOGGER.info("test");
        return null;
    }
}
