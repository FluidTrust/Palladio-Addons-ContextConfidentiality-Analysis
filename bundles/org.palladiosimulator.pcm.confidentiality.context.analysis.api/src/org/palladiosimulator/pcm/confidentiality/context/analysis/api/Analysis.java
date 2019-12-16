package org.palladiosimulator.pcm.confidentiality.context.analysis.api;

import org.eclipse.emf.common.util.URI;
public interface Analysis {
    boolean testArchitecture(URI urlContext, URI... urlScenarios);

}
