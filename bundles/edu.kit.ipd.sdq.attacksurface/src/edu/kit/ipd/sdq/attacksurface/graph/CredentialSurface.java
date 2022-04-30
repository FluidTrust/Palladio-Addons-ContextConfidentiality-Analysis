package edu.kit.ipd.sdq.attacksurface.graph;

import de.uka.ipd.sdq.identifier.Identifier;

public class CredentialSurface extends CredentialsVulnearbilitiesSurface {
    public CredentialSurface(Identifier cause) {
        super(cause, true);
    }
}
