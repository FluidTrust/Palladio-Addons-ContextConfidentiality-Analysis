package edu.kit.ipd.sdq.attacksurface.graph;

import java.util.Objects;

import de.uka.ipd.sdq.identifier.Identifier;

public abstract class CredentialsVulnearbilitiesSurface {
    private final Identifier cause; 
    private final boolean isCredential;
    
    /**
     * 
     * @param cause - the identifier
     * @param isC - if the element is a credential
     */
    protected CredentialsVulnearbilitiesSurface(final Identifier cause, final boolean isC) {
        this.cause = cause;
        this.isCredential = isC;
    }

    public Identifier getCause() {
        return this.cause;
    }

    public String getCauseId() {
        return this.cause.getId();
    }

    public boolean isCredential() {
        return this.isCredential;
    }

    @Override
    public int hashCode() {
        return Objects.hash(cause.getId());
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        CredentialsVulnearbilitiesSurface other = (CredentialsVulnearbilitiesSurface) obj;
        return Objects.equals(cause.getId(), other.cause.getId());
    }

    @Override
    public String toString() {
        return "CredentialsVulnearbilitiesSurface [causeId= " + cause.getId() + ", isC= " + isCredential + "]";
    }
}
