package edu.kit.ipd.sdq.attacksurface.graph;

import java.util.Objects;

public abstract class CredentialsVulnearbilitiesSurface {
    private final String causeId; //TODO: Identifier
    private final boolean isCredential;
    
    /**
     * 
     * @param causeId the EMF id of the cause (vulnerability or usage specification)
     * @param isC if the element isC
     */
    protected CredentialsVulnearbilitiesSurface(final String causeId, final boolean isC) {
        this.causeId = causeId;
        this.isCredential = isC;
    }

    public String getCauseId() {
        return this.causeId;
    }

    public boolean isCredential() {
        return this.isCredential;
    }

    @Override
    public int hashCode() {
        return Objects.hash(causeId);
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
        return Objects.equals(causeId, other.causeId); //TODO EcoreEquals
    }

    @Override
    public String toString() {
        return "CredentialsVulnearbilitiesSurface [causeId= " + causeId + ", isC= " + isCredential + "]";
    }
}
