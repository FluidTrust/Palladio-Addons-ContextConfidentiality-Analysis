package edu.kit.ipd.sdq.attacksurface.graph;

import java.util.Objects;

public abstract class CVSurface {
    private final String causeId;
    private final boolean isC;
    
    /**
     * 
     * @param causeId the EMF id of the cause (vulnerability or usage specification)
     * @param isC if the element isC
     */
    protected CVSurface(final String causeId, final boolean isC) {
        this.causeId = causeId;
        this.isC = isC;
    }

    public String getCauseId() {
        return this.causeId;
    }

    public boolean isC() {
        return this.isC;
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
        CVSurface other = (CVSurface) obj;
        return Objects.equals(causeId, other.causeId);
    }
}
