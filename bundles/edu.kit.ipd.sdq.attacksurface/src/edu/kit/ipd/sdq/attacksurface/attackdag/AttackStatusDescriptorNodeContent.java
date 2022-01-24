package edu.kit.ipd.sdq.attacksurface.attackdag;

import java.util.Objects;

import org.palladiosimulator.pcm.core.composition.AssemblyContext;

/**
 * Represents a {@link NodeContent} containing the attack status for an element.
 * TODO: at the moment only for {@link AssemblyContext}s.
 * 
 * @author ugnwq
 * @version 1.0
 */
public class AttackStatusDescriptorNodeContent implements NodeContent {
    private final AssemblyContext containedAssembly; // TODO adapt ++ this is the (critical) element (see also core main class
    
    //compromisation status
    private boolean compromised; //TODO at the moment takeover == compromised
    //TODO private boolean takeOver;
    
    public AttackStatusDescriptorNodeContent(final AssemblyContext containedAssembly) {
        this.containedAssembly = Objects.requireNonNull(containedAssembly);
    }

    public AssemblyContext getContainedAssembly() {
        return this.containedAssembly;
    }
    
    public boolean isCompromised() {
        return this.compromised;
    }

    public void setCompromised(final boolean compromised) {
        this.compromised = compromised;
    }

    @Override
    public int hashCode() {
        return Objects.hash(this.containedAssembly.getId());
    }
    
    @Override
    public boolean equals(final Object other) {
        if (this == other) {
            return true;
        }
        if (other == null) {
            return false;
        }
        if (other instanceof AttackStatusDescriptorNodeContent) {
            final AttackStatusDescriptorNodeContent otherContent = (AttackStatusDescriptorNodeContent)other;
            return otherContent.containedAssembly.getId().equals(this.containedAssembly.getId());
        }
        return false;
    }
}
