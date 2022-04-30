package edu.kit.ipd.sdq.attacksurface.graph;

/**
 * Interface for a content of a graph node.
 * 
 * @author ugnwq
 * @version 1.0
 * @param <T> - the contained element type
 */
public interface NodeContent<T> {
    /**
     * 
     * @return the contained node element
     */
    T getContainedElement();
    
    @Override
    int hashCode();
    
    @Override
    boolean equals(final Object other);
}
