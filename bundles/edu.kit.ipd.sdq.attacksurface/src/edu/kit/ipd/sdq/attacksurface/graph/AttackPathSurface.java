package edu.kit.ipd.sdq.attacksurface.graph;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import java.util.stream.Stream;

/**
 * Represents an attack path in an {@link AttackGraph}.
 * 
 * @author ugnwq
 * @version 1.0
 */
public class AttackPathSurface implements Iterable<AttackStatusEdge> {
    //TODO adapt
    
    private final List<AttackStatusEdge> path; //TODO maybe adapt: use reversal edges here
    
    /**
     * Creates a new empty {@link AttackPathSurface}.
     */
    public AttackPathSurface() {
        this.path = new LinkedList<>();
    }
    
    /**
     * Creates a new {@link AttackPathSurface} with a copy of the given list as an initial path.
     * 
     * @param path - the path as a list of {@link AttackStatusEdge}
     */
    public AttackPathSurface(final List<AttackStatusEdge> path) {
        this.path = new LinkedList<>(path);
    }
    
    /**
     * Gets the {@link AttackStatusEdge} at the given index.
     * 
     * @param index - the given index
     * @return the edge at the index
     */
    public AttackStatusEdge get(final int index) {
        return this.path.get(index);
    }

    /**
     * 
     * @return the size of the path edge list, i.e. the count of edges
     */
    public int size() {
        return this.path.size();
    }
    
    /**
     * Adds the edge at the beginning of the path.
     * 
     * @param edge - the edge to be added
     */
    public void addFirst(final AttackStatusEdge edge) {
        this.path.add(0, edge);
    }

    /**
     * Adds the edge at the end of the path.
     * 
     * @param edge - the edge to be added
     */
    public void add(final AttackStatusEdge edge) {
        this.path.add(edge);
    }

    /**
     * 
     * @return whether the path is empty
     */
    public boolean isEmpty() {
        return this.path.isEmpty();
    }
    
    /**
     * 
     * @return a copy of the path (only the list is copied, not the edges)
     */
    public AttackPathSurface getCopy() {
        return new AttackPathSurface(new ArrayList<>(this.path));
    }

    @Override
    public Iterator<AttackStatusEdge> iterator() {
        return Collections.unmodifiableList(this.path).iterator();
    }

    @Override
    public int hashCode() {
        return Objects.hash(path);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        AttackPathSurface other = (AttackPathSurface) obj;
        return Objects.equals(path, other.path);
    }

    @Override
    public String toString() {
        return "AttackPathSurface [path=" + path + "]";
    }

    public AttackPathSurface remove(int index) {
        this.path.remove(index);
        return this;
    }

    public Stream<AttackStatusEdge> stream() {
        return this.path.stream();
    }
}
