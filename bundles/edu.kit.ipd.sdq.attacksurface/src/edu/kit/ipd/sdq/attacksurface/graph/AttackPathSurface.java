package edu.kit.ipd.sdq.attacksurface.graph;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import com.google.common.graph.EndpointPair;

public class AttackPathSurface implements Iterable<AttackStatusEdge> {
    //TODO adapt
    
    private final List<AttackStatusEdge> path; //TODO maybe adapt: use reversal edges here
    
    public AttackPathSurface() {
        this.path = new LinkedList<>();
    }
    
    public AttackPathSurface(final List<AttackStatusEdge> path) {
        this.path = new LinkedList<>(path);
    }
    
    public AttackStatusEdge get(final int index) {
        return this.path.get(index);
    }

    public int size() {
        return this.path.size();
    }
    
    public void addFirst(final AttackStatusEdge edge) {
        this.path.add(0, edge);
    }

    public void add(final AttackStatusEdge edge) {
        this.path.add(edge);
    }

    public boolean isEmpty() {
        return this.path.isEmpty();
    }
    
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
}
