package com.threatmodel.analyzer.model;

import java.util.HashMap;
import java.util.Map;

/**
 * Represents a field within a data structure
 */
public class DataField {
    private String name;
    private String type;
    private String description;
    private Map<String, String> annotations = new HashMap<>();
    private boolean isPrimitive;
    private boolean isCollection;
    private boolean isSensitive;
    
    public DataField(String name, String type) {
        this.name = name;
        this.type = type;
        this.isPrimitive = false;
        this.isCollection = false;
        this.isSensitive = false;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public Map<String, String> getAnnotations() {
        return annotations;
    }

    public void addAnnotation(String name, String value) {
        this.annotations.put(name, value);
    }

    public boolean isPrimitive() {
        return isPrimitive;
    }

    public void setPrimitive(boolean isPrimitive) {
        this.isPrimitive = isPrimitive;
    }

    public boolean isCollection() {
        return isCollection;
    }

    public void setCollection(boolean isCollection) {
        this.isCollection = isCollection;
    }

    public boolean isSensitive() {
        return isSensitive;
    }

    public void setSensitive(boolean isSensitive) {
        this.isSensitive = isSensitive;
    }
    
    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(name).append(": ").append(type);
        if (isCollection) sb.append(" [Collection]");
        if (isSensitive) sb.append(" [Sensitive]");
        return sb.toString();
    }
}
