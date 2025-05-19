package com.threatmodel.analyzer.model;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Represents a data store in the system (database, file, cache, etc.)
 */
public class DataStore {
    private String id;
    private String name;
    private String description;
    private DataStoreType type;
    private List<String> dataStructureIds = new ArrayList<>();
    private Map<String, Object> metadata = new HashMap<>();
    
    public enum DataStoreType {
        DATABASE,
        FILE_SYSTEM,
        CACHE,
        MEMORY,
        CLOUD_STORAGE,
        OTHER
    }
    
    public DataStore(String id, String name) {
        this.id = id;
        this.name = name;
        this.type = DataStoreType.OTHER;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public DataStoreType getType() {
        return type;
    }

    public void setType(DataStoreType type) {
        this.type = type;
    }

    public List<String> getDataStructureIds() {
        return dataStructureIds;
    }

    public void addDataStructureId(String dataStructureId) {
        if (!dataStructureIds.contains(dataStructureId)) {
            this.dataStructureIds.add(dataStructureId);
        }
    }

    public Map<String, Object> getMetadata() {
        return metadata;
    }

    public void addMetadata(String key, Object value) {
        this.metadata.put(key, value);
    }
}
