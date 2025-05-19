package com.threatmodel.analyzer.output;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.threatmodel.analyzer.model.AnalysisResult;
import com.threatmodel.analyzer.model.DataFlow;
import com.threatmodel.analyzer.model.DataStore;
import com.threatmodel.analyzer.model.DataStructure;
import com.threatmodel.analyzer.model.ExternalEntity;
import com.threatmodel.analyzer.model.Process;

/**
 * Class for generating Data Flow Diagrams (DFDs) from analysis results
 */
public class DFDGenerator {
    private static final Logger logger = LoggerFactory.getLogger(DFDGenerator.class);
    
    private final AnalysisResult result;
    private final Path outputPath;
    
    public DFDGenerator(AnalysisResult result, Path outputPath) {
        this.result = result;
        this.outputPath = outputPath;
    }
    
    /**
     * Generates DFD files
     */
    public void generate() throws IOException {
        // Create output directory if it doesn't exist
        if (!Files.exists(outputPath)) {
            Files.createDirectories(outputPath);
        }
        
        // Generate DOT file for GraphViz
        generateDotFile();
        
        // Generate Mermaid diagram
        generateMermaidDiagram();
        
        logger.info("DFD files generated at: {}", outputPath);
    }
    
    /**
     * Generates a DOT file for GraphViz
     */
    private void generateDotFile() throws IOException {
        Path dotFile = outputPath.resolve("data-flow-diagram.dot");
        
        StringBuilder dot = new StringBuilder();
        dot.append("digraph \"").append(result.getProjectName()).append("\" {\n");
        dot.append("  rankdir=LR;\n");
        dot.append("  node [shape=box, style=\"rounded,filled\", fontname=\"Arial\"];\n");
        dot.append("  edge [fontname=\"Arial\"];\n\n");
        
        // Generate nodes for external entities
        dot.append("  /* External Entities */\n");
        for (ExternalEntity entity : result.getExternalEntities()) {
            String entityId = sanitizeId(entity.getName());
            dot.append("  ").append(entityId)
               .append(" [label=\"").append(entity.getName()).append("\", ")
               .append("shape=rectangle, fillcolor=lightblue];\n");
        }
        dot.append("\n");
        
        // Generate nodes for processes
        dot.append("  /* Processes */\n");
        for (Process process : result.getProcesses()) {
            String processId = sanitizeId(process.getId());
            dot.append("  ").append(processId)
               .append(" [label=\"").append(process.getName()).append("\", ")
               .append("shape=ellipse, fillcolor=lightgreen];\n");
        }
        dot.append("\n");
        
        // Generate nodes for data stores
        dot.append("  /* Data Stores */\n");
        for (DataStore store : result.getDataStores()) {
            String storeId = sanitizeId(store.getId());
            dot.append("  ").append(storeId)
               .append(" [label=\"").append(store.getName()).append("\", ")
               .append("shape=cylinder, fillcolor=lightyellow];\n");
        }
        dot.append("\n");
        
        // Generate edges for data flows
        dot.append("  /* Data Flows */\n");
        Map<String, Integer> edgeCounts = new HashMap<>();
        
        for (DataFlow flow : result.getDataFlows()) {
            String sourceId = sanitizeId(flow.getSourceId());
            String destId = sanitizeId(flow.getDestinationId());
            
            // Create a unique key for this edge
            String edgeKey = sourceId + "->" + destId;
            int edgeCount = edgeCounts.getOrDefault(edgeKey, 0);
            edgeCounts.put(edgeKey, edgeCount + 1);
            
            // Find the data structure for the label
            String dataStructureName = flow.getDataStructureId();
            for (DataStructure ds : result.getDataStructures()) {
                if (ds.getFullyQualifiedName().equals(flow.getDataStructureId())) {
                    dataStructureName = ds.getName();
                    break;
                }
            }
            
            // Create the edge
            dot.append("  ").append(sourceId).append(" -> ").append(destId);
            
            StringBuilder labelBuilder = new StringBuilder();
            labelBuilder.append(dataStructureName);
            
            if (flow.getProtocol() != null && !flow.getProtocol().isEmpty()) {
                labelBuilder.append("\\n(").append(flow.getProtocol()).append(")");
            }
            
            // Add additional attributes
            dot.append(" [label=\"").append(labelBuilder.toString()).append("\"");
            
            // Style based on flow type
            switch (flow.getType()) {
                case INPUT:
                    dot.append(", color=blue");
                    break;
                case OUTPUT:
                    dot.append(", color=green");
                    break;
                case DATABASE_READ:
                    dot.append(", color=purple, style=dashed");
                    break;
                case DATABASE_WRITE:
                    dot.append(", color=red, style=dashed");
                    break;
                case API_CALL:
                    dot.append(", color=orange");
                    break;
                default:
                    // Use default style
            }
            
            // If there are multiple edges between the same nodes, adjust the position
            if (edgeCount > 0) {
                dot.append(", pos=\"").append(edgeCount * 10).append(",0!\"");
            }
            
            dot.append("];\n");
        }
        
        dot.append("}\n");
        
        Files.writeString(dotFile, dot.toString());
        
        logger.info("DOT file written to: {}", dotFile);
    }
    
    /**
     * Generates a Mermaid diagram
     */
    private void generateMermaidDiagram() throws IOException {
        Path mermaidFile = outputPath.resolve("data-flow-diagram.mmd");
        
        StringBuilder mermaid = new StringBuilder();
        mermaid.append("flowchart LR\n");
        
        // Generate nodes for external entities
        mermaid.append("  %% External Entities\n");
        for (ExternalEntity entity : result.getExternalEntities()) {
            String entityId = sanitizeId(entity.getName());
            mermaid.append("  ").append(entityId)
                  .append("[\"").append(entity.getName()).append("\"]")
                  .append(" style fill:#d0e0ff,stroke:#0000ff\n");
        }
        mermaid.append("\n");
        
        // Generate nodes for processes
        mermaid.append("  %% Processes\n");
        for (Process process : result.getProcesses()) {
            String processId = sanitizeId(process.getId());
            mermaid.append("  ").append(processId)
                  .append("((\"").append(process.getName()).append("\"))")
                  .append(" style fill:#d0ffd0,stroke:#00aa00\n");
        }
        mermaid.append("\n");
        
        // Generate nodes for data stores
        mermaid.append("  %% Data Stores\n");
        for (DataStore store : result.getDataStores()) {
            String storeId = sanitizeId(store.getId());
            mermaid.append("  ").append(storeId)
                  .append("[(\"").append(store.getName()).append("\")]")
                  .append(" style fill:#ffffd0,stroke:#aaaa00\n");
        }
        mermaid.append("\n");
        
        // Generate edges for data flows
        mermaid.append("  %% Data Flows\n");
        Map<String, Integer> edgeCounts = new HashMap<>();
        
        for (DataFlow flow : result.getDataFlows()) {
            String sourceId = sanitizeId(flow.getSourceId());
            String destId = sanitizeId(flow.getDestinationId());
            
            // Create a unique key for this edge
            String edgeKey = sourceId + "->" + destId;
            int edgeCount = edgeCounts.getOrDefault(edgeKey, 0);
            edgeCounts.put(edgeKey, edgeCount + 1);
            
            // Find the data structure for the label
            String dataStructureName = flow.getDataStructureId();
            for (DataStructure ds : result.getDataStructures()) {
                if (ds.getFullyQualifiedName().equals(flow.getDataStructureId())) {
                    dataStructureName = ds.getName();
                    break;
                }
            }
            
            // Create the edge
            mermaid.append("  ").append(sourceId).append(" --> ");
            
            // Add label
            mermaid.append("|").append(dataStructureName);
            if (flow.getProtocol() != null && !flow.getProtocol().isEmpty()) {
                mermaid.append("<br>").append(flow.getProtocol());
            }
            mermaid.append("| ");
            
            // Add destination
            mermaid.append(destId);
            
            // Style based on flow type
            switch (flow.getType()) {
                case INPUT:
                    mermaid.append(" style color:#0000ff\n");
                    break;
                case OUTPUT:
                    mermaid.append(" style color:#00aa00\n");
                    break;
                case DATABASE_READ:
                    mermaid.append(" style color:#aa00aa,stroke-dasharray:5 5\n");
                    break;
                case DATABASE_WRITE:
                    mermaid.append(" style color:#aa0000,stroke-dasharray:5 5\n");
                    break;
                case API_CALL:
                    mermaid.append(" style color:#ff8800\n");
                    break;
                default:
                    mermaid.append("\n");
                    break;
            }
        }
        
        Files.writeString(mermaidFile, mermaid.toString());
        
        logger.info("Mermaid diagram written to: {}", mermaidFile);
    }
    
    /**
     * Sanitizes an ID for use in GraphViz and Mermaid diagrams
     */
    private String sanitizeId(String id) {
        if (id == null) {
            return "unknown";
        }
        
        // Replace special characters with underscores
        return id.replaceAll("[^a-zA-Z0-9_]", "_");
    }
}
