package com.threatmodel.analyzer.utils;

import com.github.javaparser.ast.comments.JavadocComment;

/**
 * Utility class for extracting information from Java comments
 */
public class CommentExtractor {
    
    /**
     * Extracts a description from a Javadoc comment
     * 
     * @param javadoc The Javadoc comment to extract description from
     * @return The extracted description
     */
    public static String extractDescription(JavadocComment javadoc) {
        String content = javadoc.getContent();
        
        // Remove common Javadoc formatting
        content = content.replaceAll("\\s*\\*\\s*", " ").trim();
        
        // Remove @tags
        int tagIndex = content.indexOf("@");
        if (tagIndex > 0) {
            content = content.substring(0, tagIndex).trim();
        }
        
        return content;
    }
}
