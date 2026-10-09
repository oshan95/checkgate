package com.oshan.checkgate.model;

public record RetrievedReference(String id, String sourceType, String title, String description, double similarity) {
}
