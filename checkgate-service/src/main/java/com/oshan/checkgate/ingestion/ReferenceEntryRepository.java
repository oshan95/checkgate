package com.oshan.checkgate.ingestion;

import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Repository;

import java.time.LocalDate;

@Repository
public class ReferenceEntryRepository {
    private final NamedParameterJdbcTemplate jdbcTemplate;

    public ReferenceEntryRepository(NamedParameterJdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    public void upsert(String id, String sourceType, String title, String description,
                       float[] embedding, LocalDate lastUpdated) {
        String sql = """
                INSERT INTO vulnerability_reference (id, source_type, title, description, embedding, last_updated)
                VALUES (:id, :sourceType, :title, :description, CAST(:embedding AS vector), :lastUpdated)
                ON CONFLICT (id) DO UPDATE SET
                    title = EXCLUDED.title, description = EXCLUDED.description,
                    embedding = EXCLUDED.embedding, last_updated = EXCLUDED.last_updated
                """;

        MapSqlParameterSource params = new MapSqlParameterSource()
                .addValue("id", id)
                .addValue("sourceType", sourceType)
                .addValue("title", title)
                .addValue("description", description)
                .addValue("embedding", toVectorLiteral(embedding))
                .addValue("lastUpdated", lastUpdated);

        jdbcTemplate.update(sql, params);
    }

    private String toVectorLiteral(float[] embedding) {
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < embedding.length; i++) {
            if (i > 0) sb.append(",");
            sb.append(embedding[i]);
        }
        return sb.append("]").toString();
    }
}
