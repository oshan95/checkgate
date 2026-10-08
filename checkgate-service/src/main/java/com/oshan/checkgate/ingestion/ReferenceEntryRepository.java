package com.oshan.checkgate.ingestion;

import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Repository;

import java.time.LocalDate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

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

    public Map<String, String> findDescriptionsBySource(String sourceType) {
        return jdbcTemplate.query(
                "SELECT id, description FROM vulnerability_reference WHERE source_type = :t",
                new MapSqlParameterSource("t", sourceType),
                rs -> {
                    Map<String, String> m = new HashMap<>();
                    while (rs.next()) m.put(rs.getString("id"), rs.getString("description"));
                    return m;
                });
    }

    public String getIngestedVersion(String source) {
        List<String> r = jdbcTemplate.queryForList(
                "SELECT version FROM ingestion_state WHERE source = :s",
                new MapSqlParameterSource("s", source), String.class);
        return r.isEmpty() ? null : r.get(0);
    }

    public void saveIngestedVersion(String source, String version) {
        jdbcTemplate.update("""
            INSERT INTO ingestion_state (source, version, updated_at) VALUES (:s, :v, now())
            ON CONFLICT (source) DO UPDATE SET version = EXCLUDED.version, updated_at = now()
            """,
                new MapSqlParameterSource().addValue("s", source).addValue("v", version));
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
