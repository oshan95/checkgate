package com.oshan.checkgate.rag;

import com.oshan.checkgate.ingestion.ReferenceEntryRepository;
import com.oshan.checkgate.model.ReferenceEntry;
import com.oshan.checkgate.model.RetrievedReference;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class VectorSearchService {

    // Cosine-similarity query against the vector store (pgvector <=> operator).

    private final NamedParameterJdbcTemplate jdbcTemplate;

    public VectorSearchService(NamedParameterJdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    // Cosine search (pgvector <=>). Exact scan, no index: fine at this store size.
    public List<RetrievedReference> findRelevant(float[] queryEmbedding, int topN) {
        String sql = """
                SELECT id, source_type, title, description,
                       1 - (embedding <=> CAST(:q AS vector)) AS similarity
                FROM vulnerability_reference
                ORDER BY embedding <=> CAST(:q AS vector)
                LIMIT :n
                """;
        MapSqlParameterSource params = new MapSqlParameterSource()
                .addValue("q", ReferenceEntryRepository.toVectorLiteral(queryEmbedding))
                .addValue("n", topN);

        return jdbcTemplate.query(sql, params, (rs, i) -> new RetrievedReference(
                rs.getString("id"), rs.getString("source_type"), rs.getString("title"),
                rs.getString("description"), rs.getDouble("similarity")));
    }
}
