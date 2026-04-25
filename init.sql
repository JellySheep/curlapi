CREATE TABLE IF NOT EXISTS vulnerabilities (
    id SERIAL PRIMARY KEY,
    cve_id VARCHAR(50) UNIQUE NOT NULL,
    vendor_release_date DATE,
    vendor_release_url TEXT,
    cve_url TEXT,
    published_date TIMESTAMP,
    updated_date TIMESTAMP,
    description TEXT
);

CREATE TABLE IF NOT EXISTS cvss_metrics (
    id SERIAL PRIMARY KEY,
    vulnerability_id INTEGER REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    version VARCHAR(20),
    score NUMERIC(3, 1),
    severity VARCHAR(20),
    vector TEXT
);

CREATE TABLE IF NOT EXISTS cpe_entries (
    id SERIAL PRIMARY KEY,
    vulnerability_id INTEGER REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    cpe_string TEXT
);

CREATE TABLE IF NOT EXISTS cwe_entries (
    id SERIAL PRIMARY KEY,
    vulnerability_id INTEGER REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    cwe_id VARCHAR(20),
    name TEXT,
    description TEXT
);
