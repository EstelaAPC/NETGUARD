CREATE TABLE IF NOT EXISTS ai_insights (
  id BIGSERIAL PRIMARY KEY,
  target_type TEXT NOT NULL,
  target_id BIGINT NOT NULL DEFAULT 0,
  insight_type TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'ready',
  model TEXT,
  content_md TEXT,
  content_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  evidence_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ
);

ALTER TABLE ai_insights ADD COLUMN IF NOT EXISTS target_type TEXT;
ALTER TABLE ai_insights ADD COLUMN IF NOT EXISTS target_id BIGINT;
UPDATE ai_insights
SET target_id = 0
WHERE target_id IS NULL;
ALTER TABLE ai_insights ALTER COLUMN target_id SET DEFAULT 0;
ALTER TABLE ai_insights ALTER COLUMN target_id SET NOT NULL;
ALTER TABLE ai_insights ADD COLUMN IF NOT EXISTS insight_type TEXT;
ALTER TABLE ai_insights ADD COLUMN IF NOT EXISTS status TEXT;
UPDATE ai_insights
SET status = 'ready'
WHERE status IS NULL OR BTRIM(status) = '';
ALTER TABLE ai_insights ALTER COLUMN status SET DEFAULT 'ready';
ALTER TABLE ai_insights ALTER COLUMN status SET NOT NULL;
ALTER TABLE ai_insights ADD COLUMN IF NOT EXISTS model TEXT;
ALTER TABLE ai_insights ADD COLUMN IF NOT EXISTS content_md TEXT;
ALTER TABLE ai_insights ADD COLUMN IF NOT EXISTS content_json JSONB;
UPDATE ai_insights
SET content_json = '{}'::jsonb
WHERE content_json IS NULL;
ALTER TABLE ai_insights ALTER COLUMN content_json SET DEFAULT '{}'::jsonb;
ALTER TABLE ai_insights ALTER COLUMN content_json SET NOT NULL;
ALTER TABLE ai_insights ADD COLUMN IF NOT EXISTS evidence_json JSONB;
UPDATE ai_insights
SET evidence_json = '{}'::jsonb
WHERE evidence_json IS NULL;
ALTER TABLE ai_insights ALTER COLUMN evidence_json SET DEFAULT '{}'::jsonb;
ALTER TABLE ai_insights ALTER COLUMN evidence_json SET NOT NULL;
ALTER TABLE ai_insights ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ;
UPDATE ai_insights
SET created_at = NOW()
WHERE created_at IS NULL;
ALTER TABLE ai_insights ALTER COLUMN created_at SET DEFAULT NOW();
ALTER TABLE ai_insights ALTER COLUMN created_at SET NOT NULL;
ALTER TABLE ai_insights ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS ix_ai_insights_target_lookup
  ON ai_insights (target_type, target_id, insight_type, created_at DESC);

CREATE INDEX IF NOT EXISTS ix_ai_insights_expires_at
  ON ai_insights (expires_at);

CREATE INDEX IF NOT EXISTS ix_ai_insights_status_created
  ON ai_insights (status, created_at DESC);

INSERT INTO schema_migrations (version, description)
VALUES (
  '013_ai_insights',
  'Camada simples de cache persistente para insights gerados sob demanda via Ollama'
)
ON CONFLICT (version) DO NOTHING;
