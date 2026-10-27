-- 1. 학습용 memos 테이블 생성
CREATE TABLE IF NOT EXISTS memos (
    id SERIAL PRIMARY KEY,
    content TEXT NOT NULL,
    owner_id UUID,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT TIMEZONE('utc'::text, NOW()) NOT NULL
);

-- 2. RLS(Row Level Security) 활성화
ALTER TABLE memos ENABLE ROW LEVEL SECURITY;

-- 3. anon 및 authenticated 역할에 대한 읽기 권한 차단
REVOKE ALL ON memos FROM anon, authenticated;

-- 4. 기존 data.json의 가상 메모 4건 이관
INSERT INTO memos (content, owner_id) VALUES
    ('첫 번째 가상 메모 내용', NULL),
    ('두 번째 가상 메모 내용', NULL),
    ('세 번째 가상 메모 내용', NULL),
    ('네 번째 가상 메모 내용', NULL);